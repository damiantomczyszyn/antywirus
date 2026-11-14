"""Tests for the threat-intel feed layer.

No test here touches the network: :func:`aegis.intel.feeds.fetch` is exercised
against a fake ``urlopen`` and :class:`~aegis.intel.feeds.IntelUpdater` against
a fake ``fetch``.  The sample payloads below are trimmed copies of what the
real endpoints actually returned when the parsers were written, so a format
change upstream shows up as a failing test rather than as silently empty
updates.
"""

from __future__ import annotations

import gzip
import io
import json
import tarfile
import urllib.error
import zipfile
from typing import Any

import pytest

from aegis.events import EventType
from aegis.intel import baseline, feeds
from aegis.intel.feeds import AVAILABLE_FEEDS, FeedSpec, IntelUpdater, parse_feed
from aegis.models import IndicatorKind, Severity


# ==========================================================================
# Test doubles
# ==========================================================================
class FakeDB:
    """Minimal stand-in for ``SignatureDB``: records every ``add_many`` call."""

    def __init__(self) -> None:
        self.calls: list[list[Any]] = []
        self.rows: dict[tuple[str, str], Any] = {}

    def add_many(self, indicators: Any) -> tuple[int, int]:
        batch = list(indicators)
        self.calls.append(batch)
        added = updated = 0
        for indicator in batch:
            if indicator.key in self.rows:
                updated += 1
            else:
                added += 1
            self.rows[indicator.key] = indicator
        return added, updated

    def clear_source(self, source: str) -> int:
        victims = [k for k, v in self.rows.items() if v.source == source]
        for key in victims:
            del self.rows[key]
        return len(victims)

    def __len__(self) -> int:
        return len(self.rows)


class FakeResponse(io.BytesIO):
    """Just enough of an ``http.client.HTTPResponse`` for :func:`feeds.fetch`."""

    def __init__(self, body: bytes = b"", status: int = 200, headers: dict[str, str] | None = None):
        super().__init__(body)
        self.status = status
        self.headers = _Headers(headers or {})

    def getcode(self) -> int:
        return self.status

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class _Headers(dict):
    """Case-insensitive ``.get`` like ``email.message.Message``."""

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        for k, v in self.items():
            if k.lower() == key.lower():
                return v
        return default


@pytest.fixture()
def db() -> FakeDB:
    return FakeDB()


@pytest.fixture()
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Make the retry backoff instant and record the delays it asked for."""
    delays: list[float] = []
    monkeypatch.setattr(feeds, "_sleep", lambda d: delays.append(d))
    return delays


# ==========================================================================
# Captured feed samples (trimmed, real format)
# ==========================================================================
FEODO_JSON = json.dumps(
    [
        {
            "ip_address": "162.243.103.246",
            "port": 8080,
            "status": "offline",
            "hostname": None,
            "as_number": 14061,
            "as_name": "DIGITALOCEAN-ASN",
            "country": "US",
            "first_seen": "2022-06-04 21:24:53",
            "last_online": "2026-03-07",
            "malware": "Emotet",
        },
        {
            "ip_address": "50.16.16.211",
            "port": 443,
            "status": "online",
            "hostname": "ec2-50-16-16-211.compute-1.amazonaws.com",
            "country": "US",
            "malware": "QakBot",
        },
        {"ip_address": "not-an-ip", "malware": "Junk"},
    ]
).encode()

FEODO_TXT = b"""\
################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (IPs only)     #
# Last updated: 2026-03-04 14:28:39 UTC                        #
################################################################
#
# DstIP
162.243.103.246
178.62.3.223
27.133.154.218
not-an-ip
"""

SSLBL_CERTS_CSV = b"""\
################################################################
# abuse.ch SSLBL SSL Certificate Blacklist (SHA1 Fingerprints) #
################################################################
#
# Listingdate,SHA1,Listingreason
2026-11-14 09:14:20,c8e6fc7bb95a5fe2122679cfca61f87c7ce2875a,NativeLoader C&C
2026-11-14 08:35:11,0d04a50138c74a1ecfa1a7b4a3afddeb2a4be571,QuasarRAT C&C
"""

SSLBL_IP_CSV = b"""\
################################################################
# abuse.ch SSLBL Botnet C2 IP Blacklist (CSV)                  #
#
# Firstseen,DstIP,DstPort
#
# ATTENTION: This list has been deprecated on 2025-01-03
#
"""

URLHAUS_TEXT = b"""\
# URLhaus plain-text dump
HTTP://Example-Bad.COM.:80/Payload/BOT.exe
https://198.51.100.7:443/dropper.bin
https://cdn.bad.example/a.php?id=1
garbage-without-host
"""

URLHAUS_CSV = (
    b'# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n'
    b'"1","2026-11-14 09:00:00","http://Bad.Example.COM/x.exe","online",'
    b'"2026-11-14","malware_download","exe,Loader","https://urlhaus.abuse.ch/url/1/","rep"\n'
)

BAZAAR_CSV = (
    b"# first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,"
    b"file_type_guess,mime_type,signature,clamav,vtpercent,imphash\n"
    b'"2026-11-14 09:00:00","' + b"a" * 64 + b'","' + b"b" * 32 + b'","' + b"c" * 40 + b'",'
    b'"rep","x.exe","exe","application/x-dosexec","AgentTesla","n/a","50","ih"\n'
)

THREATFOX_JSON = json.dumps(
    {
        "1001": [
            {
                "ioc_value": "bad-c2.example.org",
                "ioc_type": "domain",
                "threat_type": "botnet_cc",
                "malware_printable": "Cobalt Strike",
            }
        ],
        "1002": [
            {
                "ioc_value": "203.0.113.9:8443",
                "ioc_type": "ip:port",
                "threat_type": "botnet_cc",
                "malware_printable": "AsyncRAT",
            },
            {
                "ioc_value": "http://bad.example/p.bin",
                "ioc_type": "url",
                "threat_type": "payload_delivery",
                "malware_printable": "Unknown",
            },
        ],
    }
).encode()


def _make_cvd(members: dict[str, bytes]) -> bytes:
    """Build a real CVD: 512-byte ASCII header + gzipped tar."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    header = b"ClamAV-VDB:14 Nov 2026 10-00 +0000:27500:2000000:58:" + b"x" * 64
    return header.ljust(512, b":") + buffer.getvalue()


# ==========================================================================
# Catalogue
# ==========================================================================
def test_catalogue_is_well_formed() -> None:
    assert AVAILABLE_FEEDS, "feed catalogue must not be empty"
    for feed_id, spec in AVAILABLE_FEEDS.items():
        assert feed_id == spec.id
        assert isinstance(spec, FeedSpec)
        assert isinstance(spec.kind, IndicatorKind)
        assert isinstance(spec.severity, Severity)
        assert spec.name and spec.description
        # 'builtin' is local; everything else must be HTTPS.
        if spec.id != "builtin":
            assert spec.url.startswith("https://"), f"{feed_id} must use HTTPS"


def test_every_configured_default_feed_exists() -> None:
    """``Config.feeds_enabled`` defaults must all resolve to a real spec."""
    from aegis.config import Config

    for feed_id in Config().feeds_enabled:
        assert feed_id in AVAILABLE_FEEDS, f"default config references unknown feed {feed_id}"


def test_key_in_url_versus_header() -> None:
    urlhaus = AVAILABLE_FEEDS["urlhaus_online"]
    assert urlhaus.key_in_url is True
    assert "SECRET" in urlhaus.resolved_url("SECRET")
    assert "{key}" not in urlhaus.resolved_url("SECRET")

    bazaar = AVAILABLE_FEEDS["malwarebazaar_recent"]
    assert bazaar.key_in_url is False
    assert bazaar.resolved_url("SECRET") == bazaar.url


# ==========================================================================
# URL normalisation
# ==========================================================================
@pytest.mark.parametrize(
    ("raw", "expected_url", "expected_host"),
    [
        ("HTTP://Example.COM/Path", "http://example.com/Path", "example.com"),
        ("http://example.com.:80/x", "http://example.com/x", "example.com"),
        ("https://example.com:443/x", "https://example.com/x", "example.com"),
        ("https://example.com:8443/x", "https://example.com:8443/x", "example.com"),
        ("http://example.com", "http://example.com/", "example.com"),
        ("example.com/x", "http://example.com/x", "example.com"),
        ("http://1.2.3.4/x", "http://1.2.3.4/x", "1.2.3.4"),
        ("garbage", "http://garbage/", "garbage"),
        ("", "", ""),
        ("http:///nohost", "", ""),
    ],
)
def test_normalise_url(raw: str, expected_url: str, expected_host: str) -> None:
    url, host = feeds.normalise_url(raw)
    assert (url, host) == (expected_url, expected_host)


def test_normalise_url_keeps_path_case_and_query() -> None:
    """Malware URLs are case- and parameter-sensitive: only the host folds."""
    url, _ = feeds.normalise_url("HTTPS://BAD.example/Payload/BOT.exe?Id=AbC")
    assert url == "https://bad.example/Payload/BOT.exe?Id=AbC"


def test_host_indicator_kind() -> None:
    assert feeds.host_indicator_kind("1.2.3.4") is IndicatorKind.IPV4
    assert feeds.host_indicator_kind("example.com") is IndicatorKind.DOMAIN


# ==========================================================================
# Parsers
# ==========================================================================
def test_parse_feodo_json_uses_real_family_names() -> None:
    out = parse_feed(AVAILABLE_FEEDS["feodo_ipblocklist"], FEODO_JSON)
    by_value = {i.value: i for i in out}
    assert set(by_value) == {"162.243.103.246", "50.16.16.211"}      # junk dropped
    assert by_value["50.16.16.211"].name == "Feodo.QakBot"
    assert by_value["162.243.103.246"].name == "Feodo.Emotet"
    assert all(i.kind is IndicatorKind.IPV4 for i in out)
    assert all(i.source == "feodo_ipblocklist" for i in out)
    # An offline C2 is historical evidence, not a live threat.
    assert by_value["50.16.16.211"].severity is Severity.HIGH
    assert by_value["162.243.103.246"].severity is Severity.MEDIUM


def test_parse_feodo_json_falls_back_to_plaintext() -> None:
    """The .json endpoint has been seen serving the plain list; cope with it."""
    out = parse_feed(AVAILABLE_FEEDS["feodo_ipblocklist"], FEODO_TXT)
    assert {i.value for i in out} == {"162.243.103.246", "178.62.3.223", "27.133.154.218"}


def test_parse_feodo_aggressive_skips_comments_and_junk() -> None:
    out = parse_feed(AVAILABLE_FEEDS["feodo_aggressive"], FEODO_TXT)
    assert len(out) == 3
    assert all(i.kind is IndicatorKind.IPV4 for i in out)
    assert not any(i.value.startswith("#") for i in out)


def test_parse_sslbl_certs_csv() -> None:
    out = parse_feed(AVAILABLE_FEEDS["sslbl_certs"], SSLBL_CERTS_CSV)
    assert len(out) == 2
    assert out[0].kind is IndicatorKind.SHA1
    assert out[0].value == "c8e6fc7bb95a5fe2122679cfca61f87c7ce2875a"
    assert out[0].name == "SSLBL.NativeLoader"
    assert out[1].name == "SSLBL.QuasarRAT"
    # Must be tagged so nobody mistakes a certificate print for a file hash.
    assert "not-a-file-hash" in out[0].tags


def test_parse_deprecated_sslbl_ip_list_is_empty_not_an_error() -> None:
    assert parse_feed(AVAILABLE_FEEDS["sslbl_ipblocklist"], SSLBL_IP_CSV) == []


def test_parse_urlhaus_text_derives_host_indicators() -> None:
    out = parse_feed(AVAILABLE_FEEDS["urlhaus_online"], URLHAUS_TEXT)
    urls = {i.value for i in out if i.kind is IndicatorKind.URL}
    domains = {i.value for i in out if i.kind is IndicatorKind.DOMAIN}
    ips = {i.value for i in out if i.kind is IndicatorKind.IPV4}

    # Scheme/host lowercased, trailing dot and default port stripped.
    assert "http://example-bad.com/Payload/BOT.exe" in urls
    assert "example-bad.com" in domains
    # A bare-IP host becomes an IPV4 indicator, not a bogus domain.
    assert "https://198.51.100.7/dropper.bin" in urls
    assert "198.51.100.7" in ips
    assert "cdn.bad.example" in domains
    # Derived hosts are weaker evidence than the exact URL.
    host_indicators = [i for i in out if i.kind is not IndicatorKind.URL]
    assert all(i.severity is Severity.MEDIUM for i in host_indicators)
    assert all("derived-from-url" in i.tags for i in host_indicators)


def test_parse_urlhaus_csv_uses_threat_label() -> None:
    out = parse_feed(AVAILABLE_FEEDS["urlhaus_online"], URLHAUS_CSV)
    assert out, "CSV payload must parse"
    assert out[0].kind is IndicatorKind.URL
    assert out[0].value == "http://bad.example.com/x.exe"
    assert out[0].name == "URLhaus.malware.download"
    assert {i.kind for i in out} == {IndicatorKind.URL, IndicatorKind.DOMAIN}


def test_parse_bazaar_csv_extracts_all_three_hashes_with_family() -> None:
    out = parse_feed(AVAILABLE_FEEDS["malwarebazaar_recent"], BAZAAR_CSV)
    assert {i.kind for i in out} == {
        IndicatorKind.SHA256,
        IndicatorKind.MD5,
        IndicatorKind.SHA1,
    }
    assert all(i.name == "MalwareBazaar.AgentTesla" for i in out)
    assert {len(i.value) for i in out} == {64, 32, 40}


def test_parse_bazaar_sha256_plain_list() -> None:
    body = b"# comment\n" + b"\n".join(bytes(str(d), "ascii") * 64 for d in range(1, 4))
    out = parse_feed(AVAILABLE_FEEDS["malwarebazaar_sha256"], body)
    assert len(out) == 3
    assert all(i.kind is IndicatorKind.SHA256 for i in out)


def test_parse_threatfox_mixed_kinds() -> None:
    out = parse_feed(AVAILABLE_FEEDS["threatfox_recent"], THREATFOX_JSON)
    by_kind: dict[IndicatorKind, list[Any]] = {}
    for indicator in out:
        by_kind.setdefault(indicator.kind, []).append(indicator)

    assert by_kind[IndicatorKind.DOMAIN]
    assert by_kind[IndicatorKind.IPV4][0].value == "203.0.113.9"      # port stripped
    assert by_kind[IndicatorKind.IPV4][0].name == "ThreatFox.AsyncRAT"
    assert by_kind[IndicatorKind.URL][0].value == "http://bad.example/p.bin"
    # "Unknown" is not a family name.
    assert by_kind[IndicatorKind.URL][0].name == "ThreatFox.IOC"


def test_parse_curated_json_roundtrip() -> None:
    document = {
        "version": "1",
        "generated_at": "now",
        "indicators": [i.to_dict() for i in baseline.builtin_indicators()],
    }
    out = parse_feed(AVAILABLE_FEEDS["github_curated"], json.dumps(document).encode())
    assert len(out) == len(baseline.builtin_indicators())
    # Re-tagged with the feed id so clear_source() can roll the feed back.
    assert all(i.source == "github_curated" for i in out)
    assert {i.kind for i in out} >= {IndicatorKind.SHA256, IndicatorKind.PATTERN}


def test_parse_clamav_cvd() -> None:
    cvd = _make_cvd(
        {
            "daily.hsb": (
                b"# comment\n"
                + b"a" * 64 + b":1024:Win.Trojan.Emotet-9999\n"
                + b"b" * 40 + b":*:Unix.Malware.Mirai-1\n"
                b"garbage-line\n"
            ),
            "daily.hdb": b"c" * 32 + b":512:Win.Ransomware.Lockbit-7\n",
            "daily.ndb": b"ignored:this:section\n",
            "daily.info": b"metadata\n",
        }
    )
    out = parse_feed(AVAILABLE_FEEDS["clamav_daily"], cvd)
    by_kind = {i.kind: i for i in out}
    assert set(by_kind) == {IndicatorKind.SHA256, IndicatorKind.SHA1, IndicatorKind.MD5}
    assert by_kind[IndicatorKind.SHA256].name == "ClamAV.Win.Trojan.Emotet.9999"
    assert by_kind[IndicatorKind.MD5].name == "ClamAV.Win.Ransomware.Lockbit.7"
    assert all("clamav" in i.tags for i in out)


def test_parse_clamav_rejects_corrupt_container() -> None:
    with pytest.raises(ValueError):
        parse_feed(AVAILABLE_FEEDS["clamav_daily"], b"ClamAV-VDB:" + b"x" * 600)


def test_parsers_never_raise_on_garbage() -> None:
    """A malformed body yields nothing; it must not explode."""
    for feed_id, spec in AVAILABLE_FEEDS.items():
        if feed_id in ("clamav_daily", "builtin"):
            continue
        for junk in (b"", b"\x00\xff\xfe binary junk", b"<html>404</html>", b"{]"):
            assert isinstance(parse_feed(spec, junk), list)


def test_every_indicator_is_tagged_with_its_feed_id() -> None:
    samples = {
        "feodo_ipblocklist": FEODO_JSON,
        "feodo_aggressive": FEODO_TXT,
        "sslbl_certs": SSLBL_CERTS_CSV,
        "urlhaus_online": URLHAUS_TEXT,
        "malwarebazaar_recent": BAZAAR_CSV,
        "threatfox_recent": THREATFOX_JSON,
    }
    for feed_id, body in samples.items():
        out = parse_feed(AVAILABLE_FEEDS[feed_id], body)
        assert out, f"{feed_id} sample must parse to something"
        assert all(i.source == feed_id for i in out), feed_id


# ==========================================================================
# fetch()
# ==========================================================================
def test_fetch_sends_neutral_user_agent_and_no_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    """Privacy: no hostname, user name or local path may ever leave the box."""
    import getpass
    import socket as socket_module

    captured: dict[str, Any] = {}

    def fake_urlopen(request: Any, timeout: float = 0) -> FakeResponse:
        captured["headers"] = dict(request.headers)
        captured["url"] = request.full_url
        return FakeResponse(b"ok")

    monkeypatch.setattr(feeds.urllib.request, "urlopen", fake_urlopen)
    body, meta = feeds.fetch("https://example.invalid/feed")

    assert body == b"ok"
    assert meta["status"] == "200"
    headers = {k.lower(): v for k, v in captured["headers"].items()}
    assert headers["user-agent"] == "Aegis-AV/1.0"

    blob = " ".join(list(headers.keys()) + list(headers.values())).lower()
    for secret in (
        socket_module.gethostname().lower(),
        getpass.getuser().lower(),
        str(__import__("pathlib").Path.home()).lower(),
    ):
        if secret and len(secret) > 2:
            assert secret not in blob, f"identity leaked in headers: {secret}"


def test_fetch_conditional_headers_and_304(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_urlopen(request: Any, timeout: float = 0) -> FakeResponse:
        seen.update({k.lower(): v for k, v in request.headers.items()})
        return FakeResponse(b"", status=304, headers={"ETag": '"abc"'})

    monkeypatch.setattr(feeds.urllib.request, "urlopen", fake_urlopen)
    body, meta = feeds.fetch(
        "https://example.invalid/f", etag='"abc"', last_modified="Tue, 30 Jun 2026 04:53:05 GMT"
    )

    assert body is None, "304 must return (None, meta)"
    assert meta["status"] == "304"
    assert seen["if-none-match"] == '"abc"'
    assert seen["if-modified-since"] == "Tue, 30 Jun 2026 04:53:05 GMT"


def test_fetch_304_delivered_as_httperror(monkeypatch: pytest.MonkeyPatch) -> None:
    """Some stacks raise 304 instead of returning it."""

    def fake_urlopen(request: Any, timeout: float = 0) -> FakeResponse:
        raise urllib.error.HTTPError(
            request.full_url, 304, "Not Modified", _Headers({"ETag": '"z"'}), None  # type: ignore[arg-type]
        )

    monkeypatch.setattr(feeds.urllib.request, "urlopen", fake_urlopen)
    body, meta = feeds.fetch("https://example.invalid/f", etag='"z"')
    assert body is None
    assert meta["status"] == "304"


def test_fetch_captures_caching_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    headers = {
        "ETag": '"235-6557159bdc9f3"',
        "Last-Modified": "Tue, 30 Jun 2026 04:53:05 GMT",
        "Content-Type": "text/plain",
    }
    monkeypatch.setattr(
        feeds.urllib.request,
        "urlopen",
        lambda request, timeout=0: FakeResponse(b"1.2.3.4\n", headers=headers),
    )
    body, meta = feeds.fetch("https://example.invalid/f")
    assert body == b"1.2.3.4\n"
    assert meta["etag"] == '"235-6557159bdc9f3"'
    assert meta["last_modified"] == "Tue, 30 Jun 2026 04:53:05 GMT"
    assert meta["content_type"] == "text/plain"
    assert meta["bytes"] == "8"


def test_fetch_handles_gzip_body(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = gzip.compress(b"1.1.1.1\n2.2.2.2\n")
    monkeypatch.setattr(
        feeds.urllib.request,
        "urlopen",
        lambda request, timeout=0: FakeResponse(
            payload, headers={"Content-Encoding": "gzip"}
        ),
    )
    body, _ = feeds.fetch("https://example.invalid/f.gz")
    assert body == b"1.1.1.1\n2.2.2.2\n"


def test_fetch_handles_zip_taking_largest_member(monkeypatch: pytest.MonkeyPatch) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "small")
        archive.writestr("full_sha256.txt", "A" * 500)
    monkeypatch.setattr(
        feeds.urllib.request,
        "urlopen",
        lambda request, timeout=0: FakeResponse(buffer.getvalue()),
    )
    body, _ = feeds.fetch("https://example.invalid/full.zip")
    assert body == b"A" * 500


def test_fetch_enforces_max_bytes_while_streaming(monkeypatch: pytest.MonkeyPatch) -> None:
    """A feed far bigger than advertised must not exhaust memory."""
    monkeypatch.setattr(
        feeds.urllib.request,
        "urlopen",
        lambda request, timeout=0: FakeResponse(b"x" * 10_000),
    )
    body, meta = feeds.fetch("https://example.invalid/huge", max_bytes=1000)
    assert body is not None and len(body) == 1000
    assert meta["truncated"] == "1"


def test_fetch_retries_5xx_then_succeeds(
    monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    attempts: list[int] = []

    def fake_urlopen(request: Any, timeout: float = 0) -> FakeResponse:
        attempts.append(1)
        if len(attempts) < 3:
            raise urllib.error.HTTPError(
                request.full_url, 503, "Service Unavailable", _Headers({}), None  # type: ignore[arg-type]
            )
        return FakeResponse(b"recovered")

    monkeypatch.setattr(feeds.urllib.request, "urlopen", fake_urlopen)
    body, _ = feeds.fetch("https://example.invalid/f")
    assert body == b"recovered"
    assert len(attempts) == 3
    assert no_sleep == [1.0, 2.0], "exponential backoff"


def test_fetch_honours_retry_after_on_429(
    monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    state = {"n": 0}

    def fake_urlopen(request: Any, timeout: float = 0) -> FakeResponse:
        state["n"] += 1
        if state["n"] == 1:
            raise urllib.error.HTTPError(
                request.full_url, 429, "Too Many Requests",
                _Headers({"Retry-After": "7"}), None,  # type: ignore[arg-type]
            )
        return FakeResponse(b"ok")

    monkeypatch.setattr(feeds.urllib.request, "urlopen", fake_urlopen)
    body, _ = feeds.fetch("https://example.invalid/f")
    assert body == b"ok"
    assert no_sleep == [7.0]


def test_fetch_gives_up_after_max_attempts(
    monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    attempts: list[int] = []

    def fake_urlopen(request: Any, timeout: float = 0) -> FakeResponse:
        attempts.append(1)
        raise urllib.error.URLError("timed out")

    monkeypatch.setattr(feeds.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(OSError):
        feeds.fetch("https://example.invalid/f")
    assert len(attempts) == feeds.MAX_ATTEMPTS == 3


def test_fetch_does_not_retry_permanent_410(
    monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    """abuse.ch answers 410 Gone for the retired exports: retrying is pointless."""
    attempts: list[int] = []

    def fake_urlopen(request: Any, timeout: float = 0) -> FakeResponse:
        attempts.append(1)
        raise urllib.error.HTTPError(
            request.full_url, 410, "Gone", _Headers({}), None  # type: ignore[arg-type]
        )

    monkeypatch.setattr(feeds.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(urllib.error.HTTPError):
        feeds.fetch("https://example.invalid/export/")
    assert len(attempts) == 1
    assert no_sleep == []


# ==========================================================================
# IntelUpdater
# ==========================================================================
def _patch_fetch(monkeypatch: pytest.MonkeyPatch, bodies: dict[str, bytes]) -> list[str]:
    """Serve *bodies* keyed by feed id, matched against the requested URL."""
    requested: list[str] = []

    def fake_fetch(url: str, **kwargs: Any) -> tuple[bytes | None, dict[str, str]]:
        requested.append(url)
        for feed_id, body in bodies.items():
            spec = AVAILABLE_FEEDS[feed_id]
            if spec.url and spec.url.split("{key}")[0] in url:
                return body, {"status": "200", "etag": f'"{feed_id}"'}
        raise OSError(f"unexpected URL in test: {url}")

    monkeypatch.setattr(feeds, "fetch", fake_fetch)
    return requested


def test_update_publishes_events_in_order(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any, bus: Any
) -> None:
    _patch_fetch(monkeypatch, {"feodo_ipblocklist": FEODO_JSON})
    updater = IntelUpdater(db, config, bus)
    results = updater.update(["feodo_ipblocklist"])

    assert len(results) == 1 and results[0].ok
    types = [e.type for e in bus.history()]
    assert types == [
        EventType.DB_UPDATE_STARTED,
        EventType.DB_UPDATE_FEED,
        EventType.DB_UPDATE_FINISHED,
    ]
    finished = bus.history()[-1]
    assert finished.payload["added"] == 2
    assert finished.payload["failed"] == []


def test_update_events_one_feed_event_each(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any, bus: Any
) -> None:
    _patch_fetch(
        monkeypatch, {"feodo_ipblocklist": FEODO_JSON, "feodo_aggressive": FEODO_TXT}
    )
    updater = IntelUpdater(db, config, bus)
    updater.update(["feodo_ipblocklist", "feodo_aggressive"])
    feed_events = [e for e in bus.history() if e.type is EventType.DB_UPDATE_FEED]
    assert [e.payload["feed_id"] for e in feed_events] == [
        "feodo_ipblocklist",
        "feodo_aggressive",
    ]


def test_network_error_never_escapes_update(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any, bus: Any
) -> None:
    def boom(url: str, **kwargs: Any) -> tuple[bytes | None, dict[str, str]]:
        raise urllib.error.URLError("name resolution failed")

    monkeypatch.setattr(feeds, "fetch", boom)
    results = IntelUpdater(db, config, bus).update(["feodo_ipblocklist"])

    assert len(results) == 1
    assert results[0].ok is False
    assert "name resolution failed" in results[0].error
    assert bus.history()[-1].type is EventType.DB_UPDATE_FINISHED
    assert bus.history()[-1].payload["failed"] == ["feodo_ipblocklist"]


def test_http_error_becomes_feed_result(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any
) -> None:
    def gone(url: str, **kwargs: Any) -> tuple[bytes | None, dict[str, str]]:
        raise urllib.error.HTTPError(url, 410, "Gone", _Headers({}), None)  # type: ignore[arg-type]

    monkeypatch.setattr(feeds, "fetch", gone)
    result = IntelUpdater(db, config).update_feed("feodo_ipblocklist")
    assert result.ok is False
    assert "410" in result.error


def test_feed_requiring_a_key_is_skipped_not_attempted(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any
) -> None:
    called: list[str] = []

    def tracker(url: str, **kwargs: Any) -> tuple[bytes | None, dict[str, str]]:
        called.append(url)
        return b"", {}

    monkeypatch.setattr(feeds, "fetch", tracker)
    monkeypatch.delenv("AEGIS_URLHAUS_ONLINE_KEY", raising=False)
    config.feed_api_keys = {}

    result = IntelUpdater(db, config).update_feed("urlhaus_online")
    assert result.ok is False
    assert called == [], "a keyless feed must not be requested at all"
    # Clear, actionable Polish message with Polish characters.
    assert "klucza API" in result.error
    assert "AEGIS_URLHAUS_ONLINE_KEY" in result.error
    assert "Źródło" in result.error


def test_api_key_from_config_is_used(monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any) -> None:
    seen: dict[str, Any] = {}

    def fake_fetch(url: str, **kwargs: Any) -> tuple[bytes | None, dict[str, str]]:
        seen["url"] = url
        seen["headers"] = kwargs.get("headers")
        return URLHAUS_CSV, {"status": "200"}

    monkeypatch.setattr(feeds, "fetch", fake_fetch)
    config.feed_api_keys = {"urlhaus_online": "SECRET-KEY"}
    result = IntelUpdater(db, config).update_feed("urlhaus_online")

    assert result.ok is True
    assert "SECRET-KEY" in seen["url"], "URLhaus v2 takes the key in the URL path"
    assert not seen["headers"], "and therefore not as a header"


def test_api_key_from_environment_goes_in_auth_key_header(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any
) -> None:
    seen: dict[str, Any] = {}

    def fake_fetch(url: str, **kwargs: Any) -> tuple[bytes | None, dict[str, str]]:
        seen["url"] = url
        seen["headers"] = kwargs.get("headers") or {}
        return BAZAAR_CSV, {"status": "200"}

    monkeypatch.setattr(feeds, "fetch", fake_fetch)
    monkeypatch.setenv("AEGIS_MALWAREBAZAAR_RECENT_KEY", "ENV-KEY")
    config.feed_api_keys = {}

    result = IntelUpdater(db, config).update_feed("malwarebazaar_recent")
    assert result.ok is True
    assert seen["headers"].get("Auth-Key") == "ENV-KEY"
    assert "ENV-KEY" not in seen["url"]


def test_unchanged_feed_reports_304_and_adds_nothing(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any
) -> None:
    monkeypatch.setattr(
        feeds, "fetch", lambda url, **kw: (None, {"status": "304"})
    )
    result = IntelUpdater(db, config).update_feed("feodo_ipblocklist")
    assert result.ok is True
    assert result.skipped_unchanged is True
    assert result.added == 0
    assert db.calls == []


def test_etag_is_persisted_and_replayed(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any
) -> None:
    """The caching path: second run sends back what the first run stored."""
    conditional: list[dict[str, Any]] = []

    def fake_fetch(url: str, **kwargs: Any) -> tuple[bytes | None, dict[str, str]]:
        conditional.append(
            {"etag": kwargs.get("etag"), "last_modified": kwargs.get("last_modified")}
        )
        if conditional[-1]["etag"]:
            return None, {"status": "304"}
        return FEODO_JSON, {
            "status": "200",
            "etag": '"235-6557159bdc9f3"',
            "last_modified": "Tue, 30 Jun 2026 04:53:05 GMT",
        }

    monkeypatch.setattr(feeds, "fetch", fake_fetch)

    first = IntelUpdater(db, config).update_feed("feodo_ipblocklist")
    assert first.ok and not first.skipped_unchanged and first.added == 2
    assert conditional[0] == {"etag": None, "last_modified": None}
    assert config.feed_state_path.is_file(), "state must be persisted"

    # A brand new updater reads the state back off disk.
    second = IntelUpdater(db, config).update_feed("feodo_ipblocklist")
    assert second.skipped_unchanged is True
    assert conditional[1]["etag"] == '"235-6557159bdc9f3"'
    assert conditional[1]["last_modified"] == "Tue, 30 Jun 2026 04:53:05 GMT"


def test_force_ignores_cached_validators(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any
) -> None:
    conditional: list[Any] = []

    def fake_fetch(url: str, **kwargs: Any) -> tuple[bytes | None, dict[str, str]]:
        conditional.append(kwargs.get("etag"))
        return FEODO_JSON, {"status": "200", "etag": '"e"'}

    monkeypatch.setattr(feeds, "fetch", fake_fetch)
    updater = IntelUpdater(db, config)
    updater.update_feed("feodo_ipblocklist")
    updater.update_feed("feodo_ipblocklist", force=True)
    assert conditional == [None, None], "force must not send If-None-Match"


def test_state_file_is_private(monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any) -> None:
    monkeypatch.setattr(feeds, "fetch", lambda url, **kw: (FEODO_JSON, {"status": "200"}))
    IntelUpdater(db, config).update_feed("feodo_ipblocklist")
    assert config.feed_state_path.stat().st_mode & 0o077 == 0, "state must be 0600"


def test_feed_max_indicators_truncates_with_a_warning(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any, bus: Any
) -> None:
    big = b"\n".join(f"10.0.{a}.{b}".encode() for a in range(5) for b in range(50))
    monkeypatch.setattr(feeds, "fetch", lambda url, **kw: (big, {"status": "200"}))
    config.feed_max_indicators = 10

    result = IntelUpdater(db, config, bus).update_feed("feodo_aggressive")
    assert result.ok is True
    assert len(result.indicators) == 10, "must truncate, not fill the disk"
    assert len(db.rows) == 10
    warnings = [e for e in bus.history() if e.level == "warning"]
    assert any("limit" in e.message for e in warnings)


def test_budget_is_shared_across_feeds_in_one_update(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any
) -> None:
    _patch_fetch(
        monkeypatch, {"feodo_ipblocklist": FEODO_JSON, "feodo_aggressive": FEODO_TXT}
    )
    config.feed_max_indicators = 3
    results = IntelUpdater(db, config).update(["feodo_ipblocklist", "feodo_aggressive"])
    assert sum(r.added + r.updated for r in results) <= 3


def test_unknown_feed_id_is_a_result_not_an_exception(db: FakeDB, config: Any) -> None:
    result = IntelUpdater(db, config).update_feed("does_not_exist")
    assert result.ok is False
    assert "Nieznane źródło" in result.error


def test_builtin_pseudo_feed_needs_no_network(db: FakeDB, config: Any, bus: Any) -> None:
    """``builtin`` is in the default config: it must work with no HTTP at all."""
    result = IntelUpdater(db, config, bus).update_feed("builtin")
    assert result.ok is True
    assert result.added == len(baseline.builtin_indicators())
    assert all(i.source == "builtin" for i in result.indicators)


def test_available_describes_feeds_for_the_gui(db: FakeDB, config: Any) -> None:
    rows = IntelUpdater(db, config).available()
    assert len(rows) == len(AVAILABLE_FEEDS)
    row = next(r for r in rows if r["id"] == "feodo_ipblocklist")
    assert set(row) >= {
        "id", "name", "description", "url", "kind", "severity",
        "requires_key", "has_key", "enabled", "enabled_by_default",
        "last_success", "last_error",
    }
    assert row["enabled"] is True, "it is in the default config"
    urlhaus = next(r for r in rows if r["id"] == "urlhaus_online")
    assert urlhaus["requires_key"] is True


def test_last_update_timestamp(monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any) -> None:
    monkeypatch.setattr(feeds, "fetch", lambda url, **kw: (FEODO_JSON, {"status": "200"}))
    updater = IntelUpdater(db, config)
    assert updater.last_update() is None
    updater.update(["feodo_ipblocklist"])
    assert isinstance(updater.last_update(), float)
    # And it survives a restart.
    assert IntelUpdater(db, config).last_update() is not None


def test_update_defaults_to_configured_feeds(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, config: Any
) -> None:
    attempted: list[str] = []

    def fake_update_feed(self: Any, feed_id: str, **kwargs: Any) -> Any:
        attempted.append(feed_id)
        from aegis.models import FeedResult

        return FeedResult(feed_id=feed_id, ok=True)

    monkeypatch.setattr(IntelUpdater, "update_feed", fake_update_feed)
    config.feeds_enabled = ["builtin", "feodo_ipblocklist", "bogus_feed"]
    IntelUpdater(db, config).update()
    assert attempted == ["builtin", "feodo_ipblocklist"], "unknown ids are filtered out"


def test_corrupt_state_file_does_not_break_the_updater(db: FakeDB, config: Any) -> None:
    config.feed_state_path.write_text("{not json", encoding="utf-8")
    updater = IntelUpdater(db, config)
    assert updater.last_update() is None
    assert updater.available()


# ==========================================================================
# Integration with the real SignatureDB (skipped until Agent A lands)
# ==========================================================================
def test_update_into_real_signature_db(monkeypatch: pytest.MonkeyPatch, config: Any, bus: Any) -> None:
    signatures = pytest.importorskip(
        "aegis.core.signatures", reason="aegis.core.signatures not available yet"
    )
    real_db = signatures.SignatureDB(None)
    try:
        _patch_fetch(monkeypatch, {"feodo_ipblocklist": FEODO_JSON})
        results = IntelUpdater(real_db, config, bus).update(["builtin", "feodo_ipblocklist"])

        assert all(r.ok for r in results)
        assert len(real_db) == len(baseline.builtin_indicators()) + 2

        hit = real_db.lookup_network(ip="50.16.16.211")
        assert hit is not None and hit.name == "Feodo.QakBot"

        # Rolling one feed back leaves the rest of the database alone.
        removed = real_db.clear_source("feodo_ipblocklist")
        assert removed == 2
        assert len(real_db) == len(baseline.builtin_indicators())
    finally:
        real_db.close()
