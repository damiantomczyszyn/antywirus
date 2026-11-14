"""Threat-intel feeds: download open-source blocklists and turn them into indicators.

Design notes
------------
* **Standard library only.**  :func:`fetch` is built on :mod:`urllib.request`, so
  there is no ``requests`` dependency in the critical path.  The HTTPS proxy and
  CA bundle are picked up from the environment by ``urllib`` automatically; TLS
  verification is never disabled.
* **Privacy.**  Outbound requests carry a constant, neutral ``User-Agent``
  (:data:`USER_AGENT`) and nothing else that could identify the user: no
  hostname, no account name, no local paths, no telemetry.  See
  :func:`_request_headers`.
* **Robustness.**  A network failure must never propagate out of
  :meth:`IntelUpdater.update`; it becomes ``FeedResult(ok=False, error=...)``.
* **Politeness / bandwidth.**  ``ETag`` / ``Last-Modified`` are persisted per
  feed in ``config.feed_state_path`` so an unchanged feed costs one HTTP 304.

Empirical state of the public feeds (probed 2026-11-14, see module constants)
----------------------------------------------------------------------------
abuse.ch retired its anonymous bulk exports: the ``bazaar.abuse.ch/export/*``,
``urlhaus.abuse.ch/downloads/*`` and ``threatfox.abuse.ch/export/*`` paths all
answer **HTTP 410 Gone**.  Those datasets moved behind a free ``Auth-Key``
(``mb-api``/``threatfox-api`` take an ``Auth-Key`` HTTP header, URLhaus v2 takes
the key inside the URL path).  Their specs are therefore marked
``requires_key=True`` and are skipped - not attempted - when no key is
configured.  Feodo Tracker still serves anonymously and is the default
network feed; ``github_curated`` is the always-available fallback.
"""

from __future__ import annotations

import csv
import gzip
import io
import ipaddress
import json
import os
import re
import socket
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..config import Config
from ..events import EventBus, EventType
from ..models import FeedResult, Indicator, IndicatorKind, Severity

__all__ = [
    "FeedSpec",
    "AVAILABLE_FEEDS",
    "USER_AGENT",
    "parse_feed",
    "fetch",
    "IntelUpdater",
    "normalise_url",
    "host_indicator_kind",
]

#: Neutral client identity.  Deliberately constant: never leak who or where the
#: user is to a third-party feed operator.
USER_AGENT = "Aegis-AV/1.0"

#: Maximum number of HTTP attempts per feed (1 try + 2 retries).
MAX_ATTEMPTS = 3

#: Base delay for the exponential backoff, in seconds.
BACKOFF_BASE = 1.0

#: Longest delay we are willing to honour from a ``Retry-After`` header.
MAX_RETRY_AFTER = 30.0

#: Injectable sleep so tests do not actually wait.
_sleep: Callable[[float], None] = time.sleep

#: Upper bound for the ClamAV CVD download (the real daily.cvd is ~60-80 MB).
CLAMAV_MAX_BYTES = 96 * 1024 * 1024

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_HASH_KIND_BY_LEN = {
    32: IndicatorKind.MD5,
    40: IndicatorKind.SHA1,
    64: IndicatorKind.SHA256,
}


# ==========================================================================
# Feed catalogue
# ==========================================================================
@dataclass(frozen=True)
class FeedSpec:
    """Static description of one threat-intel source.

    A spec whose :attr:`url` contains the literal ``{key}`` placeholder expects
    its API key inside the URL path (URLhaus v2 style); every other
    ``requires_key`` feed receives it as an ``Auth-Key`` HTTP header
    (MalwareBazaar / ThreatFox style).
    """

    id: str
    name: str
    url: str
    description: str
    kind: IndicatorKind
    threat_prefix: str
    requires_key: bool = False
    enabled_by_default: bool = True
    severity: Severity = Severity.HIGH
    homepage: str = ""

    @property
    def key_in_url(self) -> bool:
        """True when the API key belongs in the URL instead of a header."""
        return "{key}" in self.url

    def resolved_url(self, key: str | None = None) -> str:
        """The URL to request, with the API key substituted if needed."""
        if self.key_in_url:
            return self.url.replace("{key}", urllib.parse.quote(key or "", safe=""))
        return self.url


AVAILABLE_FEEDS: dict[str, FeedSpec] = {
    # ---------------------------------------------------------------- offline
    "builtin": FeedSpec(
        id="builtin",
        name="Wbudowana baza startowa",
        url="",                              # local: no HTTP request at all
        description=(
            "Baza dołączona do programu: EICAR, znaczniki próbek symulatora i "
            "ogólne wzorce złośliwych skryptów. Nie wymaga sieci, dzięki niej "
            "świeża instalacja wykrywa zagrożenia od razu."
        ),
        kind=IndicatorKind.PATTERN,
        threat_prefix="Aegis",
        enabled_by_default=True,
        homepage="",
    ),
    "github_curated": FeedSpec(
        id="github_curated",
        name="Aegis - kurowana baza (GitHub)",
        url=(
            "https://raw.githubusercontent.com/damiantomczyszyn/antywirus/"
            "claude/antivirus/antivirus/aegis/data/signatures_baseline.json"
        ),
        description=(
            "Kurowana lista wskaźników utrzymywana w repozytorium projektu. "
            "Zawsze dostępna, nie wymaga klucza - działa nawet gdy abuse.ch "
            "jest nieosiągalne."
        ),
        kind=IndicatorKind.PATTERN,          # mixed; the JSON carries real kinds
        threat_prefix="Aegis",
        enabled_by_default=True,
        homepage="https://github.com/damiantomczyszyn/antywirus",
    ),
    # ------------------------------------------------- Feodo Tracker (anonymous)
    "feodo_ipblocklist": FeedSpec(
        id="feodo_ipblocklist",
        name="Feodo Tracker - C2 botnetów (JSON)",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        description=(
            "Adresy IP serwerów C2 botnetów bankowych (Emotet, QakBot, "
            "Dridex, TrickBot). Wariant JSON podaje rodzinę malware, więc "
            "nazwy zagrożeń są prawdziwe, a nie ogólne."
        ),
        kind=IndicatorKind.IPV4,
        threat_prefix="Feodo",
        enabled_by_default=True,
        severity=Severity.HIGH,
        homepage="https://feodotracker.abuse.ch/blocklist/",
    ),
    "feodo_aggressive": FeedSpec(
        id="feodo_aggressive",
        name="Feodo Tracker - lista agresywna",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
        description=(
            "Pełna, agresywna lista IP z Feodo Tracker (także adresy offline "
            "i historyczne). Dużo większe pokrycie, ale wyższe ryzyko "
            "fałszywych alarmów - domyślnie wyłączona."
        ),
        kind=IndicatorKind.IPV4,
        threat_prefix="Feodo",
        enabled_by_default=False,
        severity=Severity.MEDIUM,
        homepage="https://feodotracker.abuse.ch/blocklist/",
    ),
    # --------------------------------------------------------- SSLBL (abuse.ch)
    "sslbl_ipblocklist": FeedSpec(
        id="sslbl_ipblocklist",
        name="SSLBL - C2 botnetów (wycofana)",
        url="https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
        description=(
            "UWAGA: abuse.ch wycofało tę listę 2025-01-03. Endpoint nadal "
            "zwraca HTTP 200, ale sam plik zawiera już tylko nagłówek, bez "
            "żadnych adresów IP. Zostawiona dla zgodności konfiguracji."
        ),
        kind=IndicatorKind.IPV4,
        threat_prefix="SSLBL",
        enabled_by_default=False,
        severity=Severity.HIGH,
        homepage="https://sslbl.abuse.ch/blacklist/",
    ),
    "sslbl_certs": FeedSpec(
        id="sslbl_certs",
        name="SSLBL - odciski certyfikatów C2 (SHA1)",
        url="https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        description=(
            "Odciski SHA1 certyfikatów TLS używanych przez serwery C2 wraz z "
            "nazwą rodziny. To odciski CERTYFIKATÓW, nie skróty plików - nie "
            "dopasują się do zawartości pliku, więc feed jest domyślnie "
            "wyłączony. Przydatny dopiero przy inspekcji ruchu TLS."
        ),
        kind=IndicatorKind.SHA1,
        threat_prefix="SSLBL",
        enabled_by_default=False,
        severity=Severity.HIGH,
        homepage="https://sslbl.abuse.ch/blacklist/",
    ),
    # ----------------------------------------- abuse.ch exports behind Auth-Key
    "malwarebazaar_recent": FeedSpec(
        id="malwarebazaar_recent",
        name="MalwareBazaar - ostatnie próbki (CSV)",
        url="https://bazaar.abuse.ch/export/csv/recent/",
        description=(
            "Skróty SHA256/SHA1/MD5 świeżych próbek wraz z nazwą rodziny. "
            "Anonimowy eksport został wyłączony przez abuse.ch (HTTP 410 "
            "Gone) - wymaga darmowego klucza Auth-Key."
        ),
        kind=IndicatorKind.SHA256,
        threat_prefix="MalwareBazaar",
        requires_key=True,
        enabled_by_default=False,
        severity=Severity.CRITICAL,
        homepage="https://bazaar.abuse.ch/api/",
    ),
    "malwarebazaar_sha256": FeedSpec(
        id="malwarebazaar_sha256",
        name="MalwareBazaar - lista SHA256",
        url="https://bazaar.abuse.ch/export/txt/sha256/recent/",
        description=(
            "Czysta lista SHA256 ostatnich próbek (jeden skrót na wiersz). "
            "Anonimowy eksport wyłączony przez abuse.ch (HTTP 410 Gone) - "
            "wymaga darmowego klucza Auth-Key."
        ),
        kind=IndicatorKind.SHA256,
        threat_prefix="MalwareBazaar",
        requires_key=True,
        enabled_by_default=False,
        severity=Severity.CRITICAL,
        homepage="https://bazaar.abuse.ch/api/",
    ),
    "urlhaus_online": FeedSpec(
        id="urlhaus_online",
        name="URLhaus - aktywne adresy URL",
        url="https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv",
        description=(
            "Adresy URL rozsiewające malware. Anonimowy eksport "
            "(/downloads/text_online/) zwraca HTTP 410 Gone; dane przeniesiono "
            "do urlhaus-api.abuse.ch, gdzie klucz podaje się w ścieżce URL."
        ),
        kind=IndicatorKind.URL,
        threat_prefix="URLhaus",
        requires_key=True,
        enabled_by_default=False,
        severity=Severity.HIGH,
        homepage="https://urlhaus.abuse.ch/api/",
    ),
    "threatfox_recent": FeedSpec(
        id="threatfox_recent",
        name="ThreatFox - mieszane wskaźniki IOC",
        url="https://threatfox.abuse.ch/export/json/recent/",
        description=(
            "Mieszane wskaźniki (IP:port, domeny, URL-e, skróty) z nazwami "
            "rodzin. Anonimowy eksport wyłączony przez abuse.ch (HTTP 410 "
            "Gone) - wymaga darmowego klucza Auth-Key."
        ),
        kind=IndicatorKind.DOMAIN,          # mixed; the payload carries ioc_type
        threat_prefix="ThreatFox",
        requires_key=True,
        enabled_by_default=False,
        severity=Severity.HIGH,
        homepage="https://threatfox.abuse.ch/api/",
    ),
    # ------------------------------------------------------------ ClamAV CVD
    "clamav_daily": FeedSpec(
        id="clamav_daily",
        name="ClamAV - baza dzienna (daily.cvd)",
        url="https://database.clamav.net/daily.cvd",
        description=(
            "Oficjalna baza ClamAV: 512-bajtowy nagłówek ASCII + spakowany "
            "tar, z którego czytamy sekcje .hdb/.hsb (skróty plików). Duża "
            "(dziesiątki MB), więc domyślnie wyłączona i pobierana "
            "strumieniowo z limitem rozmiaru. Z tego kontenera endpoint "
            "odpowiada HTTP 403 (blokada Cloudflare)."
        ),
        kind=IndicatorKind.SHA256,          # mixed md5/sha1/sha256
        threat_prefix="ClamAV",
        enabled_by_default=False,
        severity=Severity.CRITICAL,
        homepage="https://www.clamav.net/",
    ),
}


# ==========================================================================
# Normalisation helpers
# ==========================================================================
def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def host_indicator_kind(host: str) -> IndicatorKind:
    """Classify a bare host: an IPv4 literal is an IP, anything else a domain."""
    return IndicatorKind.IPV4 if _is_ipv4(host) else IndicatorKind.DOMAIN


def _normalise_host(host: str) -> str:
    """Lowercase, strip the trailing root dot and any default port."""
    host = host.strip().strip(".").lower()
    if host.startswith("[") and "]" in host:          # [::1]:443
        host = host[1 : host.index("]")]
    elif host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host.strip(".")


def normalise_url(raw: str) -> tuple[str, str]:
    """Canonicalise a feed URL.

    Returns ``(url, host)``.  The scheme and host are lowercased, the trailing
    root dot is dropped and a redundant default port (80 for http, 443 for
    https) is removed; the path, query and fragment are left byte-for-byte
    intact because malware URLs are case- and parameter-sensitive.
    Returns ``("", "")`` when *raw* cannot be understood.
    """
    raw = raw.strip().strip('"').strip()
    if not raw:
        return "", ""
    candidate = raw if "://" in raw else f"http://{raw}"
    try:
        parts = urllib.parse.urlsplit(candidate)
    except ValueError:
        return "", ""
    scheme = (parts.scheme or "http").lower()
    host = _normalise_host(parts.hostname or "")
    if not host:
        return "", ""
    port = parts.port
    netloc = f"[{host}]" if ":" in host else host
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        netloc = f"{netloc}:{port}"
    path = parts.path or "/"
    url = urllib.parse.urlunsplit((scheme, netloc, path, parts.query, parts.fragment))
    return url, host


def _clean_name(raw: str, prefix: str, fallback: str) -> str:
    """Build a ``Prefix.Family`` threat name out of a messy feed label."""
    label = re.sub(r"[^0-9A-Za-z]+", ".", (raw or "").strip()).strip(".")
    label = re.sub(r"\.{2,}", ".", label)
    if not label or label.lower() in {"unknown", "none", "null", "na", "n.a"}:
        label = fallback
    return f"{prefix}.{label}"


def _decode(raw: bytes) -> str:
    """Feeds are ASCII/UTF-8 in practice; never raise on a stray byte."""
    return raw.decode("utf-8", "replace")


def _iter_lines(raw: bytes) -> Iterator[str]:
    """Yield stripped, non-comment, non-empty lines."""
    for line in _decode(raw).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        yield line


def _csv_rows(raw: bytes) -> Iterator[list[str]]:
    """Parse an abuse.ch style CSV: ``#`` comment lines, quoted fields."""
    text = "\n".join(
        line for line in _decode(raw).splitlines() if line.strip() and not line.lstrip().startswith("#")
    )
    if not text:
        return
    for row in csv.reader(io.StringIO(text), skipinitialspace=True):
        if row:
            yield [cell.strip().strip('"') for cell in row]


def _header_rows(raw: bytes) -> list[str]:
    """Column names from the last ``#``-commented header line of a CSV."""
    header: list[str] = []
    for line in _decode(raw).splitlines():
        stripped = line.strip()
        if not stripped.startswith("#"):
            break
        candidate = stripped.lstrip("#").strip()
        if "," in candidate and " " not in candidate.replace(",", ""):
            header = [c.strip().strip('"').lower() for c in candidate.split(",")]
    return header


# ==========================================================================
# Per-feed parsers
# ==========================================================================
def _ip_indicators(
    spec: FeedSpec, raw: bytes, *, now: float, family: str = "C2"
) -> list[Indicator]:
    """Plain-text IP blocklist: one address per line, ``#`` comments."""
    out: list[Indicator] = []
    for line in _iter_lines(raw):
        token = line.split(",")[0].split()[0].strip()
        if not _is_ipv4(token):
            continue
        out.append(
            Indicator(
                kind=IndicatorKind.IPV4,
                value=token,
                name=f"{spec.threat_prefix}.{family}",
                severity=spec.severity,
                source=spec.id,
                tags=("c2", "network"),
                description=f"Adres C2 z listy {spec.name}",
                added_at=now,
            )
        )
    return out


def _parse_feodo_json(spec: FeedSpec, raw: bytes, *, now: float) -> list[Indicator]:
    """Feodo Tracker JSON: ``[{"ip_address","port","malware","status",...}]``."""
    try:
        data = json.loads(_decode(raw) or "[]")
    except ValueError:
        # The JSON variant occasionally serves the plain-text list.
        return _ip_indicators(spec, raw, now=now)
    if not isinstance(data, list):
        return []
    out: list[Indicator] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        ip = str(entry.get("ip_address") or "").strip()
        if not _is_ipv4(ip):
            continue
        port = entry.get("port")
        status = str(entry.get("status") or "").strip().lower()
        tags = ["c2", "network"]
        if status:
            tags.append(status)
        detail = f"Serwer C2 {_clean_name(str(entry.get('malware') or ''), '', 'C2').lstrip('.')}"
        if port:
            detail += f", port {port}"
        if entry.get("country"):
            detail += f", kraj {entry['country']}"
        out.append(
            Indicator(
                kind=IndicatorKind.IPV4,
                value=ip,
                name=_clean_name(str(entry.get("malware") or ""), spec.threat_prefix, "C2"),
                # An offline C2 is historical evidence, not a live threat.
                severity=spec.severity if status != "offline" else Severity.MEDIUM,
                source=spec.id,
                tags=tuple(tags),
                description=detail,
                added_at=now,
            )
        )
    return out


def _parse_sslbl_ip_csv(spec: FeedSpec, raw: bytes, *, now: float) -> list[Indicator]:
    """SSLBL IP CSV: ``Firstseen,DstIP,DstPort`` (deprecated, usually empty)."""
    out: list[Indicator] = []
    for row in _csv_rows(raw):
        ip = next((cell for cell in row if _is_ipv4(cell)), "")
        if not ip:
            continue
        port = row[2] if len(row) > 2 else ""
        out.append(
            Indicator(
                kind=IndicatorKind.IPV4,
                value=ip,
                name=f"{spec.threat_prefix}.C2",
                severity=spec.severity,
                source=spec.id,
                tags=("c2", "network", "tls"),
                description=f"Serwer C2 z SSLBL{f', port {port}' if port else ''}",
                added_at=now,
            )
        )
    return out


def _parse_sslbl_certs_csv(spec: FeedSpec, raw: bytes, *, now: float) -> list[Indicator]:
    """SSLBL certificate CSV: ``Listingdate,SHA1,Listingreason``."""
    out: list[Indicator] = []
    for row in _csv_rows(raw):
        sha1 = next(
            (c.lower() for c in row if len(c) == 40 and _HEX_RE.match(c.lower())), ""
        )
        if not sha1:
            continue
        reason = row[2] if len(row) > 2 else ""
        family = re.sub(r"\s*C&?C\s*$", "", reason, flags=re.IGNORECASE)
        out.append(
            Indicator(
                kind=IndicatorKind.SHA1,
                value=sha1,
                name=_clean_name(family, spec.threat_prefix, "C2"),
                severity=spec.severity,
                source=spec.id,
                # Tagged so a future TLS-inspection layer can tell these apart
                # from genuine file hashes.
                tags=("ssl-cert", "c2", "not-a-file-hash"),
                description=f"Odcisk SHA1 certyfikatu TLS serwera C2 ({reason or 'C&C'})",
                added_at=now,
            )
        )
    return out


def _url_indicators(
    spec: FeedSpec,
    url: str,
    *,
    name: str,
    now: float,
    tags: Sequence[str] = ("malware-url", "network"),
    description: str = "",
) -> list[Indicator]:
    """Build the URL indicator plus the derived host indicator.

    The behaviour monitor sees connections to *hosts*, not full URLs, so every
    URL also contributes a DOMAIN (or IPV4, for a bare-IP host) indicator.
    """
    canonical, host = normalise_url(url)
    if not canonical:
        return []
    out = [
        Indicator(
            kind=IndicatorKind.URL,
            value=canonical,
            name=name,
            severity=spec.severity,
            source=spec.id,
            tags=tuple(tags),
            description=description or f"Adres URL rozsiewający malware ({spec.name})",
            added_at=now,
        )
    ]
    if host:
        out.append(
            Indicator(
                kind=host_indicator_kind(host),
                value=host,
                name=name,
                # A host is weaker evidence than the exact URL: shared hosting
                # and compromised legitimate sites are common.
                severity=Severity.MEDIUM,
                source=spec.id,
                tags=tuple(tags) + ("derived-from-url",),
                description=f"Host adresu URL rozsiewającego malware ({spec.name})",
                added_at=now,
            )
        )
    return out


def _parse_urlhaus_text(spec: FeedSpec, raw: bytes, *, now: float) -> list[Indicator]:
    """URLhaus plain text: one URL per line."""
    out: list[Indicator] = []
    for line in _iter_lines(raw):
        out.extend(
            _url_indicators(spec, line, name=f"{spec.threat_prefix}.MalwareURL", now=now)
        )
    return out


def _parse_urlhaus_csv(spec: FeedSpec, raw: bytes, *, now: float) -> list[Indicator]:
    """URLhaus CSV: ``id,dateadded,url,url_status,last_online,threat,tags,...``."""
    header = _header_rows(raw)
    out: list[Indicator] = []
    for row in _csv_rows(raw):
        if header and row and row[0].strip().lower() == header[0]:
            continue                                     # repeated header row
        url = next((cell for cell in row if "://" in cell), "")
        if not url:
            continue
        threat = row[5] if len(row) > 5 else ""
        extra = row[6] if len(row) > 6 else ""
        tags = ["malware-url", "network"]
        tags += [t for t in re.split(r"[,|]", extra) if t and len(t) < 32][:4]
        out.extend(
            _url_indicators(
                spec,
                url,
                name=_clean_name(threat, spec.threat_prefix, "MalwareURL"),
                now=now,
                tags=tags,
            )
        )
    return out


def _parse_hash_list(spec: FeedSpec, raw: bytes, *, now: float) -> list[Indicator]:
    """One hex hash per line; the length decides md5/sha1/sha256."""
    out: list[Indicator] = []
    for line in _iter_lines(raw):
        token = line.split(",")[0].split()[0].strip().strip('"').lower()
        kind = _HASH_KIND_BY_LEN.get(len(token))
        if kind is None or not _HEX_RE.match(token):
            continue
        out.append(
            Indicator(
                kind=kind,
                value=token,
                name=f"{spec.threat_prefix}.Sample",
                severity=spec.severity,
                source=spec.id,
                tags=("sample",),
                description=f"Znana próbka malware z {spec.name}",
                added_at=now,
            )
        )
    return out


def _parse_bazaar_csv(spec: FeedSpec, raw: bytes, *, now: float) -> list[Indicator]:
    """MalwareBazaar CSV: hash columns plus a ``signature`` (family) column.

    Layout (abuse.ch):
    ``first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,
    file_type_guess,mime_type,signature,clamav,vtpercent,imphash,...``
    """
    out: list[Indicator] = []
    for row in _csv_rows(raw):
        hashes: dict[IndicatorKind, str] = {}
        for cell in row:
            token = cell.strip().lower()
            kind = _HASH_KIND_BY_LEN.get(len(token))
            if kind is not None and _HEX_RE.match(token) and kind not in hashes:
                hashes[kind] = token
        if not hashes:
            continue
        signature = row[8] if len(row) > 8 else ""
        file_type = row[6] if len(row) > 6 else ""
        name = _clean_name(signature, spec.threat_prefix, "Sample")
        detail = f"Próbka z MalwareBazaar{f' ({file_type})' if file_type else ''}"
        for kind, value in hashes.items():
            out.append(
                Indicator(
                    kind=kind,
                    value=value,
                    name=name,
                    severity=spec.severity,
                    source=spec.id,
                    tags=("sample", "malwarebazaar"),
                    description=detail,
                    added_at=now,
                )
            )
    return out


_THREATFOX_KINDS: dict[str, IndicatorKind] = {
    "domain": IndicatorKind.DOMAIN,
    "url": IndicatorKind.URL,
    "ip:port": IndicatorKind.IPV4,
    "ip": IndicatorKind.IPV4,
    "md5_hash": IndicatorKind.MD5,
    "sha1_hash": IndicatorKind.SHA1,
    "sha256_hash": IndicatorKind.SHA256,
}


def _parse_threatfox_json(spec: FeedSpec, raw: bytes, *, now: float) -> list[Indicator]:
    """ThreatFox export: ``{"<id>": [{"ioc_value","ioc_type","malware_printable"}]}``."""
    try:
        data = json.loads(_decode(raw) or "{}")
    except ValueError:
        return []
    entries: list[dict[str, Any]] = []
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list):
                entries.extend(e for e in value if isinstance(e, dict))
            elif isinstance(value, dict):
                entries.append(value)
    elif isinstance(data, list):
        entries = [e for e in data if isinstance(e, dict)]

    out: list[Indicator] = []
    for entry in entries:
        value = str(entry.get("ioc_value") or "").strip()
        ioc_type = str(entry.get("ioc_type") or "").strip().lower()
        if not value:
            continue
        name = _clean_name(
            str(entry.get("malware_printable") or entry.get("malware") or ""),
            spec.threat_prefix,
            "IOC",
        )
        kind = _THREATFOX_KINDS.get(ioc_type)
        if kind is IndicatorKind.URL or (kind is None and "://" in value):
            out.extend(_url_indicators(spec, value, name=name, now=now))
            continue
        if kind is IndicatorKind.IPV4 or ioc_type == "ip:port":
            host = _normalise_host(value)
            if not _is_ipv4(host):
                continue
            kind = IndicatorKind.IPV4
            value = host
        elif kind in (IndicatorKind.MD5, IndicatorKind.SHA1, IndicatorKind.SHA256):
            value = value.lower()
            if not _HEX_RE.match(value):
                continue
        elif kind is IndicatorKind.DOMAIN:
            value = _normalise_host(value)
            if not value:
                continue
        else:
            continue
        out.append(
            Indicator(
                kind=kind,
                value=value,
                name=name,
                severity=spec.severity,
                source=spec.id,
                tags=("threatfox", str(entry.get("threat_type") or "ioc")),
                description=f"Wskaźnik ThreatFox typu {ioc_type or 'nieznany'}",
                added_at=now,
            )
        )
    return out


def _parse_curated_json(spec: FeedSpec, raw: bytes, *, now: float) -> list[Indicator]:
    """Our own curated dump: ``{"version","generated_at","indicators":[...]}``."""
    try:
        data = json.loads(_decode(raw) or "{}")
    except ValueError:
        return []
    rows = data.get("indicators") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return []
    out: list[Indicator] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            indicator = Indicator.from_dict(row)
        except (KeyError, TypeError, ValueError):
            continue
        if not indicator.value:
            continue
        out.append(indicator)
    return out


def _parse_clamav_cvd(spec: FeedSpec, raw: bytes, *, now: float) -> list[Indicator]:
    """ClamAV CVD: 512-byte ASCII header, then a gzipped tar.

    We only read the hash databases (``.hdb``/``.hsb``/``.mdb``/``.msb``) whose
    lines are ``hash:size:name``; the regex/logical signature sections use
    ClamAV's own bytecode format and are out of scope.
    """
    if raw[:10] != b"ClamAV-VDB":
        # Accept a bare gzipped tar too, so the parser is testable in isolation.
        body = raw
    else:
        body = raw[512:]
    out: list[Indicator] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                if not member.name.lower().endswith((".hdb", ".hsb", ".mdb", ".msb")):
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                for line in handle.read().decode("utf-8", "replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) < 3:
                        continue
                    token = parts[0].strip().lower()
                    kind = _HASH_KIND_BY_LEN.get(len(token))
                    if kind is None or not _HEX_RE.match(token):
                        continue
                    out.append(
                        Indicator(
                            kind=kind,
                            value=token,
                            name=_clean_name(parts[2], spec.threat_prefix, "Malware"),
                            severity=spec.severity,
                            source=spec.id,
                            tags=("clamav", Path(member.name).suffix.lstrip(".")),
                            description=f"Sygnatura ClamAV z {member.name}",
                            added_at=now,
                        )
                    )
    except (tarfile.TarError, EOFError, OSError, zlib.error, gzip.BadGzipFile) as exc:
        raise ValueError(f"nieczytelny plik CVD: {exc}") from exc
    return out


def parse_feed(spec: FeedSpec, raw: bytes) -> list[Indicator]:
    """Turn a downloaded feed body into indicators tagged ``source=spec.id``.

    Never raises on malformed content: unparseable lines are skipped.  Only a
    structurally broken container (a corrupt CVD) raises :class:`ValueError`.
    """
    now = time.time()
    if spec.id == "github_curated":
        indicators = _parse_curated_json(spec, raw, now=now)
    elif spec.id == "feodo_ipblocklist":
        indicators = _parse_feodo_json(spec, raw, now=now)
    elif spec.id == "feodo_aggressive":
        indicators = _ip_indicators(spec, raw, now=now)
    elif spec.id == "sslbl_ipblocklist":
        indicators = _parse_sslbl_ip_csv(spec, raw, now=now)
    elif spec.id == "sslbl_certs":
        indicators = _parse_sslbl_certs_csv(spec, raw, now=now)
    elif spec.id == "malwarebazaar_recent":
        indicators = _parse_bazaar_csv(spec, raw, now=now)
    elif spec.id == "malwarebazaar_sha256":
        indicators = _parse_hash_list(spec, raw, now=now)
    elif spec.id == "urlhaus_online":
        indicators = (
            _parse_urlhaus_csv(spec, raw, now=now)
            if b"," in raw.split(b"\n", 1)[0] or b"url_status" in raw[:4096]
            else _parse_urlhaus_text(spec, raw, now=now)
        )
    elif spec.id == "threatfox_recent":
        indicators = _parse_threatfox_json(spec, raw, now=now)
    elif spec.id == "clamav_daily":
        indicators = _parse_clamav_cvd(spec, raw, now=now)
    else:
        # Unknown feed: fall back to a format sniff so a spec added later still
        # yields something useful.
        head = raw.lstrip()[:1]
        if head in (b"{", b"["):
            indicators = _parse_curated_json(spec, raw, now=now) or _parse_threatfox_json(
                spec, raw, now=now
            )
        elif spec.kind in (IndicatorKind.URL, IndicatorKind.DOMAIN):
            indicators = _parse_urlhaus_text(spec, raw, now=now)
        elif spec.kind is IndicatorKind.IPV4:
            indicators = _ip_indicators(spec, raw, now=now)
        else:
            indicators = _parse_hash_list(spec, raw, now=now)

    # Every indicator must carry the feed id so clear_source() can roll it back.
    return [
        ind if ind.source == spec.id else _retag(ind, spec.id) for ind in indicators
    ]


def _retag(indicator: Indicator, source: str) -> Indicator:
    """Copy *indicator* with a different ``source`` (it is frozen)."""
    data = indicator.to_dict()
    data["source"] = source
    return Indicator.from_dict(data)


# ==========================================================================
# HTTP
# ==========================================================================
def _request_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Outbound headers.

    Privacy rule: exactly one identity header, a constant product name.  No
    hostname, user name, locale, local path or anything else derived from the
    machine ever goes out.
    """
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Encoding": "gzip",
    }
    if extra:
        headers.update({k: v for k, v in extra.items() if v})
    return headers


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, min(MAX_RETRY_AFTER, float(value)))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime

        when = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    delay = when.timestamp() - time.time()
    return max(0.0, min(MAX_RETRY_AFTER, delay))


def _read_capped(handle: Any, max_bytes: int) -> tuple[bytes, bool]:
    """Stream *handle* into memory, stopping at *max_bytes*.

    Returns ``(data, truncated)``.  Reading in chunks means a feed that is far
    bigger than advertised can never exhaust memory or disk.
    """
    chunks: list[bytes] = []
    total = 0
    truncated = False
    chunk_size = 256 * 1024
    while True:
        chunk = handle.read(min(chunk_size, max(1, max_bytes - total + 1)))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            overflow = total - max_bytes
            keep = len(chunk) - overflow
            if keep > 0:
                chunks.append(chunk[:keep])
            truncated = True
            break
        chunks.append(chunk)
    return b"".join(chunks), truncated


def _decompress(data: bytes, encoding: str = "", *, member: str | None = None) -> bytes:
    """Transparently unwrap gzip / zip payloads.

    A truncated gzip stream is decompressed as far as it goes instead of
    failing, so a size-capped download still yields usable lines.  For a zip we
    take *member* when given, otherwise the largest member.
    """
    if data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = [i for i in archive.infolist() if not i.is_dir()]
                if not infos:
                    return b""
                chosen = None
                if member:
                    chosen = next((i for i in infos if i.filename == member), None)
                if chosen is None:
                    chosen = max(infos, key=lambda i: i.file_size)
                with archive.open(chosen) as handle:
                    return handle.read()
        except (zipfile.BadZipFile, OSError, RuntimeError, zlib.error) as exc:
            raise ValueError(f"nieczytelne archiwum ZIP: {exc}") from exc
    if data[:2] == b"\x1f\x8b" or "gzip" in encoding.lower():
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = b""
        try:
            out = decompressor.decompress(data)
            out += decompressor.flush()
        except zlib.error as exc:
            # A size-capped download leaves a half gzip stream; keep whatever
            # decompressed cleanly instead of throwing the whole feed away.
            if not out:
                raise ValueError(f"nieczytelny strumień gzip: {exc}") from exc
        return out
    return data


_TRANSIENT_ERRORS = (
    urllib.error.URLError,
    socket.timeout,
    TimeoutError,
    ConnectionError,
    OSError,
)


def fetch(
    url: str,
    *,
    timeout: float = 30.0,
    headers: dict[str, str] | None = None,
    etag: str | None = None,
    last_modified: str | None = None,
    max_bytes: int = 64 * 1024 * 1024,
) -> tuple[bytes | None, dict[str, str]]:
    """GET *url* and return ``(body, meta)``; ``(None, meta)`` on HTTP 304.

    * Conditional request: *etag* / *last_modified* become ``If-None-Match`` /
      ``If-Modified-Since``.
    * ``gzip``, ``zip`` and plain bodies are handled transparently.
    * Transient failures (timeout, 5xx, 429) are retried with exponential
      backoff, at most :data:`MAX_ATTEMPTS` attempts in total; ``Retry-After``
      is honoured when present.
    * *max_bytes* is enforced while streaming, so an unexpectedly huge feed
      cannot exhaust memory.  ``meta["truncated"] == "1"`` reports the cut.

    Raises :class:`urllib.error.HTTPError` / :class:`OSError` for permanent
    failures; :meth:`IntelUpdater.update_feed` converts those into a
    ``FeedResult``.
    """
    conditional: dict[str, str] = {}
    if etag:
        conditional["If-None-Match"] = etag
    if last_modified:
        conditional["If-Modified-Since"] = last_modified
    request_headers = _request_headers({**conditional, **(headers or {})})

    meta: dict[str, str] = {"url": url}
    last_error: BaseException | None = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        request = urllib.request.Request(url, headers=request_headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = int(getattr(response, "status", 0) or response.getcode() or 0)
                info = response.headers
                meta.update(
                    {
                        "status": str(status),
                        "etag": (info.get("ETag") or "").strip(),
                        "last_modified": (info.get("Last-Modified") or "").strip(),
                        "content_type": (info.get("Content-Type") or "").strip(),
                    }
                )
                if status == 304:
                    meta["bytes"] = "0"
                    return None, meta
                payload, truncated = _read_capped(response, max_bytes)
                encoding = info.get("Content-Encoding") or ""
            body = _decompress(payload, encoding)
            meta["bytes"] = str(len(body))
            meta["raw_bytes"] = str(len(payload))
            if truncated:
                meta["truncated"] = "1"
            return body, meta

        except urllib.error.HTTPError as exc:
            meta["status"] = str(exc.code)
            if exc.code == 304:
                meta["bytes"] = "0"
                meta["etag"] = (exc.headers.get("ETag") or "").strip() if exc.headers else ""
                return None, meta
            last_error = exc
            retryable = exc.code == 429 or 500 <= exc.code < 600
            if not retryable or attempt >= MAX_ATTEMPTS:
                raise
            delay = _parse_retry_after(exc.headers.get("Retry-After") if exc.headers else None)
            _sleep(delay if delay is not None else BACKOFF_BASE * (2 ** (attempt - 1)))

        except _TRANSIENT_ERRORS as exc:
            last_error = exc
            if attempt >= MAX_ATTEMPTS:
                raise
            _sleep(BACKOFF_BASE * (2 ** (attempt - 1)))

    # Unreachable in practice: the loop either returns or re-raises.
    raise OSError(f"nie udało się pobrać {url}: {last_error}")


# ==========================================================================
# Feed state (ETag / Last-Modified bookkeeping)
# ==========================================================================
def _load_state(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"feeds": {}, "last_update": None}
    if not isinstance(data, dict):
        return {"feeds": {}, "last_update": None}
    feeds = data.get("feeds")
    data["feeds"] = feeds if isinstance(feeds, dict) else {}
    return data


def _save_state(path: Path, state: dict[str, Any]) -> None:
    """Atomically persist the feed state with private permissions."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(state, indent=2, ensure_ascii=False, sort_keys=True)
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".feedstate-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    except OSError:
        # Losing the cache is annoying, never fatal: the next update just
        # re-downloads instead of getting a 304.
        pass


# ==========================================================================
# The updater
# ==========================================================================
class IntelUpdater:
    """Pulls the configured feeds into a :class:`~aegis.core.signatures.SignatureDB`.

    Feeds run **sequentially** so the event order on the bus is deterministic:
    ``DB_UPDATE_STARTED``, one ``DB_UPDATE_FEED`` per feed, ``DB_UPDATE_FINISHED``.
    """

    def __init__(self, db: Any, config: Config, bus: EventBus | None = None) -> None:
        self.db = db
        self.config = config
        self.bus = bus
        self._state = _load_state(config.feed_state_path)

    # -- public API ------------------------------------------------------
    def available(self) -> list[dict[str, Any]]:
        """Describe every known feed, for the feed table in the GUI."""
        enabled = set(self.config.feeds_enabled or ())
        out: list[dict[str, Any]] = []
        for spec in AVAILABLE_FEEDS.values():
            entry = self._state["feeds"].get(spec.id, {})
            out.append(
                {
                    "id": spec.id,
                    "name": spec.name,
                    "description": spec.description,
                    "url": spec.url,
                    "kind": spec.kind.value,
                    "severity": spec.severity.value,
                    "requires_key": spec.requires_key,
                    "has_key": bool(self._key_for(spec)),
                    "enabled": spec.id in enabled,
                    "enabled_by_default": spec.enabled_by_default,
                    "homepage": spec.homepage,
                    "last_success": entry.get("last_success"),
                    "last_attempt": entry.get("last_attempt"),
                    "last_count": entry.get("count"),
                    "last_error": entry.get("error") or "",
                }
            )
        return out

    def last_update(self) -> float | None:
        value = self._state.get("last_update")
        try:
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def update(
        self, feed_ids: Sequence[str] | None = None, *, force: bool = False
    ) -> list[FeedResult]:
        """Refresh *feed_ids* (default: ``config.feeds_enabled``)."""
        ids = self._select(feed_ids)
        started = time.time()
        self._publish(
            EventType.DB_UPDATE_STARTED,
            f"Aktualizacja bazy sygnatur: {len(ids)} źródeł",
            feeds=list(ids),
            count=len(ids),
        )

        results: list[FeedResult] = []
        budget = max(0, int(self.config.feed_max_indicators))
        for feed_id in ids:
            result = self.update_feed(feed_id, force=force, _budget=budget)
            results.append(result)
            budget = max(0, budget - result.added - result.updated)
            level = "success" if result.ok else "warning"
            if result.skipped_unchanged:
                message = f"{feed_id}: bez zmian (HTTP 304)"
                level = "info"
            elif result.ok:
                message = (
                    f"{feed_id}: {len(result.indicators)} wskaźników "
                    f"(nowych {result.added}, zaktualizowanych {result.updated})"
                )
            else:
                message = f"{feed_id}: błąd - {result.error}"
            self._publish(EventType.DB_UPDATE_FEED, message, level=level, **result.to_dict())

        total_added = sum(r.added for r in results)
        total_updated = sum(r.updated for r in results)
        failed = [r.feed_id for r in results if not r.ok]
        self._state["last_update"] = started
        _save_state(self.config.feed_state_path, self._state)
        self._publish(
            EventType.DB_UPDATE_FINISHED,
            (
                f"Zakończono aktualizację: +{total_added} nowych, "
                f"{total_updated} zaktualizowanych"
                + (f", nieudane źródła: {', '.join(failed)}" if failed else "")
            ),
            level="warning" if failed else "success",
            added=total_added,
            updated=total_updated,
            failed=failed,
            duration_ms=(time.time() - started) * 1000.0,
            results=[r.to_dict() for r in results],
        )
        return results

    def update_feed(
        self, feed_id: str, *, force: bool = False, _budget: int | None = None
    ) -> FeedResult:
        """Refresh exactly one feed.  Never raises - failures become the result."""
        started = time.time()
        spec = AVAILABLE_FEEDS.get(feed_id)
        if spec is None:
            return FeedResult(
                feed_id=feed_id,
                ok=False,
                error=f"Nieznane źródło danych: {feed_id}",
                duration_ms=(time.time() - started) * 1000.0,
            )

        if spec.id == "builtin":
            return self._update_builtin(spec, started)

        key = self._key_for(spec)
        if spec.requires_key and not key:
            # Do not even attempt the request: it would only produce a
            # confusing 401/403/410 in the log.
            env_name = f"AEGIS_{spec.id.upper()}_KEY"
            return self._finish(
                spec,
                FeedResult(
                    feed_id=spec.id,
                    ok=False,
                    error=(
                        f"Źródło '{spec.name}' wymaga darmowego klucza API. "
                        f"Ustaw go w konfiguracji (feed_api_keys['{spec.id}']) "
                        f"albo w zmiennej środowiskowej {env_name}. "
                        f"Klucz uzyskasz na {spec.homepage or 'https://auth.abuse.ch/'}."
                    ),
                    duration_ms=(time.time() - started) * 1000.0,
                ),
                attempted=False,
            )

        entry = self._state["feeds"].get(spec.id, {}) if not force else {}
        max_bytes = CLAMAV_MAX_BYTES if spec.id == "clamav_daily" else 64 * 1024 * 1024
        headers = {"Auth-Key": key} if (key and not spec.key_in_url) else None

        try:
            body, meta = fetch(
                spec.resolved_url(key),
                timeout=float(self.config.feed_timeout_sec),
                headers=headers,
                etag=entry.get("etag") or None,
                last_modified=entry.get("last_modified") or None,
                max_bytes=max_bytes,
            )
        except urllib.error.HTTPError as exc:
            return self._finish(
                spec,
                FeedResult(
                    feed_id=spec.id,
                    ok=False,
                    error=f"HTTP {exc.code} {exc.reason} przy pobieraniu {spec.url}",
                    duration_ms=(time.time() - started) * 1000.0,
                ),
            )
        except Exception as exc:  # noqa: BLE001 - a feed must never break update()
            return self._finish(
                spec,
                FeedResult(
                    feed_id=spec.id,
                    ok=False,
                    error=f"Błąd sieci przy pobieraniu {spec.url}: {exc}",
                    duration_ms=(time.time() - started) * 1000.0,
                ),
            )

        if body is None:
            return self._finish(
                spec,
                FeedResult(
                    feed_id=spec.id,
                    ok=True,
                    skipped_unchanged=True,
                    duration_ms=(time.time() - started) * 1000.0,
                ),
                meta=meta,
            )

        try:
            indicators = parse_feed(spec, body)
        except Exception as exc:  # noqa: BLE001 - malformed payload is not a crash
            return self._finish(
                spec,
                FeedResult(
                    feed_id=spec.id,
                    ok=False,
                    error=f"Nie udało się sparsować danych z {spec.name}: {exc}",
                    duration_ms=(time.time() - started) * 1000.0,
                ),
                meta=meta,
            )

        if meta.get("truncated") == "1":
            self._publish(
                EventType.LOG,
                f"{spec.id}: pobieranie przerwane po {max_bytes} bajtach - "
                f"dane mogą być niepełne",
                level="warning",
            )

        limit = _budget if _budget is not None else max(0, int(self.config.feed_max_indicators))
        if len(indicators) > limit:
            self._publish(
                EventType.LOG,
                f"{spec.id}: limit {self.config.feed_max_indicators} wskaźników "
                f"osiągnięty - przyjęto {limit} z {len(indicators)}",
                level="warning",
            )
            indicators = indicators[:limit]

        added = updated = 0
        if indicators:
            try:
                added, updated = self.db.add_many(indicators)
            except Exception as exc:  # noqa: BLE001 - DB problem is a feed failure
                return self._finish(
                    spec,
                    FeedResult(
                        feed_id=spec.id,
                        ok=False,
                        indicators=indicators,
                        error=f"Nie udało się zapisać wskaźników do bazy: {exc}",
                        duration_ms=(time.time() - started) * 1000.0,
                    ),
                    meta=meta,
                )

        return self._finish(
            spec,
            FeedResult(
                feed_id=spec.id,
                ok=True,
                indicators=indicators,
                added=int(added),
                updated=int(updated),
                duration_ms=(time.time() - started) * 1000.0,
            ),
            meta=meta,
        )

    # -- internals -------------------------------------------------------
    def _update_builtin(self, spec: FeedSpec, started: float) -> FeedResult:
        """The ``builtin`` pseudo-feed: load the shipped baseline, no HTTP."""
        from .baseline import builtin_indicators

        try:
            indicators = builtin_indicators()
            added, updated = self.db.add_many(indicators)
        except Exception as exc:  # noqa: BLE001 - must not break update()
            return self._finish(
                spec,
                FeedResult(
                    feed_id=spec.id,
                    ok=False,
                    error=f"Nie udało się wczytać wbudowanej bazy: {exc}",
                    duration_ms=(time.time() - started) * 1000.0,
                ),
            )
        return self._finish(
            spec,
            FeedResult(
                feed_id=spec.id,
                ok=True,
                indicators=indicators,
                added=int(added),
                updated=int(updated),
                duration_ms=(time.time() - started) * 1000.0,
            ),
        )

    def _select(self, feed_ids: Sequence[str] | None) -> list[str]:
        if feed_ids is not None:
            return [fid for fid in feed_ids if fid]
        configured = [fid for fid in (self.config.feeds_enabled or ()) if fid in AVAILABLE_FEEDS]
        if configured:
            return configured
        return [spec.id for spec in AVAILABLE_FEEDS.values() if spec.enabled_by_default]

    def _key_for(self, spec: FeedSpec) -> str:
        """API key from the config, else from ``AEGIS_<FEEDID>_KEY``."""
        key = (self.config.feed_api_keys or {}).get(spec.id, "")
        if not key:
            key = os.environ.get(f"AEGIS_{spec.id.upper()}_KEY", "")
        return key.strip()

    def _finish(
        self,
        spec: FeedSpec,
        result: FeedResult,
        *,
        meta: dict[str, str] | None = None,
        attempted: bool = True,
    ) -> FeedResult:
        """Record per-feed bookkeeping and persist it atomically."""
        entry = dict(self._state["feeds"].get(spec.id, {}))
        if attempted:
            entry["last_attempt"] = result.fetched_at
        if result.ok:
            entry["last_success"] = result.fetched_at
            entry["error"] = ""
            if not result.skipped_unchanged:
                entry["count"] = len(result.indicators)
            if meta:
                if meta.get("etag"):
                    entry["etag"] = meta["etag"]
                if meta.get("last_modified"):
                    entry["last_modified"] = meta["last_modified"]
        else:
            entry["error"] = result.error
        self._state["feeds"][spec.id] = entry
        _save_state(self.config.feed_state_path, self._state)
        return result

    def _publish(
        self, type: EventType, message: str, level: str = "info", **payload: Any
    ) -> None:
        if self.bus is not None:
            self.bus.publish(type, message, level=level, **payload)
