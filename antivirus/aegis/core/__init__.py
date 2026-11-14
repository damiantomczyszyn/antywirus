"""Static scanning engine: hashing, signatures, heuristics, quarantine, scanner.

This is the part of Aegis AV that looks at a file *without* running it.  The
pipeline lives in :mod:`aegis.core.scanner` and glues together:

* :mod:`aegis.core.hashing`     - one streaming pass, three digests;
* :mod:`aegis.core.signatures`  - SQLite indicator store + wildcard patterns;
* :mod:`aegis.core.heuristics`  - structural analysis for unknown samples;
* :mod:`aegis.core.quarantine`  - the obfuscated vault.

Importing this package has no side effects: no I/O, no directories created.
"""

from __future__ import annotations

from .hashing import FileHashes, hash_bytes, hash_file, sha256_file
from .heuristics import HEURISTIC_RULES, analyze, detect_file_type, shannon_entropy
from .quarantine import Quarantine
from .scanner import CancellationToken, ScanResult, Scanner
from .signatures import SignatureDB

__all__ = [
    "FileHashes",
    "hash_file",
    "hash_bytes",
    "sha256_file",
    "SignatureDB",
    "shannon_entropy",
    "detect_file_type",
    "analyze",
    "HEURISTIC_RULES",
    "Quarantine",
    "CancellationToken",
    "ScanResult",
    "Scanner",
]
