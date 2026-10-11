"""
Provenance hashing utilities.
Provides deterministic SHA-256 hashing for files and content blobs.
Hashes support integrity checking but do not guarantee tamper-proof storage.
"""
from __future__ import annotations

import hashlib
from pathlib import Path


CHUNK_SIZE = 65536  # 64 KB


def hash_file(path: Path) -> str:
    """Return hex SHA-256 of a file. Reads in chunks to handle large PCAPs."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_text(text: str) -> str:
    return hash_bytes(text.encode("utf-8"))
