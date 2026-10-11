"""
Stable ID generation using ULID (lexicographically sortable, collision-resistant).
Falls back to UUID if python-ulid is not installed.
"""
from __future__ import annotations

try:
    from ulid import ULID

    def new_id(prefix: str = "") -> str:
        uid = str(ULID())
        return f"{prefix}_{uid}" if prefix else uid

except ImportError:
    import uuid

    def new_id(prefix: str = "") -> str:  # type: ignore[misc]
        uid = uuid.uuid4().hex
        return f"{prefix}_{uid}" if prefix else uid
