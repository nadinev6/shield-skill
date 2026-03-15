#!/usr/bin/env python3
"""Silas Shield – salted PII hasher.

Usage:
    python hash.py "<data>"
    echo "<data>" | python hash.py

Reads SILAS_SALT from environment. Outputs a 16-char hex digest (SHA-256
truncated) that is consistent for the same input+salt but irreversible.
"""

import hashlib
import os
import sys


def secure_hash(data: str, salt: str) -> str:
    return hashlib.sha256((salt + data).encode("utf-8")).hexdigest()[:16]


def main() -> None:
    salt = os.environ.get("SILAS_SALT", "")
    if not salt:
        print("ERROR: SILAS_SALT environment variable is not set", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) > 1:
        data = sys.argv[1]
    else:
        data = sys.stdin.read().strip()

    if not data:
        print("ERROR: no input provided", file=sys.stderr)
        sys.exit(1)

    print(secure_hash(data, salt))


if __name__ == "__main__":
    main()
