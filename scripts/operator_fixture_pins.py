"""Dependency-free retained-file reader shared by private SDK checkers.

This is the original Gmail reader, unchanged in custody checks, return shape
and fixed diagnostics. Importing it never imports a provider or PKI fixture.
"""
from __future__ import annotations

import os
import stat

from scripts.check_operator_demo import require


def read_pin(path, maximum):
    require(path.is_absolute() and path.resolve() == path, "Gmail SDK file path differs")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, "Gmail SDK file custody differs")
        chunks = bytearray()
        while len(chunks) <= maximum:
            part = os.read(descriptor, min(65536, maximum + 1 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        final = os.fstat(descriptor)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(identity(info) == identity(final) and len(chunks) == info.st_size, "Gmail SDK file changed while pinned")
        return identity(info), bytes(chunks)
    finally:
        os.close(descriptor)
