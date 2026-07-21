"""Atomic writes and cross-process file locks (Windows + POSIX)."""

from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


def atomic_write_text(path: Path, text: str) -> None:
    """Write ``text`` via temp file + ``os.replace`` so readers never see a partial file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


@contextmanager
def interprocess_lock(lock_path: Path, *, timeout: float = 30.0) -> Iterator[None]:
    """Exclusive lock file usable across processes on Windows and POSIX."""
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(lock_path, "a+b")
    locked = False
    try:
        deadline = time.monotonic() + max(0.1, float(timeout))
        while True:
            try:
                if sys.platform == "win32":
                    import msvcrt

                    handle.seek(0)
                    if handle.tell() == 0 and handle.read(1) == b"":
                        handle.write(b"\0")
                        handle.flush()
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"timed out waiting for lock: {lock_path}") from None
                time.sleep(0.05)
        yield
    finally:
        if locked:
            try:
                if sys.platform == "win32":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
        handle.close()
