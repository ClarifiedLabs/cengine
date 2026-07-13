#!/usr/bin/env python3
import gzip
import os
import stat
import struct
import sys
from pathlib import Path


def pad4(data: bytes) -> bytes:
    return data + b"\0" * ((-len(data)) & 3)


def field(value: int) -> bytes:
    return f"{value & 0xFFFFFFFF:08x}".encode("ascii")


def record(name: str, mode: int, payload: bytes, inode: int, mtime: int, nlink: int = 1) -> bytes:
    encoded = name.encode("utf-8") + b"\0"
    header = b"070701" + b"".join([
        field(inode), field(mode), field(0), field(0), field(nlink), field(mtime),
        field(len(payload)), field(0), field(0), field(0), field(0), field(len(encoded)), field(0),
    ])
    return pad4(header + encoded) + pad4(payload)


def archive(root: Path, epoch: int) -> bytes:
    output = bytearray()
    paths = [root] + sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix())
    inode = 1
    for path in paths:
        relative = "." if path == root else path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            payload = b""
        elif stat.S_ISLNK(info.st_mode):
            payload = os.readlink(path).encode("utf-8")
        elif stat.S_ISREG(info.st_mode):
            payload = path.read_bytes()
        else:
            raise ValueError(f"unsupported initramfs entry: {path}")
        output.extend(record(relative, info.st_mode, payload, inode, epoch, 2 if stat.S_ISDIR(info.st_mode) else 1))
        inode += 1
    output.extend(record("TRAILER!!!", stat.S_IFREG, b"", inode, epoch))
    return bytes(output)


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: make-initramfs.py ROOT OUTPUT.cpio.gz")
    root = Path(sys.argv[1]).resolve()
    output = Path(sys.argv[2])
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
            compressed.write(archive(root, epoch))


if __name__ == "__main__":
    main()
