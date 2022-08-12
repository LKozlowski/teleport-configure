#!/usr/bin/python3

import hashlib
import struct
import sys


def cli():
    cert = sys.argv[1]

    data = None
    with open(cert, "rb") as f:
        data = f.read()

    # Windows removes last (null) byte from the certificate :D
    data = data[:-1]

    sha1= hashlib.sha1()
    sha1.update(data)

    # CERTIFICATE_MAGIC = b'\x20\x00\x00\x00\x01\x00\x00\x00'
    # 32 and 1 are just certificate magic ^
    header = struct.pack("<III", 32, 1, len(data))

    with open(f"{sha1.digest().hex().upper()}.blob", "wb") as f:
        f.write(header + data)


if __name__ == '__main__':
    cli()
