import sys
import os
import zlib
import hashlib
import struct
import binascii
import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument('output', type=str)
parser.add_argument('key', type=str)
parser.add_argument('path', type=str)

args = parser.parse_args()

signature = hashlib.sha256()

fh = open(args.output, "w")
fh.write("\x00" * len(signature.digest())) # 32

for path in os.listdir(args.path):
    # TODO recurse into directories
    path = path.encode("ascii")
    content = open(os.path.join(args.path, path)).read()
    compressed_content = zlib.compress(content)
    h = hashlib.sha256(compressed_content).digest()
    sys.stderr.write("Adding %s (%d bytes, compressed to %d bytes, sha256=%s)\n" % (path,
        len(compressed_content), len(content), binascii.hexlify(h)))
    file_header = struct.pack(">HL32s%ds" % len(path), len(path), len(compressed_content), h, path)
    fh.write(file_header)
    fh.write(compressed_content)
    signature.update(file_header)
    signature.update(compressed_content)

signature.update(binascii.unhexlify(args.key))

fh.seek(0)
fh.write(signature.digest())
sys.stderr.write("Signature=%s\n" % (signature.hexdigest()))
fh.close()

