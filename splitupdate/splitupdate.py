#!/usr/bin/env python
from __future__ import print_function
import argparse
import sys
import os
import logging
import struct
import hexdump
import subprocess

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

MAGIC = b'\x55\xAA\x5A\xA5'
CRC_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "crc")


class UpdateAppHeader(object):
    magic = None
    length = None
    unknown1 = None
    hardware_id = None
    file_sequence = None
    file_size = None
    file_date = None
    file_time = None
    file_type = None
    blank1 = None
    header_checksum = None
    block_size = None
    blank2 = None
    file_checksum = None
    file_data = ''
    padding = ''
    begin_off = None
    end_off = None
    header_begin_off = None
    header_end_off = None
    file_begin_off = None
    file_end_off = None

    def __str__(self):
        return \
"""
begin_off : {}
end_off : {}
magic : {}
length : {}
unknown1 : {}
hardware_id : {}
file_sequence : {}
file_size : {}
file_date : {}
file_time : {}
file_type : {}
blank1 : {}
header_checksum : {}
block_size : {}
blank2 : {}
""".format(
        self.begin_off,
        self.end_off,
        self.magic,
        self.length,
        self.unknown1,
        self.hardware_id,
        hexdump.hexdump(self.file_sequence, result='return'),
        self.file_size,
        self.file_date,
        self.file_time,
        self.file_type,
        self.blank1,
        self.header_checksum,
        self.block_size,
        self.blank2,
        #"len={}".format(len(self.file_checksum)),
        #"len={}".format(len(self.file_data)),
        #"len={}".format(len(self.padding)),
        #hexdump.hexdump(self.padding, result='return'),
        #hexdump.hexdump(self.file_checksum, result='return'),
        #hexdump.hexdump(self.file_data, result='return'),
        #hexdump.hexdump(self.padding, result='return'),
        )


def pretty_hex(data):
    out = ""
    for c in data:
        out = out + '{:02X}'.format(ord(c))
    return out


def read_chunk(f, chunk_size=1024):
    while True:
        data = f.read(chunk_size)
        if not data:
            break
        yield data


def find_magic(f):
    opos = f.tell()
    for data in read_chunk(f, chunk_size=1024):
        if not data:
            return None

        if MAGIC in data:
            off = f.tell() - 1024 + data.find(MAGIC)
            f.seek(opos)
            return off


def process_headers(f):

    headers = []
    while True:
        #import ipdb; ipdb.set_trace()
        begin = find_magic(f)
        if not begin:
            break
        f.seek(begin)

        h = UpdateAppHeader()
        h.begin_off = begin
        h.magic = pretty_hex(f.read(4))
        h.length = struct.unpack("<I", f.read(4))[0]
        h.unknown1 = f.read(4)
        h.hardware_id = f.read(8)

        if h.hardware_id not in ['HW7x27\xff\xff']:
            del h
            continue

        h.file_sequence = f.read(4)
        h.file_size = struct.unpack("<I", f.read(4))[0]
        h.file_date = f.read(16)
        h.file_time = f.read(16)
        h.file_type = f.read(16).strip('\x00')
        #log.debug("File type: %s" % h.file_type)
        h.blank1 = f.read(16)
        h.header_checksum = pretty_hex(f.read(2))
        h.block_size = struct.unpack("<H", f.read(2))[0]
        h.blank2 = f.read(2)
        headers.append(h)
    return headers


def split(updateapp_path, dump=True):

    log.info("Splitting {}".format(updateapp_path))
    # we are writing the resulting files to <base_dir>/out/
    base_dir = os.path.dirname(os.path.abspath(updateapp_path))
    out_dir = os.path.join(base_dir, "out")
    if not os.path.exists(os.path.join(base_dir, "out")):
        os.mkdir(os.path.join(base_dir, "out"))

    with open(updateapp_path, "rb") as f:
        headers = process_headers(f)

        log.debug("#headers: %i" % len(headers))

        if dump:
            for h in headers:
                # header.file_checksum = header.begin_off + 88
                f.seek(h.begin_off+98)

                log.debug("processing: %s" % h.file_type)
                h.file_checksum = pretty_hex(f.read(h.length-98))
                h.file_begin_off = f.tell()

                data = f.read(h.file_size)

                img_path = os.path.join(out_dir, "{}.img".format(h.file_type))
                log.debug("writing img file: {}".format(img_path))
                with open(img_path, "wb") as img:
                    img.write(data)

                p = subprocess.Popen([CRC_PATH, img_path], stdout=subprocess.PIPE)
                crc = p.stdout.read().strip()

                if h.file_checksum != crc:
                    log.warn("CRC check failed for {}".format(h.file_type))

    return headers


def setup_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--info", action='store_true',
                       help='Get info from header in update_app')
    group.add_argument("-e", "--extract", action='store_true',
                       help='Extract TAs from update_app')
    parser.add_argument("update_app")
    return parser


def main():

    arg_parser = setup_args()
    args = arg_parser.parse_args()

    if not os.path.exists(CRC_PATH):
        print("./crc not found")
        sys.exit(0)

    if args.info:
        headers = split(args.update_app, dump=False)
        for h in headers:
            print(h)
    elif args.extract:
        split(args.update_app)
    else:
        arg_parser.print_help()
    sys.exit()


if __name__ == "__main__":
    main()
