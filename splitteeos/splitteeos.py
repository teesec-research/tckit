#!/usr/bin/env python
from __future__ import print_function
import sys
import os
import struct
import logging

DUMP_FILES=True
MAKES_SENSE=False

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


def uI(v):
    return struct.unpack("<I", v)[0]


def uH(v):
    return struct.unpack("<H", v)[0]


def us(v, length):
    return struct.unpack("<{}s".format(length), v)[0]


def dump(f, begin, size, name):
    teeos_img_dir = os.path.dirname(os.path.abspath(f.name))
    tas_out_dir = os.path.join(teeos_img_dir, "tas_out")
    if not os.path.exists(tas_out_dir):
        os.mkdir(tas_out_dir)

    f.seek(begin)
    with open(os.path.join(tas_out_dir, name), "w+") as ta_f:
        ta_f.write(f.read(size))


def split(teeos_path):
    log.info("Splitting {}".format(teeos_path))

    with open(teeos_path) as f:
        header_data = f.read(0x2000)
        globaltask_pos = header_data.find("globaltask")
        if globaltask_pos == -1:
            log.error("Could not find globaltask in {}".format(teeos_path))
            return 1

        seek_pos = globaltask_pos & 0xff00
        f.seek(seek_pos)

        # HEADER
        header_begin = f.tell()
        header_size = uI(f.read(4))
        log.debug("header_begin: %s" % hex(header_begin))
        log.debug("header_size: %s" % hex(header_size))

        if header_size != 0x400:
            log.error("header_size is usually 0x400... terminating")
            return 1

        # dunno what these guys are
        log.debug("?: %s" % hex(uH(f.read(2))))
        log.debug("?: %s" % hex(uH(f.read(2))))

        kernel_size = uI(f.read(4))
        tas_begin = header_begin + kernel_size
        log.debug("kernel_size: %s" % hex(kernel_size))

        ta_count = uI(f.read(4))
        log.debug("ta_count: %s" % hex(ta_count))

        # dunno what these guys are either
        log.debug("?: %s" % hex(uI(f.read(4))))
        log.debug("?: %s" % hex(uI(f.read(4))))

        # KERNEL
            # TBD
        # TA

        tas_data = []
        for c in range(ta_count):
            log.debug("")
            ta_off = uI(f.read(4))
            log.debug("ta_off: %s" % hex(ta_off))
            ta_begin = tas_begin + ta_off
            log.debug("\tta begins at -> %s" % hex(ta_begin))
            ta_size = uI(f.read(4))
            log.debug("ta_ondisk_size: %s" % hex(ta_size))
            log.debug("ta_inmem_size?: %s" % hex(uI(f.read(4))))
            ta_name = us(f.read(20), 20).strip("\x00")
            log.debug("name: %s" % ta_name)

            if ta_name in ['globaltask']:
                MAKES_SENSE=True

            tas_data.append((ta_begin, ta_size, ta_name))

            log.debug("uuid: %s %s %s %s" % (
                  hex(uI(f.read(4))),
                  hex(uI(f.read(4))),
                  hex(uI(f.read(4))),
                  hex(uI(f.read(4)))))

        if MAKES_SENSE and DUMP_FILES:
            for ta_data in tas_data:
                dump(f, ta_data[0], ta_data[1], ta_data[2])
            return 0

        if MAKES_SENSE:
            return 0

    return 1


def main(teeos_path):
    return split(teeos_path)


def usage():
    print("%s <teeos.img>" % sys.argv[0])


if __name__=="__main__":
    if len(sys.argv) < 2:
        usage()
        sys.exit()

    if not os.path.exists(sys.argv[1]):
        usage()
        sys.exit()

    sys.exit(main(sys.argv[1]))
