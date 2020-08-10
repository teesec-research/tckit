#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
import elftools.elf.structs
from elftools.construct import Container
from elftools.elf.constants import *

import sys
import os


class Section(object):
    def __init__(self, name='', data='', **kwargs):
        self.name = name
        self.hdr = Container(sh_name=0, sh_type='SHT_NULL', sh_flags=0, sh_addr=0, sh_offset=0, sh_size=0, sh_link=0, sh_info=0, sh_addralign=0, sh_entsize=0)
        self.data = data
        for key, value in kwargs.iteritems():
            self.hdr[key] = value

    def get_data(self):
        return self._data

    def set_data(self, data):
        self._data = data
        self.hdr.sh_size = len(data)

    data = property(get_data, set_data)

    @property
    def start_addr(self):
        return self.hdr.sh_addr

    @property
    def end_addr(self):
        return self.hdr.sh_addr + self.hdr.sh_size


def u8(v):
    return struct.unpack("<B", v)[0]

def uI(v):
    return struct.unpack("<I", v)[0]

def find_string_table_begin(data):
    position = len(data) - 1
    assert data[position] == '\x00'
    while data[position - 1] == '\x00':
        position -= 1
    while True:
        lastPos = position
        if data[position] != '\x00':
            break
        position -= 1
        while True:
            c = u8(data[position])
            if c < 0x20 or c > 0x7f:
                break
            position -= 1
        if lastPos - position <= 1:
            break
    return lastPos

def build_elf(teeos_img):
    with open(teeos_img) as f:
        # "58 f3 91 e2" seems to be some MAGIC in range 0x80 to 0x1000
        # header begins at 0x1000
        f.seek(0x1000)

        # HEADER
        header_begin = f.tell()
        header_size = uI(f.read(4))

        # anything
        f.read(4)

        kernel_begin = header_begin + header_size
        kernel_size = uI(f.read(4))
        #print('Kernel begin: ' + hex(kernel_begin))
        #print('Kernel end: ' + hex(kernel_begin + kernel_size))

        # Read kernel content
        f.seek(kernel_begin)
        kernel = f.read(kernel_size)

        # Find begin of symbol name string table (located at the end)
        string_table_begin = find_string_table_begin(kernel)

        strings = kernel[string_table_begin:]

        elf_structs = elftools.elf.structs.ELFStructs(True, 32)
        if hasattr(elf_structs, 'create_basic_structs'):
            elf_structs.create_basic_structs()
        if hasattr(elf_structs, 'create_advanced_structs'):
            elf_structs.create_advanced_structs()

        syms = []
        sym_map = {}
        try:
            for i in range(1, 100000):
                idx = string_table_begin - 16 * i
                sym = elf_structs.Elf_Sym.parse(kernel[idx:idx+16])
                sym_name = strings[sym.st_name:strings.index('\x00', sym.st_name)]
                syms.append((sym_name, sym))
                sym_map[sym_name] = sym.st_value
        except ValueError:
            pass

        # Sort syms by addr
        syms.sort(key=lambda x: x[1])

        for sym_name, sym in syms:
            print('%s (%s): %s\t\t%s\t%s\t%s\t%s\t%s' % (hex(sym.st_value), hex(sym.st_value - 0xc0006c00), sym_name, hex(sym.st_size), sym.st_info.type, sym.st_info.bind, sym.st_other.visibility, sym.st_shndx))


        text_start = sym_map['CODE_START']
        text_end   = sym_map['TEXT_END']
        data_start = sym_map['DATA_START']
        data_end   = sym_map['DATA_END']
        bss_start  = sym_map['BSS_START']
        bss_end    = sym_map['BSS_END']

        def get_data(start_addr, end_addr):
            return kernel[start_addr - text_start:end_addr - text_start]

        text = Section('.text', data=get_data(text_start, text_end), sh_type='SHT_PROGBITS', sh_flags=SH_FLAGS.SHF_ALLOC|SH_FLAGS.SHF_EXECINSTR, sh_addr=text_start, sh_addralign=4)
        data = Section('.data', data=get_data(data_start, data_end), sh_type='SHT_PROGBITS', sh_flags=SH_FLAGS.SHF_ALLOC|SH_FLAGS.SHF_WRITE, sh_addr=data_start, sh_addralign=4)
        bss = Section('.bss', sh_type='SHT_NOBITS', sh_flags=SH_FLAGS.SHF_ALLOC|SH_FLAGS.SHF_WRITE, sh_addr=bss_start, sh_size=bss_end-bss_start, sh_addralign=4)
        shstrtab = Section('.shstrtab', sh_type='SHT_STRTAB', sh_addralign=1)
        symtab = Section('.symtab', sh_type='SHT_SYMTAB', sh_info=len(syms), sh_addralign=4, sh_entsize=elf_structs.Elf_Sym.sizeof())
        strtab = Section('.strtab', data=strings, sh_type='SHT_STRTAB', sh_addralign=1)
        sections = [
                Section(),
                text,
                data,
                bss,
                shstrtab,
                symtab,
                strtab,
                ]

        # Add unknown sections before bss
        si = 1
        i = 1
        while True:
            if sections[i] == bss:
                break
            section = sections[i]
            if section.end_addr < sections[i + 1].start_addr:
                # Unknown section missing here
                start_addr = section.end_addr
                end_addr = sections[i + 1].start_addr
                sections.insert(i + 1, Section('.unknown' + str(si), data=get_data(start_addr, end_addr), sh_type='SHT_PROGBITS', sh_flags=SH_FLAGS.SHF_ALLOC|SH_FLAGS.SHF_EXECINSTR|SH_FLAGS.SHF_WRITE, sh_addr=start_addr, sh_addralign=4))
                si += 1
                i += 1
            i += 1

        # Generate .shstrtab section
        for section in sections:
            section.hdr.sh_name = len(shstrtab.data)
            shstrtab.data += section.name + '\x00'

        # Generate .symtab section
        symtab.hdr.sh_link = sections.index(strtab)
        for sym_name, sym in syms:
            # Update section index if it's not a predefined value
            shndx = 0
            for i, section in enumerate(sections):
                if sym.st_value >= section.start_addr and sym.st_value <= section.end_addr and section.hdr.sh_flags & SH_FLAGS.SHF_ALLOC:
                    shndx = i
            if type(sym.st_shndx) == int:
                sym.st_shndx = shndx
            # Build the symbol data
            symtab.data += elf_structs.Elf_Sym.build(sym)

        # Set sh_offset for all sections
        sh_offset = elf_structs.Elf_Ehdr.sizeof() + len(sections) * elf_structs.Elf_Shdr.sizeof()
        for section in sections:
            section.hdr.sh_offset = sh_offset
            sh_offset += len(section.data)

        ehdr = elf_structs.Elf_Ehdr.build(Container(
            e_ident = Container(
                    EI_MAG=[0x7f, 0x45, 0x4c, 0x46],
                    EI_CLASS='ELFCLASS32',
                    EI_DATA='ELFDATA2LSB',
                    EI_VERSION=1,
                    EI_OSABI=0,
                    EI_ABIVERSION=0,
                ),
            e_type = 'ET_EXEC',
            e_machine = 'EM_ARM',
            e_version = 1,
            e_entry = text_start,
            e_phoff = 0,
            e_shoff = elf_structs.Elf_Ehdr.sizeof(),
            e_flags = E_FLAGS.EF_ARM_EABI_VER5,
            e_ehsize = elf_structs.Elf_Ehdr.sizeof(),
            e_phentsize = 0,
            e_phnum = 0,
            e_shentsize = elf_structs.Elf_Shdr.sizeof(),
            e_shnum = len(sections),
            e_shstrndx = sections.index(shstrtab)
            ))

        # Write elf file
        with open(os.path.join(os.path.dirname(teeos_img), 'Rtosck'), 'wb') as f:
            # Write ELF Header
            f.write(ehdr)
            # Write Section Headers
            for section in sections:
                elf_structs.Elf_Shdr.build_stream(section.hdr, f)
            # Write Section Data
            for section in sections:
                f.write(section.data)


def main():
    if len(sys.argv) != 2:
        print('Usage: ' + sys.argv[0] + ' <TEEOS.img>')
        exit(1)
    build_elf(sys.argv[1])

if __name__ == "__main__":
    main()
