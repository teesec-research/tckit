#!/usr/bin/env python
# -*- coding: utf-8 -*-

import struct
import elftools.elf.structs
from elftools.construct import Container
from elftools.elf.constants import *

import sys


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


def build_elf(globaltask):
    with open(globaltask) as f:
        data = f.read()

        # Find begin of symbol name string table (located at the end)
        string_table_begin = find_string_table_begin(data)

        strings = data[string_table_begin:]

        elf_structs = elftools.elf.structs.ELFStructs(True, 32)
        if hasattr(elf_structs, 'create_basic_structs'):
            elf_structs.create_basic_structs()
        if hasattr(elf_structs, 'create_advanced_structs'):
            elf_structs.create_advanced_structs()

        syms = []
        sym_map = {}
        try:
            # Load symbols
            for i in range(1, 100000):
                idx = string_table_begin - 16 * i
                sym = elf_structs.Elf_Sym.parse(data[idx:idx+16])
                sym_name = strings[sym.st_name:strings.index('\x00', sym.st_name)]
                syms.append((sym_name, sym))
                sym_map[sym_name] = sym.st_value
                #if addr == 0 or not sym_name.endswith('.c'):
                #    syms.append((sym_name, addr, type, size, strings_off))
                #    sym_map[sym_name] = addr
        except ValueError:
            pass

        # Sort syms by addr
        syms.sort(key=lambda x: x[1])

        for sym_name, sym in syms:
            print('%s (%s): %s\t\t%s\t%s\t%s\t%s\t%s' % (hex(sym.st_value), hex(sym.st_value - 0xc0006c00), sym_name, hex(sym.st_size), sym.st_info.type, sym.st_info.bind, sym.st_other.visibility, sym.st_shndx))

        process_start    = sym_map['PROCESS_START']
        text_start       = sym_map['TEE_TEXT_START']
        process_end      = text_start
        got_start        = sym_map['TEE_GOT_START']
        text_end         = got_start
        got_end          = sym_map['TEE_GOT_END']
        bss_start        = sym_map['TEE_BSS_START']
        bss_end          = sym_map['TEE_LIB_END']

        def get_data(start_addr, end_addr):
            return data[start_addr - process_start:end_addr - process_start]

        process = Section('.process', data=get_data(process_start, process_end), sh_type='SHT_PROGBITS', sh_flags=SH_FLAGS.SHF_ALLOC|SH_FLAGS.SHF_EXECINSTR, sh_addr=process_start, sh_addralign=4)
        text = Section('.text', data=get_data(text_start, text_end), sh_type='SHT_PROGBITS', sh_flags=SH_FLAGS.SHF_ALLOC|SH_FLAGS.SHF_EXECINSTR, sh_addr=text_start, sh_addralign=4)
        got = Section('.got', data=get_data(got_start, got_end), sh_type='SHT_PROGBITS', sh_flags=SH_FLAGS.SHF_ALLOC|SH_FLAGS.SHF_WRITE, sh_addr=got_start, sh_addralign=4)
        bss = Section('.bss', sh_type='SHT_NOBITS', sh_flags=SH_FLAGS.SHF_ALLOC|SH_FLAGS.SHF_WRITE, sh_addr=bss_start, sh_size=bss_end-bss_start, sh_addralign=4)
        shstrtab = Section('.shstrtab', sh_type='SHT_STRTAB', sh_addralign=1)
        symtab = Section('.symtab', sh_type='SHT_SYMTAB', sh_info=len(syms), sh_addralign=4, sh_entsize=elf_structs.Elf_Sym.sizeof())
        strtab = Section('.strtab', data=strings, sh_type='SHT_STRTAB', sh_addralign=1)
        sections = [
                Section(),
                process,
                text,
                got,
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

        offset = elf_structs.Elf_Ehdr.sizeof() + 3 * elf_structs.Elf_Phdr.sizeof() + len(sections) * elf_structs.Elf_Shdr.sizeof()

        phdr = Container(
            p_type = 'PT_PHDR',
            p_offset = elf_structs.Elf_Ehdr.sizeof(),
            p_vaddr = 0,
            p_paddr = 0,
            p_filesz = 3 * elf_structs.Elf_Phdr.sizeof(),
            p_memsz = 0,
            p_flags = P_FLAGS.PF_R | P_FLAGS.PF_X,
            p_align = 4
            )
        phdr2 = Container(
            p_type = 'PT_LOAD',
            p_offset = offset,
            p_vaddr = 0x0,
            p_paddr = 0x0,
            p_filesz = got_start,
            p_memsz = got_start,
            p_flags = P_FLAGS.PF_R | P_FLAGS.PF_X,
            p_align = 0x1000
            )
        phdr3 = Container(
            p_type = 'PT_LOAD',
            p_offset = offset + got_start,
            p_vaddr = got_start,
            p_paddr = got_start,
            p_filesz = bss_start - got_start,
            p_memsz = bss_end - got_start,
            p_flags = P_FLAGS.PF_R | P_FLAGS.PF_W,
            p_align = 0x1000
            )
        phdrs = [phdr, phdr2, phdr3]

        # Set sh_offset for all sections
        sh_offset = elf_structs.Elf_Ehdr.sizeof() + len(phdrs) * elf_structs.Elf_Phdr.sizeof() + len(sections) * elf_structs.Elf_Shdr.sizeof()
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
            e_entry = process_start,
            e_phoff = elf_structs.Elf_Ehdr.sizeof(),
            e_shoff = elf_structs.Elf_Ehdr.sizeof() + len(phdrs) * elf_structs.Elf_Phdr.sizeof(),
            e_flags = E_FLAGS.EF_ARM_EABI_VER5,
            e_ehsize = elf_structs.Elf_Ehdr.sizeof(),
            e_phentsize = elf_structs.Elf_Phdr.sizeof(),
            e_phnum = len(phdrs),
            e_shentsize = elf_structs.Elf_Shdr.sizeof(),
            e_shnum = len(sections),
            e_shstrndx = sections.index(shstrtab)
            ))

        # Write elf file
        with open(globaltask + '.elf', 'wb') as f:
            # Write ELF Header
            f.write(ehdr)
            # Write Program Headers
            for phdr in phdrs:
                elf_structs.Elf_Phdr.build_stream(phdr, f)
            # Write Section Headers
            for section in sections:
                elf_structs.Elf_Shdr.build_stream(section.hdr, f)
            # Write Section Data
            for section in sections:
                f.write(section.data)


def main():
    if len(sys.argv) != 2:
        print('Usage: ' + sys.argv[0] + ' <globaltask>')
        exit(1)
    build_elf(sys.argv[1])


if __name__ == "__main__":
    main()
