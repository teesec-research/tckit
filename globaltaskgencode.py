#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import struct


class GlobaltaskGenCodeException(Exception):
    pass


def u8(v):
    return struct.unpack("<B", v)[0]


def u32(v):
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


def gencode(globaltask):
    """
    See load_secure_app_image(), get_dx_private_key() and get_dx_public_key()
    functions in globaltask.
    """

    with open(globaltask) as f:
        data = f.read()

    # Find begin of symbol name string table (located at the end)
    string_table_begin = find_string_table_begin(data)
    strings = data[string_table_begin:]
    # Read out symbols
    sym_map = {}
    try:
        # Load symbols
        for i in range(1, 100000):
            idx = string_table_begin - 16 * i
            strings_off = u32(data[idx:idx+4])
            addr = u32(data[idx+4:idx+8])
            size = u32(data[idx+8:idx+12])
            type = u32(data[idx+12:idx+16])
            sym_name = strings[strings_off:strings.index('\x00', strings_off)]
            if addr == 0 or not sym_name.endswith('.c'):
                sym_map[sym_name] = addr
    except ValueError:
        pass

    if len(sym_map) == 0:
        raise GlobaltaskGenCodeException("Could not get symbols.")

    # Generate C code
    ccode = """
    #include <stdio.h>
    #include <sys/mman.h>
    #include <string.h>
    #include <stdint.h>
    """
    ccode += '__attribute__((aligned(0x100000))) unsigned char data[] = {\n'
    for i in range(0, len(data), 30):
        ccode += '    '
        for c in data[i:i+30]:
            ccode += str(u8(c)) + ','
        ccode += '\n'
    ccode += '};\n'
    ccode += """
    void mydump(const char *desc, const char *buf, int len) {
        if (desc) {
            printf("%s = '", desc);
        } else {
            printf("'");
        }
        for (int i = 0; i < len; ++i) {
            printf("\\\\x%02x", buf[i]);
        }
        printf("'\\n");
    }

    int main() {
        // Make pages read write executable
        mprotect(data, sizeof(data), PROT_READ | PROT_WRITE | PROT_EXEC);

        // Fix .got table, as there is an absolute table_zygote_ptr used by wb_decrypt_key
        uint32_t *got_table = (uint32_t*)(data + """ + hex(sym_map['TEE_GOT_START']) + """);
        uint32_t *got_table_end = (uint32_t*)(data + """ + hex(sym_map['TEE_GOT_END']) + """);
        for (uint32_t *entry = got_table; entry != got_table_end; ++entry) {
            if (*entry)
                *entry += (uint32_t)data;
        }

        char *ciphertext1 = data + """ + hex(sym_map['ciphertext1']) + """;
        char *ciphertext2 = data + """ + hex(sym_map['ciphertext2']) + """;
        char*(*wb_decrypt_key)(char *, char *, unsigned int) = ((char*(*)(char*, char*, unsigned int))(data + """ + hex(sym_map['wb_decrypt_key']) + """));

        // Decrypt private key
        char buf[4096] = {0};
        wb_decrypt_key(ciphertext1, buf, 320);
        mydump("private_key", buf, 320);

        // Decrypt public key
        char buf2[4096] = {0};
        wb_decrypt_key(ciphertext2, buf2, 272);
        mydump("public_key", buf2, 272);

        return 0;
    }
    """

    return ccode


def main():
    if len(sys.argv) != 2:
        print('Usage: ' + sys.argv[0] + ' <globaltask>')
        exit(1)
    globaltask_path = sys.argv[1]
    ccode = gencode(globaltask_path)
    # Save C code to disk
    code_path = globaltask_path + '_extract_keys.c'
    with open(code_path, 'w') as f:
        f.write(ccode)


if __name__ == "__main__":
    main()
