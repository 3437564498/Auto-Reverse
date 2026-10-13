"""Construct inert ELF bytes; fixtures are data and are never executed."""

import struct


def build_elf(
    *, sections=True, base=0x10000, symbol_size=8, ifunc=False, features=False, gnu_hash=False
):
    data = bytearray(0x800)
    ident = b"\x7fELF\x02\x01\x01\x00" + bytes(8)
    phnum = 5 if features else 2
    shnum = 8 if sections else 0
    struct.pack_into(
        "<16sHHIQQQIHHHHHH",
        data,
        0,
        ident,
        3,
        183,
        1,
        0,
        64,
        0x600 if sections else 0,
        0,
        64,
        56,
        phnum,
        64,
        shnum,
        7 if sections else 0,
    )
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, base, base, len(data), 0x1000, 0x1000)
    strings = b"\0foo\0malloc\0JNI_OnLoad\0libc.so\0libfixture.so\0"
    data[0x300 : 0x300 + len(strings)] = strings

    def index(name):
        return strings.index(name.encode() + b"\0")

    symbols = [
        bytes(24),
        struct.pack(
            "<IBBHQQ", index("foo"), 0x1A if ifunc else 0x12, 0, 4, base + 0x400, symbol_size
        ),
        struct.pack("<IBBHQQ", index("malloc"), 0x12, 0, 0, 0, 0),
        struct.pack("<IBBHQQ", index("JNI_OnLoad"), 0x12, 0, 4, base + 0x408, 8),
    ]
    data[0x380:0x3E0] = b"".join(symbols)
    # Two pairs of valid-looking ARM64 instructions; no fixture is executed.
    data[0x400:0x410] = bytes.fromhex("00040011c0035fd6000000aac0035fd6")
    tags = [
        (5, base + 0x300),
        (10, len(strings)),
        (6, base + 0x380),
        (11, 24),
        (1, index("libc.so")),
        (14, index("libfixture.so")),
        (12, base + 0x400),
        (25, base + 0x440),
        (27, 8),
    ]
    struct.pack_into("<Q", data, 0x440, base + 0x400)
    if gnu_hash:
        tags += [(0x6FFFFEF5, base + 0x4A0)]
        # 1 bucket, first hashed symbol 1, one 64-bit bloom word,
        # bucket 1 and three chain entries, terminated at symbol 3.
        struct.pack_into("<IIIIQIIII", data, 0x4A0, 1, 1, 1, 0, 0, 1, 2, 4, 7)
    else:
        tags += [(4, base + 0x4A0)]
        struct.pack_into("<IIIIIII", data, 0x4A0, 1, 4, 1, 0, 0, 0, 0)
    if features:
        tags += [(0x60000011, base + 0x460), (0x60000012, 8), (36, base + 0x470), (35, 8), (37, 8)]
        data[0x460:0x468] = b"APS2\0\0\0\0"
        struct.pack_into("<Q", data, 0x470, base + 0x440)
    tags += [(0, 0)]
    dynamic = b"".join(struct.pack("<qQ", tag, value) for tag, value in tags)
    data[0x200 : 0x200 + len(dynamic)] = dynamic
    struct.pack_into(
        "<IIQQQQQQ",
        data,
        120,
        2,
        4,
        0x200,
        base + 0x200,
        base + 0x200,
        len(dynamic),
        len(dynamic),
        8,
    )
    if features:
        struct.pack_into(
            "<IIQQQQQQ", data, 176, 7, 4, 0x480, base + 0x480, base + 0x480, 16, 32, 16
        )
        struct.pack_into(
            "<IIQQQQQQ",
            data,
            232,
            0x6474E552,
            4,
            0x400,
            base + 0x400,
            base + 0x400,
            0x100,
            0x100,
            1,
        )
        note = struct.pack("<III", 8, 4, 1) + b"Android\0" + struct.pack("<I", 30)
        data[0x500 : 0x500 + len(note)] = note
        struct.pack_into(
            "<IIQQQQQQ", data, 288, 4, 4, 0x500, base + 0x500, base + 0x500, len(note), len(note), 4
        )
    if sections:
        names = (
            b"\0.dynamic\0.dynstr\0.dynsym\0.text\0.init_array\0.note.android.ident\0.shstrtab\0"
        )
        data[0x560 : 0x560 + len(names)] = names

        def ni(name):
            return names.index(name.encode() + b"\0")

        headers = [
            bytes(64),
            struct.pack(
                "<IIQQQQIIQQ", ni(".dynamic"), 6, 2, base + 0x200, 0x200, len(dynamic), 2, 0, 8, 16
            ),
            struct.pack(
                "<IIQQQQIIQQ", ni(".dynstr"), 3, 2, base + 0x300, 0x300, len(strings), 0, 0, 1, 0
            ),
            struct.pack("<IIQQQQIIQQ", ni(".dynsym"), 11, 2, base + 0x380, 0x380, 96, 2, 1, 8, 24),
            struct.pack("<IIQQQQIIQQ", ni(".text"), 1, 6, base + 0x400, 0x400, 16, 0, 0, 4, 0),
            struct.pack(
                "<IIQQQQIIQQ", ni(".init_array"), 14, 2, base + 0x440, 0x440, 8, 0, 0, 8, 8
            ),
            struct.pack(
                "<IIQQQQIIQQ",
                ni(".note.android.ident"),
                7,
                2,
                base + 0x500,
                0x500,
                24 if features else 0,
                0,
                0,
                4,
                0,
            ),
            struct.pack("<IIQQQQIIQQ", ni(".shstrtab"), 3, 0, 0, 0x560, len(names), 0, 0, 1, 0),
        ]
        data[0x600:0x800] = b"".join(headers)
    return bytes(data)
