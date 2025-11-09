import struct

def write_header(filename, ENTRY_OFFSET, TARGET_FILESIZE):

    MH_MAGIC_64          = 0xfeedfacf
    CPU_TYPE_ARM64       = 0x0100000c
    CPU_SUBTYPE_ARM64_ALL= 0x00000000
    MH_EXECUTE           = 0x2

    LC_SEGMENT_64        = 0x19
    LC_LOAD_DYLINKER     = 0x0e
    LC_MAIN              = 0x80000028

    NCMDS      = 2
    SIZEOFCMDS = 0x48 + 0x18  # 0x80

    # mach_header_64
    hdr = struct.pack(
        "<IiiIIII",
        MH_MAGIC_64,
        CPU_TYPE_ARM64,
        CPU_SUBTYPE_ARM64_ALL,
        MH_EXECUTE,
        NCMDS,
        SIZEOFCMDS,
        0,
    ) + struct.pack("<I", 0)

    # LC_SEGMENT_64 __TEXT
    segname = b"__TEXT" + b"\x00" * (16 - len("__TEXT"))
    VMADDR   = 0x100000000
    VMSIZE   = 0x1000
    FILEOFF  = 0
    FILESIZE = TARGET_FILESIZE

    segment = struct.pack(
        "<II16sQQQQIIII",
        LC_SEGMENT_64,
        0x48,
        segname,
        VMADDR,
        VMSIZE,
        FILEOFF,
        FILESIZE,
        5,
        5,
        0,
        0,
    )

    # LC_LOAD_DYLINKER "/usr/lib/dyld"
    dyld_path = b"/usr/lib/dyld\x00"
    name_offset = 0x0c
    pad_len = 0x20 - (4 + 4 + 4 + len(dyld_path))
    dyld_cmd = struct.pack(
        "<III",
        LC_LOAD_DYLINKER,
        0x20,
        name_offset,
    ) + dyld_path + (b"\x00" * pad_len)

    # LC_MAIN
    lc_main = struct.pack(
        "<IIQQ",
        LC_MAIN,
        0x18,
        ENTRY_OFFSET,
        0,
    )

    with open(filename, "wb") as f:
        f.write(hdr)
        f.write(segment)
        f.write(lc_main)