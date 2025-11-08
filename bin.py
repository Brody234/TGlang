ENTRY_OFFSET = 0x80
TARGET_FILESIZE = 0x200

def assemble_asm_to_bytes(asm_path: str) -> bytes:
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    with open(asm_path, "r") as f:
        lines = []
        for line in f:
            line = line.split(";")[0].split("#")[0].strip()
            if not line:
                continue
            lines.append(line)

    if not lines:
        raise ValueError("Assembly file is empty after stripping comments.")

    asm_source = "\n".join(lines)
    print(asm_source)
    encoding, count = ks.asm("""
mov x0, #0
mov w8, #93
svc #0
""")
    if count == 0:
        raise ValueError("Keystone did not assemble any instructions.")

    return bytes(encoding)


def process(line: str):
    x=0
    with open(FILE_NAME+".asm", "w") as f:
        f.write("""mov x0, #0
mov w8, #93
svc #0""")
    

with open(FILE_NAME, "r+b") as f:
    f.seek(ENTRY_OFFSET)
    f.write(code)

    # 4) Ensure file size is consistent with segment.filesize
    if TARGET_FILESIZE is not None:
        end_pos = ENTRY_OFFSET + len(code)
        if end_pos > TARGET_FILESIZE:
            raise ValueError(
                f"Code ({len(code)} bytes) does not fit in declared "
                f"filesize (0x{TARGET_FILESIZE:x}) starting at 0x{ENTRY_OFFSET:x}."
            )

        # Pad with zeros up to TARGET_FILESIZE so LC_SEGMENT_64.filesize is honest
        f.truncate(TARGET_FILESIZE)

st = os.stat(FILE_NAME)
os.chmod(FILE_NAME, st.st_mode | stat.S_IXUSR)
