# build.py
import os
import re
import stat
import subprocess

FILE_NAME = "beta"

# ----- Token patterns -----
REG_FULL   = re.compile(r'^r([0-2]?\d|30)$')
IDENT_FULL = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
IMM_FULL   = re.compile(r'^-?\d+$')

# Inner (non-capturing) for embedding
REG_INNER     = r'r(?:[0-2]?\d|30)'
IDENT_INNER   = r'[A-Za-z_][A-Za-z0-9_]*'
IMM_INNER     = r'-?\d+'
REG_OR_IDENT  = rf'(?:{REG_INNER}|{IDENT_INNER})'

# Inline comment stripper: requires whitespace before comment opener
COMMENT_RE = re.compile(r'\s+(#|//).*?$')
def strip_trailing_comment(line: str) -> str:
    return COMMENT_RE.sub("", line).strip()

# ----- Registers & variables -----
def is_reg(tok: str) -> bool:
    return REG_FULL.fullmatch(tok) is not None

def reg_to_x(tok: str) -> str:
    m = REG_FULL.fullmatch(tok)
    if not m:
        raise ValueError(f"Invalid register '{tok}'")
    n = int(m.group(1))
    if not (0 <= n <= 30):
        raise ValueError("Register out of range (0..30)")
    return f"x{n}"

AVAILABLE_GPRS = [f"x{i}" for i in range(29)]  # x0..x28 free; x29 FP, x30 LR reserved

class VarAllocator:
    def __init__(self):
        self.var2reg = {}
        self.used = set()
    def alloc(self, name: str) -> str:
        if name in self.var2reg:
            return self.var2reg[name]
        for r in AVAILABLE_GPRS:#make it floats in w registers and adjust for 32 bit and 64 bit(check it)
            if r not in self.used and r not in ("x29", "x30"):
                self.used.add(r)
                self.var2reg[name] = r
                return r
        raise RuntimeError("Too many variables: out of general-purpose registers")
    def get(self, name: str) -> str:
        return self.alloc(name)

def resolve_any(tok: str, vars: VarAllocator) -> str:
    if is_reg(tok):
        return reg_to_x(tok)
    if not IDENT_FULL.fullmatch(tok):
        raise ValueError(f"Invalid identifier or register '{tok}'")
    return vars.get(tok)

# ----- Condition map -----
COND_MAP = {"eq":"beq","ne":"bne","gt":"bgt","ge":"bge","lt":"blt","le":"ble"}

# ----- Prologue/Epilogue -----
PROLOGUE = [
    ".text",
    ".globl _main",
    "_main:",
    "stp x29, x30, [sp, #-16]!",
    "mov x29, sp",
    "sub sp, sp, #256",
]
EPILOGUE = [
    "add sp, sp, #256",
    "ldp x29, x30, [sp], #16",
    "mov w0, #0",
    "ret",
]

# ----- Emitter -----
class Emitter:
    def __init__(self):
        self.lines = []
    def emit(self, s: str):
        self.lines.append(s)
    def extend(self, seq):
        self.lines.extend(seq)
    def text(self) -> str:
        return "\n".join(self.lines) + "\n"

# ----- RHS parser -----
def parse_rhs(rhs_raw: str):
    rhs = rhs_raw.replace(" ", "")
    if "*" in rhs:
        parts = rhs.split("*")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError(f"Malformed multiplication RHS: {rhs_raw!r}")
        return ("mul", parts[0], parts[1])

    op_pos = None
    op_char = None
    for i, ch in enumerate(rhs):
        if ch in "+-":
            if i == 0:
                continue
            if op_pos is not None:
                raise ValueError(f"Only single + or - supported: {rhs_raw!r}")
            op_pos, op_char = i, ch
    if op_pos is not None:
        left = rhs[:op_pos]; right = rhs[op_pos+1:]
        if not left or not right:
            raise ValueError(f"Incomplete expression around '{op_char}': {rhs_raw!r}")
        if IMM_FULL.fullmatch(right):
            return ("add_imm" if op_char == "+" else "sub_imm", left, int(right))
        else:
            return ("add_reg" if op_char == "+" else "sub_reg", left, right)

    if IMM_FULL.fullmatch(rhs):
        return ("mov_imm", int(rhs))
    if IDENT_FULL.fullmatch(rhs) or REG_FULL.fullmatch(rhs):
        return ("mov_reg", rhs)
    raise ValueError(f"Unrecognized RHS: {rhs_raw!r}")

# ----- Parser context -----
class ParseCtx:
    def __init__(self):
        self.labels = set()
        self.refs = set()
        self.defined_vars = set()  # identifiers defined so far

    def ensure_defined_use(self, tok: str):
        if is_reg(tok):
            return
        if not IDENT_FULL.fullmatch(tok):
            raise ValueError(f"Invalid identifier or register '{tok}'")
        if tok not in self.defined_vars:
            raise ValueError(f"Use of undefined variable '{tok}'")

    def mark_defined(self, tok: str):
        if is_reg(tok):
            return
        if not IDENT_FULL.fullmatch(tok):
            raise ValueError(f"Invalid identifier '{tok}'")
        self.defined_vars.add(tok)

# ----- Line parser -----
# New call-style forms:
CALL_STORE_RE = re.compile(
    rf'^store\(\s*(?P<src>{REG_OR_IDENT})\s*,\s*\[\s*sp\s*\+\s*(?P<off>{IMM_INNER})\s*\]\s*\)$'
)
CALL_LOAD_RE = re.compile(
    rf'^load\(\s*(?P<dst>{REG_OR_IDENT})\s*,\s*\[\s*sp\s*\+\s*(?P<off>{IMM_INNER})\s*\]\s*\)$'
)
CALL_IF_RE = re.compile(
    rf'^if(?P<cond>eq|ne|gt|ge|lt|le)\(\s*(?P<a>{REG_OR_IDENT})\s*,\s*(?P<b>{REG_OR_IDENT})\s*,\s*(?P<lbl>{IDENT_INNER})\s*\)$'
)

def parse_line(raw_line: str, out: Emitter, vars: VarAllocator, ctx: ParseCtx):
    trimmed = raw_line.strip()
    if not trimmed or trimmed.startswith("#") or trimmed.startswith("//"):
        return
    line = strip_trailing_comment(trimmed)
    if not line:
        return

    # label NAME:
    m = re.fullmatch(rf"label\s+(?P<name>{IDENT_INNER}):", line)#TODO;delete
    if m:
        name = m.group('name')
        ctx.labels.add(name)
        out.emit(f"{name}:")
        return

    # goto NAME
    m = re.fullmatch(rf"goto\s+(?P<name>{IDENT_INNER})", line)
    if m:
        name = m.group('name')
        ctx.refs.add(name)
        out.emit(f"b {name}")
        return

    # --- New call-style FIRST ---

    # store(src, [sp+off])
    m = CALL_STORE_RE.fullmatch(line)
    if m:
        src_tok = m.group('src')
        off = int(m.group('off'))
        ctx.ensure_defined_use(src_tok)
        rs = resolve_any(src_tok, vars)
        if off < 0 or off >= 256:
            raise ValueError("stack offset must be 0..255")
        out.emit(f"str {rs}, [sp, #{off}]")
        return

    # load(dst, [sp+off])
    m = CALL_LOAD_RE.fullmatch(line)
    if m:
        dst_tok = m.group('dst')
        off = int(m.group('off'))
        ctx.mark_defined(dst_tok)              # load defines destination
        rd = resolve_any(dst_tok, vars)
        if off < 0 or off >= 256:
            raise ValueError("stack offset must be 0..255")
        out.emit(f"ldr {rd}, [sp, #{off}]")
        return

    # ifxx(a, b, label)
    m = CALL_IF_RE.fullmatch(line)
    if m:
        cond = m.group('cond')
        a_tok = m.group('a'); b_tok = m.group('b'); lbl = m.group('lbl')
        ctx.refs.add(lbl)
        ctx.ensure_defined_use(a_tok)
        ctx.ensure_defined_use(b_tok)
        a = resolve_any(a_tok, vars); b = resolve_any(b_tok, vars)
        out.emit(f"cmp {a}, {b}")
        out.emit(f"{COND_MAP[cond]} {lbl}")
        return

    # --- Legacy forms (still supported) ---

    # conditionals: if{cond} A, B, label
    for cond, bmn in COND_MAP.items():
        m = re.fullmatch(
            rf"if{cond}\s+(?P<a>{REG_OR_IDENT})\s*,\s*(?P<b>{REG_OR_IDENT})\s*,\s*(?P<lbl>{IDENT_INNER})",
            line
        )
        if m:
            a_tok = m.group('a'); b_tok = m.group('b'); lbl = m.group('lbl')
            ctx.refs.add(lbl)
            ctx.ensure_defined_use(a_tok)
            ctx.ensure_defined_use(b_tok)
            a = resolve_any(a_tok, vars); b = resolve_any(b_tok, vars)
            out.emit(f"cmp {a}, {b}")
            out.emit(f"{COND_MAP[cond]} {lbl}")
            return

    # store SRC, [sp+OFF]
    m = re.fullmatch(rf"store\s+(?P<src>{REG_OR_IDENT})\s*,\s*\[\s*sp\s*\+\s*(?P<off>{IMM_INNER})\s*\]", line)
    if m:
        src_tok = m.group('src'); off = int(m.group('off'))
        ctx.ensure_defined_use(src_tok)
        rs = resolve_any(src_tok, vars)
        if off < 0 or off >= 256:
            raise ValueError("stack offset must be 0..255")
        out.emit(f"str {rs}, [sp, #{off}]")
        return

    # load DST, [sp+OFF]
    m = re.fullmatch(rf"load\s+(?P<dst>{REG_OR_IDENT})\s*,\s*\[\s*sp\s*\+\s*(?P<off>{IMM_INNER})\s*\]", line)
    if m:
        dst_tok = m.group('dst'); off = int(m.group('off'))
        ctx.mark_defined(dst_tok)
        rd = resolve_any(dst_tok, vars)
        if off < 0 or off >= 256:
            raise ValueError("stack offset must be 0..255")
        out.emit(f"ldr {rd}, [sp, #{off}]")
        return

    # let DST = RHS
    if line.startswith("let "):
        body = line[4:]
        if "=" not in body:
            raise ValueError("Missing '=' in assignment")
        lhs, rhs_raw = body.split("=", 1)
        lhs = lhs.strip(); rhs_raw = rhs_raw.strip()
        if not lhs: raise ValueError("Missing left-hand side in assignment")
        if not rhs_raw: raise ValueError("Missing right-hand side in assignment")

        # Validate uses in RHS first
        kind = parse_rhs(rhs_raw)
        if kind[0] in ("mul", "add_reg", "sub_reg"):
            # both operands are uses
            a, b = kind[1], kind[2]
            if not IMM_FULL.fullmatch(a): ctx.ensure_defined_use(a)
            if not IMM_FULL.fullmatch(b): ctx.ensure_defined_use(b)
        elif kind[0] in ("add_imm", "sub_imm"):
            ctx.ensure_defined_use(kind[1])
        elif kind[0] == "mov_reg":
            ctx.ensure_defined_use(kind[1])
        # mov_imm has no variable uses

        # Define LHS now
        ctx.mark_defined(lhs)
        rd = resolve_any(lhs, vars)

        # Emit
        if kind[0] == "mul":
            ra = resolve_any(kind[1], vars); rb = resolve_any(kind[2], vars)
            out.emit(f"mul {rd}, {ra}, {rb}"); return
        if kind[0] == "add_reg":
            ra = resolve_any(kind[1], vars); rb = resolve_any(kind[2], vars)
            out.emit(f"add {rd}, {ra}, {rb}"); return
        if kind[0] == "sub_reg":
            ra = resolve_any(kind[1], vars); rb = resolve_any(kind[2], vars)
            out.emit(f"sub {rd}, {ra}, {rb}"); return
        if kind[0] == "add_imm":
            ra = resolve_any(kind[1], vars)
            out.emit(f"add {rd}, {ra}, #{kind[2]}"); return
        if kind[0] == "sub_imm":
            ra = resolve_any(kind[1], vars)
            out.emit(f"sub {rd}, {ra}, #{kind[2]}"); return
        if kind[0] == "mov_reg":
            rs = resolve_any(kind[1], vars)
            out.emit(f"mov {rd}, {rs}"); return
        if kind[0] == "mov_imm":
            out.emit(f"mov {rd}, #{kind[1]}"); return

        raise AssertionError("unreachable")

    raise ValueError(f"Unrecognized line syntax: '{line}'")

# ----- Compile .tg -> .s -----
def compile_tg_to_asm(tg_path: str, asm_path: str):
    vars = VarAllocator()#TODO:should be changed a bit 
    ctx = ParseCtx()
    out = Emitter()
    out.extend(PROLOGUE)
    with open(tg_path, "r") as f:
        for i, raw_line in enumerate(f, 1):
            try:
                parse_line(raw_line, out, vars, ctx)
            except Exception as e:
                raise RuntimeError(f"[{tg_path}:{i}] {e} | line={raw_line.rstrip()!r}")
    # Validate forward label refs
    missing = ctx.refs - ctx.labels
    if missing:
        raise RuntimeError(f"Undefined label(s): {', '.join(sorted(missing))}")
    out.extend(EPILOGUE)
    with open(asm_path, "w") as f:
        f.write(out.text())

# ----- Main -----
def main():
    tg = "beta.tg"
    asm = "beta.s"
    if not os.path.exists(tg):
        raise SystemExit(f"Missing {tg}. Create one first.")
    compile_tg_to_asm(tg, asm)
    try:
        subprocess.run(["clang", "-arch", "arm64", asm, "-o", FILE_NAME], check=True)
    except subprocess.CalledProcessError as e:
        raise SystemExit(f"clang failed: {e}")
    st = os.stat(FILE_NAME)
    os.chmod(FILE_NAME, st.st_mode | stat.S_IXUSR)
    print(f"Built {FILE_NAME} from {tg} via {asm}")

if __name__ == "__main__":
    main()
