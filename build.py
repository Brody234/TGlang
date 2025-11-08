import os, re, subprocess

FILE_NAME = "beta"

# ---------- tokens & helpers ----------
IDENT_RE   = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
INT_RE     = re.compile(r'^-?\d+$')
FLOAT_LIT  = re.compile(r'^-?\d+\.\d+$')

# print(...) matchers
STR_CALL_RE   = re.compile(r'^\s*print\s*\(\s*"(.*)"\s*\)\s*;?\s*$')  # "string"
PRINT_VAL_RE  = re.compile(r'^\s*print\s*\(\s*([A-Za-z_][A-Za-z0-9_]*|-?\d+)\s*\)\s*;?\s*$')

# types
T_INT32, T_INT64, T_FLOAT32, T_FLOAT64 = 'i32', 'i64', 'f32', 'f64'
TYPE_KEYWORDS = {'int32':T_INT32, 'int64':T_INT64, 'float32':T_FLOAT32, 'float64':T_FLOAT64}

COMMENT_RE = re.compile(r'\s+(#|//).*?$')
def strip_comment(s: str) -> str:
    return COMMENT_RE.sub('', s).strip()

def is_ident(s): return IDENT_RE.fullmatch(s) is not None
def is_int(s):   return INT_RE.fullmatch(s) is not None
def is_float_lit(s): return FLOAT_LIT.fullmatch(s) is not None

# cond token helpers (identifier or integer literal)
def is_cond_ident(tok): return is_ident(tok)
def is_cond_int(tok):   return is_int(tok)

# ---------- register allocator with block scoping ----------
class RegAlloc:
    def __init__(self):
        self.int_used=set(); self.fp_used=set()
        self.var_info={}              # name -> (type, index)
        self.scope_stack=[[]]         # lists of names per scope

    def begin_scope(self):
        self.scope_stack.append([])

    def end_scope(self):
        if len(self.scope_stack)==1: return
        names=self.scope_stack.pop()
        for name in reversed(names):
            ty, idx = self.var_info.pop(name)
            if ty in (T_INT32, T_INT64): self.int_used.discard(idx)
            else: self.fp_used.discard(idx)

    
    def declare(self, name, ty):
        if name in self.var_info: raise ValueError(f"Variable '{name}' already declared")
        if ty in (T_INT32, T_INT64):
            for i in range(2, 29):   # reserve 0/1 for temps/ABI
                if i not in self.int_used:
                    self.int_used.add(i)
                    self.var_info[name] = (ty, i)
                    self.scope_stack[-1].append(name)
                    return
            raise RuntimeError("Out of integer registers")
        elif ty in (T_FLOAT32, T_FLOAT64):
            for i in range(32):
                if i not in self.fp_used:
                    self.fp_used.add(i)
                    self.var_info[name] = (ty, i)
                    self.scope_stack[-1].append(name)
                    return
            raise RuntimeError("Out of FP registers")
        else:
            raise ValueError("unknown type")


    def ensure(self, name):
        if name not in self.var_info: raise ValueError(f"Use of undeclared variable '{name}'")
    def ty(self, name):
        self.ensure(name); return self.var_info[name][0]
    def reg(self, name):
        self.ensure(name); ty, idx = self.var_info[name]
        if ty==T_INT32: return f"w{idx}"
        if ty==T_INT64: return f"x{idx}"
        if ty==T_FLOAT32: return f"s{idx}"
        if ty==T_FLOAT64: return f"d{idx}"
        raise ValueError("bad type")

# ---------- emitter ----------
class Emitter:
    def __init__(self):
        self.lines=[]
    def emit(self, s): self.lines.append(s)
    def extend(self, seq): self.lines.extend(seq)
    def text(self): return "\n".join(self.lines) + "\n"

# Prologue/Epilogue for _main
PROLOGUE = [
    ".text",
    ".globl _main",
    "_main:",
    "stp x29, x30, [sp, #-16]!",
    "mov x29, sp",
    "sub sp, sp, #256",
]
EPILOGUE = [
    "L_exit:",
    "add sp, sp, #256",
    "ldp x29, x30, [sp], #16",
    "ret",
]

# ---------- parser utilities ----------
BINOP_RE  = re.compile(r'^\s*(.+?)\s*([+\-*])\s*(.+?)\s*$')

# allow identifiers OR integer literals in conditions:
COND_TOKEN = r'([A-Za-z_][A-Za-z0-9_]*|-?\d+)'

IF_HEAD_RE   = re.compile(
    rf'^\s*if\s*\(\s*{COND_TOKEN}\s*(==|!=|>=|>|<=|<)\s*{COND_TOKEN}\s*\)\s*\{{\s*$'
)
ELSE_HEAD_RE = re.compile(r'^\s*else\s*\{\s*$')
CLOSE_BRACE_RE = re.compile(r'^\s*\}\s*$')
ELSE_AFTER_CLOSE_RE = re.compile(r'^\s*\}\s*else\s*\{\s*$')
FOR_HEAD_RE = re.compile(
    rf'^\s*for\s*\(\s*(.*?)\s*;\s*{COND_TOKEN}\s*(==|!=|>=|>|<=|<)\s*{COND_TOKEN}\s*;\s*(.*?)\s*\)\s*\{{\s*$'
)

def parse_binop(rhs_raw):
    m = BINOP_RE.fullmatch(rhs_raw)
    if not m: return None
    L, op, R = m.group(1).strip(), m.group(2), m.group(3).strip()
    return (op, L, R)

# ---------- statement compilers ----------
class Compiler:
    def __init__(self):
        self.regs = RegAlloc()
        self.out = Emitter()
        self.labels = set()
        self.label_refs = set()
        self.uniq = 0

        # cstring table (dedup)
        self._str_map = {}   # text -> label
        self._str_list = []  # (label, text)
        # builtin format strings for ints
        self.fmt_i32 = self.cstring("%d\n")
        self.fmt_i64 = self.cstring("%lld\n")


    def unique(self, base):
        self.uniq += 1
        return f"{base}_{self.uniq}"

    # ----- cstring helpers -----
    def cstring(self, text: str) -> str:
        if text in self._str_map:
            return self._str_map[text]
        label = f"L_str_{len(self._str_list)+1}"
        self._str_map[text] = label
        self._str_list.append((label, text))
        return label

    def emit_cstrings_section(self) -> str:
        if not self._str_list:
            return ""
        lines = []
        lines.append(".section __TEXT,__cstring,cstring_literals")
        for label, txt in self._str_list:
            # Escape for assembler source:
            #  - backslash -> \\
            #  - newline   -> \n
            #  - quote     -> \"
            esc = (
                txt.replace("\\", "\\\\")
                .replace("\n", "\\n")
                .replace('"', '\\"')
            )
            lines.append(f"{label}:")
            lines.append(f'  .asciz "{esc}"')
        return "\n".join(lines) + "\n"



    # ---- emit large immediates safely (ARM64) ----
    def _emit_mov_imm(self, reg: str, bits: int, value: int):
        mask = (1 << bits) - 1
        val = value & mask
        shifts = [s for s in (0,16,32,48) if s < bits]
        first = True
        wrote = False
        for s in shifts:
            part = (val >> s) & 0xFFFF
            if first:
                self.out.emit(f"movz {reg}, #{part}" + (f", lsl #{s}" if s else ""))
                first = False
                wrote = True
            else:
                if part != 0:
                    self.out.emit(f"movk {reg}, #{part}" + (f", lsl #{s}" if s else ""))
                    wrote = True
        if not wrote:
            self.out.emit(f"movz {reg}, #0")

    # ---- helpers used by decl/assign ----
    def _emit_int_binop(self, dst, ty, name, ln, op, L, R):
        def reg_of_var(v):
            self.regs.ensure(v)
            if self.regs.ty(v)!=ty: raise RuntimeError(f"[line {ln}] type mismatch in {name} = ...")
            return self.regs.reg(v)
        if is_ident(L) and is_ident(R):
            rL, rR = reg_of_var(L), reg_of_var(R)
            if op=="*": self.out.emit(f"mul {dst}, {rL}, {rR}")
            elif op=="+": self.out.emit(f"add {dst}, {rL}, {rR}")
            else: self.out.emit(f"sub {dst}, {rL}, {rR}")
            return True
        if is_ident(L) and is_int(R):
            rL = reg_of_var(L)
            if op=="*":
                tmp = "w0" if ty==T_INT32 else "x0"
                self._emit_mov_imm(tmp, 32 if ty==T_INT32 else 64, int(R))
                self.out.emit(f"mul {dst}, {rL}, {tmp}")
            elif op=="+":
                self.out.emit(f"add {dst}, {rL}, #{int(R)}")
            else:
                self.out.emit(f"sub {dst}, {rL}, #{int(R)}")
            return True
        if is_int(L) and is_ident(R):
            rR = reg_of_var(R)
            if op=="*":
                tmp = "w0" if ty==T_INT32 else "x0"
                self._emit_mov_imm(tmp, 32 if ty==T_INT32 else 64, int(L))
                self.out.emit(f"mul {dst}, {tmp}, {rR}")
            elif op=="+":
                self.out.emit(f"add {dst}, {rR}, #{int(L)}")
            else:
                self._emit_mov_imm(dst, 32 if ty==T_INT32 else 64, int(L))
                self.out.emit(f"sub {dst}, {dst}, {rR}")
            return True
        raise RuntimeError(f"[line {ln}] unsupported int binop operands '{L}' and '{R}'")

    def _emit_float_binop(self, dst, ty, ln, L, op, R):
        if not (is_ident(L) and is_ident(R)): raise RuntimeError(f"[line {ln}] float ops require variables")
        self.regs.ensure(L); self.regs.ensure(R)
        if self.regs.ty(L)!=ty or self.regs.ty(R)!=ty: raise RuntimeError(f"[line {ln}] type mismatch in float op")
        rL, rR = self.regs.reg(L), self.regs.reg(R)
        if op=="*": self.out.emit(f"fmul {dst}, {rL}, {rR}")
        elif op=="+": self.out.emit(f"fadd {dst}, {rL}, {rR}")
        else: self.out.emit(f"fsub {dst}, {rL}, {rR}")

    def _emit_int_cmp(self, a_tok, b_tok, ty):
        tmp  = "w0" if ty == T_INT32 else "x0"
        tmp2 = "w1" if ty == T_INT32 else "x1"
        if is_cond_ident(a_tok) and is_cond_ident(b_tok):
            rA = self.regs.reg(a_tok); rB = self.regs.reg(b_tok)
            self.out.emit(f"cmp {rA}, {rB}"); return
        if is_cond_ident(a_tok) and is_cond_int(b_tok):
            rA = self.regs.reg(a_tok)
            self.out.emit(f"cmp {rA}, #{int(b_tok)}"); return
        if is_cond_int(a_tok) and is_cond_ident(b_tok):
            rB = self.regs.reg(b_tok)
            self._emit_mov_imm(tmp, 32 if ty==T_INT32 else 64, int(a_tok))
            self.out.emit(f"cmp {tmp}, {rB}"); return
        self._emit_mov_imm(tmp,  32 if ty==T_INT32 else 64, int(a_tok))
        self._emit_mov_imm(tmp2, 32 if ty==T_INT32 else 64, int(b_tok))
        self.out.emit(f"cmp {tmp}, {tmp2}")

    # ---- builtin calls: print ----
    def compile_print_string(self, line, ln):
        m = STR_CALL_RE.fullmatch(line)
        if not m: return False
        text = m.group(1)
        lbl = self.cstring(text)
        self.out.emit(f"adrp x0, {lbl}@PAGE")
        self.out.emit(f"add  x0, x0, {lbl}@PAGEOFF")
        self.out.emit("bl _puts")
        return True

    def compile_print_value(self, line, ln):
        m = PRINT_VAL_RE.fullmatch(line)
        print(m)
        if not m: return False
        tok = m.group(1)

        if is_int(tok):
            print(0)
            fmt = self.fmt_i32
            self.out.emit(f"adrp x0, {fmt}@PAGE")
            self.out.emit(f"add  x0, x0, {fmt}@PAGEOFF")
            self._emit_mov_imm("x1", 64, int(tok))   # immediate -> x1
            self.out.emit("bl _printf")
            return True

        if is_ident(tok):
            print(1)
            self.regs.ensure(tok)
            ty = self.regs.ty(tok)

            if ty == T_INT32:
                fmt = self.fmt_i32
                self.out.emit(f"adrp x0, {fmt}@PAGE")
                self.out.emit(f"add  x0, x0, {fmt}@PAGEOFF")
                r = self.regs.reg(tok)           # e.g. w2
                if r.startswith("w"):
                    print(r)
                    # zero-extend 32->64 into x1 (use sxtw if you want negatives preserved)
                    self.out.emit(f"mov  w1, {r}") 
                else:
                    self.out.emit(f"mov x1, {r}")
                self.out.emit("bl _printf")
                return True

            if ty == T_INT64:
                print(2)
                fmt = self.fmt_i64
                self.out.emit(f"adrp x0, {fmt}@PAGE")
                self.out.emit(f"add  x0, x0, {fmt}@PAGEOFF")
                r = self.regs.reg(tok)           # e.g. x2
                if r.startswith("w"):
                    self.out.emit(f"uxtw x1, {r}")
                else:
                    self.out.emit(f"mov x1, {r}")
                self.out.emit("bl _printf")
                return True

            raise RuntimeError(f"[line {ln}] print() currently supports int32/int64 and string literals")

        return False



    # ---- simple statements ----
    def compile_store_call(self, line, ln):
        m = re.fullmatch(r'^store\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*\[\s*sp\s*\+\s*(-?\d+)\s*\]\s*\)\s*;?\s*$', line)
        if not m: return False
        v, off = m.group(1), int(m.group(2))
        self.regs.ensure(v)
        if not (0 <= off < 256): raise RuntimeError(f"[line {ln}] stack offset 0..255")
        self.out.emit(f"str {self.regs.reg(v)}, [sp, #{off}]")
        return True

    def compile_load_call(self, line, ln):
        m = re.fullmatch(r'^load\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,\s*\[\s*sp\s*\+\s*(-?\d+)\s*\]\s*\)\s*;?\s*$', line)
        if not m: return False
        v, off = m.group(1), int(m.group(2))
        self.regs.ensure(v)
        if not (0 <= off < 256): raise RuntimeError(f"[line {ln}] stack offset 0..255")
        self.out.emit(f"ldr {self.regs.reg(v)}, [sp, #{off}]")
        return True

    def compile_return(self, line, ln):
        m = re.fullmatch(r'^\s*return\s*(?:;|([A-Za-z_][A-Za-z0-9_]*|-?\d+)\s*;?)\s*$', line)
        if not m: return False
        tok = m.group(1)
        if tok is None:
            self.out.emit("mov w0, #0")
        else:
            if is_int(tok):
                self._emit_mov_imm("w0", 32, int(tok))
            elif is_ident(tok):
                self.regs.ensure(tok)
                t = self.regs.ty(tok)
                r = self.regs.reg(tok)
                if t==T_INT32: self.out.emit(f"mov w0, {r}")
                elif t==T_INT64: self.out.emit(f"mov w0, {r.replace('x','w',1)}")
                else: raise RuntimeError(f"[line {ln}] returning non-integer '{tok}' not supported")
            else:
                raise RuntimeError(f"[line {ln}] invalid return expression '{tok}'")
        self.out.emit("b L_exit"); self.label_refs.add("L_exit")
        return True

    def compile_label(self, line, ln):
        m = re.fullmatch(r'^\s*label\s+([A-Za-z_][A-Za-z0-9_]*)\:\s*$', line)
        if not m: return False
        name = m.group(1); self.labels.add(name); self.out.emit(f"{name}:"); return True

    def compile_goto(self, line, ln):
        m = re.fullmatch(r'^\s*goto\s+([A-Za-z_][A-Za-z0-9_]*)\s*;?\s*$', line)
        if not m: return False
        name = m.group(1); self.label_refs.add(name); self.out.emit(f"b {name}"); return True

    # ---- declarations with expressions ----
    def compile_decl(self, line, ln):
        m = re.fullmatch(r'^\s*(int32|int64|float32|float64)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;?\s*$', line)
        if not m: return False
        kw, name, rhs_raw = m.group(1), m.group(2), m.group(3)
        ty = TYPE_KEYWORDS[kw]
        self.regs.declare(name, ty)
        dst = self.regs.reg(name)

        b = parse_binop(rhs_raw)
        if b:
            op, L, R = b
            if ty in (T_INT32, T_INT64):
                self._emit_int_binop(dst, ty, name, ln, op, L, R); return True
            else:
                self._emit_float_binop(dst, ty, ln, L, op, R); return True

        tok = rhs_raw.strip()
        if ty==T_INT32:
            if is_int(tok): self._emit_mov_imm(dst, 32, int(tok)); return True
            if is_ident(tok):
                self.regs.ensure(tok)
                if self.regs.ty(tok)!=T_INT32: raise RuntimeError(f"[line {ln}] type mismatch in int32 init")
                self.out.emit(f"mov {dst}, {self.regs.reg(tok)}"); return True
            raise RuntimeError(f"[line {ln}] invalid int32 initializer '{tok}'")
        if ty==T_INT64:
            if is_int(tok): self._emit_mov_imm(dst, 64, int(tok)); return True
            if is_ident(tok):
                self.regs.ensure(tok)
                if self.regs.ty(tok)!=T_INT64: raise RuntimeError(f"[line {ln}] type mismatch in int64 init")
                self.out.emit(f"mov {dst}, {self.regs.reg(tok)}"); return True
            raise RuntimeError(f"[line {ln}] invalid int64 initializer '{tok}'")
        if ty==T_FLOAT32:
            if is_ident(tok):
                self.regs.ensure(tok)
                if self.regs.ty(tok)!=T_FLOAT32: raise RuntimeError(f"[line {ln}] type mismatch in float32 init")
                self.out.emit(f"fmov {dst}, {self.regs.reg(tok)}"); return True
            if is_int(tok):
                self._emit_mov_imm("w0", 32, int(tok)); self.out.emit(f"scvtf {dst}, w0"); return True
            raise RuntimeError(f"[line {ln}] float32 init needs var or int literal (no 3.14 yet)")
        if ty==T_FLOAT64:
            if is_ident(tok):
                self.regs.ensure(tok)
                if self.regs.ty(tok)!=T_FLOAT64: raise RuntimeError(f"[line {ln}] type mismatch in float64 init")
                self.out.emit(f"fmov {dst}, {self.regs.reg(tok)}"); return True
            if is_int(tok):
                self._emit_mov_imm("x0", 64, int(tok)); self.out.emit(f"scvtf {dst}, x0"); return True
            raise RuntimeError(f"[line {ln}] float64 init needs var or int literal (no 3.14 yet)")
        return True

    # ---- assignment ----
    def compile_assign(self, line, ln):
        m = re.fullmatch(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*;?\s*$', line)
        if not m: return False
        name, rhs_raw = m.group(1), m.group(2)
        self.regs.ensure(name)
        ty = self.regs.ty(name)
        dst = self.regs.reg(name)

        b = parse_binop(rhs_raw)
        if b:
            op, L, R = b
            if ty in (T_INT32, T_INT64):
                self._emit_int_binop(dst, ty, name, ln, op, L, R); return True
            else:
                self._emit_float_binop(dst, ty, ln, L, op, R); return True

        tok = rhs_raw.strip()
        if ty==T_INT32:
            if is_int(tok): self._emit_mov_imm(dst, 32, int(tok)); return True
            if is_ident(tok):
                self.regs.ensure(tok)
                if self.regs.ty(tok)!=T_INT32: raise RuntimeError(f"[line {ln}] type mismatch in int32 assign")
                self.out.emit(f"mov {dst}, {self.regs.reg(tok)}"); return True
            raise RuntimeError(f"[line {ln}] invalid int32 assignment '{tok}'")
        if ty==T_INT64:
            if is_int(tok): self._emit_mov_imm(dst, 64, int(tok)); return True
            if is_ident(tok):
                self.regs.ensure(tok)
                if self.regs.ty(tok)!=T_INT64: raise RuntimeError(f"[line {ln}] type mismatch in int64 assign")
                self.out.emit(f"mov {dst}, {self.regs.reg(tok)}"); return True
            raise RuntimeError(f"[line {ln}] invalid int64 assignment '{tok}'")
        if ty==T_FLOAT32:
            if is_ident(tok):
                self.regs.ensure(tok)
                if self.regs.ty(tok)!=T_FLOAT32: raise RuntimeError(f"[line {ln}] type mismatch in float32 assign")
                self.out.emit(f"fmov {dst}, {self.regs.reg(tok)}"); return True
            if is_int(tok):
                self._emit_mov_imm("w0", 32, int(tok)); self.out.emit(f"scvtf {dst}, w0"); return True
            raise RuntimeError(f"[line {ln}] float32 assign needs var or int literal")
        if ty==T_FLOAT64:
            if is_ident(tok):
                self.regs.ensure(tok)
                if self.regs.ty(tok)!=T_FLOAT64: raise RuntimeError(f"[line {ln}] type mismatch in float64 assign")
                self.out.emit(f"fmov {dst}, {self.regs.reg(tok)}"); return True
            if is_int(tok):
                self._emit_mov_imm("x0", 64, int(tok)); self.out.emit(f"scvtf {dst}, x0"); return True
            raise RuntimeError(f"[line {ln}] float64 assign needs var or int literal")
        return True

    # ---- if (...) { ... } [else { ... }] ----
    def compile_if_block(self, lines, i):
        ln = i+1
        m = IF_HEAD_RE.fullmatch(lines[i])
        if not m: return None
        a_tok, op, b_tok = m.group(1), m.group(2), m.group(3)

        L_else = self.unique("L_else")
        L_end  = self.unique("L_end")

        if is_cond_ident(a_tok) and is_cond_ident(b_tok):
            self.regs.ensure(a_tok); self.regs.ensure(b_tok)
            ta, tb = self.regs.ty(a_tok), self.regs.ty(b_tok)
            if ta != tb: raise RuntimeError(f"[line {ln}] type mismatch in if: {a_tok}:{ta} vs {b_tok}:{tb}")
            if ta in (T_INT32, T_INT64):
                self._emit_int_cmp(a_tok, b_tok, ta)
            else:
                rA, rB = self.regs.reg(a_tok), self.regs.reg(b_tok)
                self.out.emit(f"fcmp {rA}, {rB}")
        else:
            ty = T_INT32
            if is_cond_ident(a_tok):
                self.regs.ensure(a_tok); ty = self.regs.ty(a_tok)
            elif is_cond_ident(b_tok):
                self.regs.ensure(b_tok); ty = self.regs.ty(b_tok)
            if ty not in (T_INT32, T_INT64):
                raise RuntimeError(f"[line {ln}] only integer literals supported in comparisons for now")
            self._emit_int_cmp(a_tok, b_tok, ty)

        negate = {"==":"bne","!=":"beq",">":"ble",">=":"blt","<":"bge","<=":"bgt"}
        self.out.emit(f"{negate[op]} {L_else}"); self.label_refs.add(L_else)

        i += 1
        brace = 1
        self.regs.begin_scope()
        while i < len(lines):
            line = lines[i]
            if IF_HEAD_RE.fullmatch(line):
                i = self.compile_if_block(lines, i); continue
            if FOR_HEAD_RE.fullmatch(line):
                i = self.compile_for_block(lines, i); continue

            if ELSE_AFTER_CLOSE_RE.fullmatch(line) and brace == 1:
                self.regs.end_scope()
                self.out.emit(f"b {L_end}"); self.label_refs.add(L_end)
                self.out.emit(f"{L_else}:"); self.labels.add(L_else)
                i += 1
                brace2 = 1
                self.regs.begin_scope()
                while i < len(lines):
                    l2 = lines[i]
                    if IF_HEAD_RE.fullmatch(l2):
                        i = self.compile_if_block(lines, i); continue
                    if FOR_HEAD_RE.fullmatch(l2):
                        i = self.compile_for_block(lines, i); continue
                    if CLOSE_BRACE_RE.fullmatch(l2):
                        brace2 -= 1
                        if brace2 == 0:
                            self.regs.end_scope()
                            self.out.emit(f"{L_end}:"); self.labels.add(L_end)
                            return i+1
                        i += 1; continue
                    if ELSE_HEAD_RE.fullmatch(l2):
                        brace2 += 1; i += 1; continue
                    self.compile_statement(l2, i+1)
                    i += 1
                raise RuntimeError(f"Unclosed else block starting line {ln}")

            if ELSE_HEAD_RE.fullmatch(line) and brace == 1:
                self.regs.end_scope()
                self.out.emit(f"b {L_end}"); self.label_refs.add(L_end)
                self.out.emit(f"{L_else}:"); self.labels.add(L_else)
                i += 1
                brace2 = 1
                self.regs.begin_scope()
                while i < len(lines):
                    l2 = lines[i]
                    if IF_HEAD_RE.fullmatch(l2):
                        i = self.compile_if_block(lines, i); continue
                    if FOR_HEAD_RE.fullmatch(l2):
                        i = self.compile_for_block(lines, i); continue
                    if CLOSE_BRACE_RE.fullmatch(l2):
                        brace2 -= 1
                        if brace2 == 0:
                            self.regs.end_scope()
                            self.out.emit(f"{L_end}:"); self.labels.add(L_end)
                            return i+1
                        i += 1; continue
                    if ELSE_HEAD_RE.fullmatch(l2):
                        brace2 += 1; i += 1; continue
                    self.compile_statement(l2, i+1)
                    i += 1
                raise RuntimeError(f"Unclosed else block starting line {ln}")

            if CLOSE_BRACE_RE.fullmatch(line):
                brace -= 1
                if brace == 0:
                    self.regs.end_scope()
                    j = i + 1
                    while j < len(lines) and not lines[j]:
                        j += 1
                    if j < len(lines) and ELSE_HEAD_RE.fullmatch(lines[j]):
                        self.out.emit(f"b {L_end}"); self.label_refs.add(L_end)
                        self.out.emit(f"{L_else}:"); self.labels.add(L_else)
                        i = j + 1
                        brace2 = 1
                        self.regs.begin_scope()
                        while i < len(lines):
                            l2 = lines[i]
                            if IF_HEAD_RE.fullmatch(l2):
                                i = self.compile_if_block(lines, i); continue
                            if FOR_HEAD_RE.fullmatch(l2):
                                i = self.compile_for_block(lines, i); continue
                            if CLOSE_BRACE_RE.fullmatch(l2):
                                brace2 -= 1
                                if brace2 == 0:
                                    self.regs.end_scope()
                                    self.out.emit(f"{L_end}:"); self.labels.add(L_end)
                                    return i+1
                                i += 1; continue
                            if ELSE_HEAD_RE.fullmatch(l2):
                                brace2 += 1; i += 1; continue
                            self.compile_statement(l2, i+1)
                            i += 1
                        raise RuntimeError(f"Unclosed else block starting line {ln}")
                    self.out.emit(f"{L_else}:"); self.labels.add(L_else)
                    self.out.emit(f"{L_end}:");  self.labels.add(L_end)
                    return i+1
                i += 1; continue

            self.compile_statement(line, i+1)
            i += 1
        raise RuntimeError(f"Unclosed if block starting line {ln}")

    # ---- for (init; a op b; step) { ... } ----
    def compile_for_block(self, lines, i):
        ln = i+1
        m = FOR_HEAD_RE.fullmatch(lines[i])
        if not m: return None
        init_src, a_tok, op, b_tok, step_src = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)

        self.regs.begin_scope()

        if init_src.strip():
            if not (self.compile_decl(init_src, ln) or self.compile_assign(init_src, ln)):
                raise RuntimeError(f"[line {ln}] invalid for-init: '{init_src}'")

        ty = T_INT32
        if is_cond_ident(a_tok):
            self.regs.ensure(a_tok); ty = self.regs.ty(a_tok)
        elif is_cond_ident(b_tok):
            self.regs.ensure(b_tok); ty = self.regs.ty(b_tok)
        if ty not in (T_INT32, T_INT64):
            raise RuntimeError(f"[line {ln}] for-condition currently supports only integer compares")

        L_cond = self.unique("L_for_cond")
        L_body = self.unique("L_for_body")
        L_end  = self.unique("L_for_end")

        self.out.emit(f"{L_cond}:"); self.labels.add(L_cond)
        self._emit_int_cmp(a_tok, b_tok, ty)
        negate = {"==":"bne","!=":"beq",">":"ble",">=":"blt","<":"bge","<=":"bgt"}
        self.out.emit(f"{negate[op]} {L_end}"); self.label_refs.add(L_end)

        self.out.emit(f"{L_body}:"); self.labels.add(L_body)
        i += 1
        brace = 1
        while i < len(lines):
            line = lines[i]
            if IF_HEAD_RE.fullmatch(line):
                i = self.compile_if_block(lines, i); continue
            if FOR_HEAD_RE.fullmatch(line):
                i = self.compile_for_block(lines, i); continue
            if CLOSE_BRACE_RE.fullmatch(line):
                brace -= 1
                if brace == 0:
                    if step_src.strip():
                        if not (self.compile_assign(step_src, ln) or self.compile_decl(step_src, ln)):
                            raise RuntimeError(f"[line {ln}] invalid for-step: '{step_src}'")
                    self.out.emit(f"b {L_cond}"); self.label_refs.add(L_cond)
                    self.out.emit(f"{L_end}:"); self.labels.add(L_end)
                    self.regs.end_scope()
                    return i+1
                i += 1; continue
            self.compile_statement(line, i+1)
            i += 1
        raise RuntimeError(f"Unclosed for block starting line {ln}")

    def compile_statement(self, raw, ln):
        line = strip_comment(raw)
        if not line: return
        if self.compile_print_string(line, ln): return
        if self.compile_print_value(line, ln): return
        if self.compile_label(line, ln): return
        if self.compile_goto(line, ln): return
        if self.compile_return(line, ln): return
        if self.compile_store_call(line, ln): return
        if self.compile_load_call(line, ln): return
        if self.compile_decl(line, ln): return
        if self.compile_assign(line, ln): return
        raise RuntimeError(f"[line {ln}] Unrecognized statement: '{line}'")

# ---------- driver ----------
def compile_tg_to_asm(tg_path, asm_path):
    comp = Compiler()

    # read & normalize lines
    with open(tg_path,"r") as f:
        src_lines = [strip_comment(l.rstrip()) for l in f.readlines()]

    # body compilation
    comp.out.extend(PROLOGUE)

    i = 0
    n = len(src_lines)
    while i < n:
        line = src_lines[i]
        if not line: i += 1; continue
        if IF_HEAD_RE.fullmatch(line):
            i = comp.compile_if_block(src_lines, i); continue
        if FOR_HEAD_RE.fullmatch(line):
            i = comp.compile_for_block(src_lines, i); continue
        if CLOSE_BRACE_RE.fullmatch(line) or ELSE_HEAD_RE.fullmatch(line) or ELSE_AFTER_CLOSE_RE.fullmatch(line):
            raise RuntimeError(f"[line {i+1}] stray '}}' or 'else' without matching block opener")
        comp.compile_statement(line, i+1)
        i += 1

    comp.labels.add("L_exit")
    comp.out.emit("mov w0, #0")
    comp.out.emit("b L_exit")
    comp.out.extend(EPILOGUE)


    # stitch final assembly: cstrings then text
    asm_full = comp.emit_cstrings_section() + comp.out.text()

    with open(asm_path,"w") as f:
        f.write(asm_full)

def main():
    tg, asm = "beta.tg", "beta.s"
    if not os.path.exists(tg): raise SystemExit("Missing beta.tg")
    compile_tg_to_asm(tg, asm)
    subprocess.run(["clang","-arch","arm64","-g","-Wl,-no_pie",asm,"-o",FILE_NAME], check=True)

    os.chmod(FILE_NAME, os.stat(FILE_NAME).st_mode | 0o100)
    print(f"Built {FILE_NAME} from {tg} via {asm}")

if __name__ == "__main__":
    main()
