from AST import AST, parser

T_INT32   = 'int32'
T_INT64   = 'int64'
T_FLOAT32 = 'float32'
T_FLOAT64 = 'float64'

class RegAlloc:
    """
    Manage separate pools:
      - GPR x0..x28 for ints (we derive wN/xN from the same index)
      - FP  d0..d31 (alias with sN) for floats
    """
    def __init__(self):
        self.int_used = set()
        self.fp_used  = set()
        self.var_reg  = {}   # name -> (type (x, d, s), reg_index)
        self.var_type = {}   # name -> type

    def alloc_int(self, name: str, ty: str) -> int:
        for i in range(29):  # x0..x28
            if i not in self.int_used:
                self.int_used.add(i)
                self.var_reg[name]  = (ty, i)
                self.var_type[name] = ty
                return i
        raise RuntimeError("Out of integer registers (x0..x28)")

    def alloc_fp(self, name: str, ty: str) -> int:
        for i in range(32):  # d0..d31 / s0..s31
            if i not in self.fp_used:
                self.fp_used.add(i)
                if(ty == "float32"):
                    self.var_reg[name]  = (ty, i)

                if(ty == "float64"):
                    self.var_reg[name]  = (ty, i)

                self.var_type[name] = ty
                return i
        raise RuntimeError("Out of floating-point registers (d0..d31)")

    def declare(self, name: str, ty: str):
        if name in self.var_reg:
            raise ValueError(f"Variable '{name}' already declared")
        if ty in (T_INT32, T_INT64):
            return self.alloc_int(name, ty)
        elif ty in (T_FLOAT32, T_FLOAT64):
            return self.alloc_fp(name, ty)
        else:
            raise ValueError(f"Unknown type '{ty}'")

    def ensure_declared(self, name: str):
        if name not in self.var_reg:
            raise ValueError(f"Use of undeclared variable '{name}'")

    def reg_name(self, name: str) -> str:
        """Return the proper architectural register name for a variable by type."""
        self.ensure_declared(name)
        ty, idx = self.var_reg[name]
        if ty == T_INT32: return f"w{idx}"
        if ty == T_INT64: return f"x{idx}"
        if ty == T_FLOAT32: return f"s{idx}"
        if ty == T_FLOAT64: return f"d{idx}"
        raise ValueError("invalid type")

    def ty(self, name: str) -> str:
        self.ensure_declared(name)
        return self.var_type[name]

def make_asm(ast, allocator):
    if(ast[0] == 'decl'):
        allocator.declare(ast[2][1], ast[1])
    elif(ast[0]=='sub'):
        x=1
    
    elif(ast[0] == 'var'):
        return alloc.reg_name(ast[1])
    
    elif(ast[0] == 'div'):
        x=1
    
    elif(ast[0] == 'num'):
        return str(ast[1])
    elif(ast[0] == 'add'):
        x=1
    elif(ast[0] == 'mul'):
        x=1
    elif(ast[0] == 'initpd'):
        source = alloc.reg_name(ast[1][1])
        val = make_asm(ast[2], alloc)
        return f"str {source}, {val}"
    
if __name__ == "__main__":
    alloc = RegAlloc()
    tree1 = parser.parse("int32 y")
    ast1 = AST().transform(tree1)
    make_asm(ast1, alloc)

    tree1 = parser.parse("int32 x")
    ast1 = AST().transform(tree1)
    make_asm(ast1, alloc)

    tree = parser.parse("y = x")
    ast = AST().transform(tree)
    print(ast)
    print(make_asm(ast, alloc))
