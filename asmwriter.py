def write_asm(asm, asm_path, is_func=False, funcname=""):
    if(not is_func):
        with open(asm_path, "w") as f:
            for line in asm:
                f.write(line+"\n")

    else:
        with open(asm_path, "w") as f:
            f.write(f".global _{funcname}\n\n_{funcname}:\n\n")
            for line in asm:
                f.write(line+"\n")

    

if __name__ == "__main__":
    write_asm(["mov x9, x8", "mov x7, x0", "ret"], "joebiden.asm", True, "joe")
