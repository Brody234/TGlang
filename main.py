import os
import stat
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN

class MemoryBlock:
    start: int
    length: int

    def __init__(self, start, length):
        self.start = start
        self.length = length

class StackVar:
    start: int
    length: int
    scope: int
    var_name: str

    def __init__(self, start, length):
        self.start = start
        self.length = length

FILE_NAME = "beta"
int_registers = [None for _ in range(31)]
float_registers = [None for _ in range(32)]

stack_free_blocks = [MemoryBlock(0, None)]
stack_list = []

def process(line: str):
    x=0
    with open("beta", "w") as f:
        f.write("")
    

with open("beta.tg") as f:
    for line in f.readlines():
        process(line)

st = os.stat("beta")
os.chmod("beta", st.st_mode | stat.S_IXUSR)
