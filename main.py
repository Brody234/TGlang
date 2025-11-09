import os
import stat
from keystone import Ks, KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
from lark import Lark, Transformer


from fortnite import write_header

FILE_NAME = "beta"

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

class TreeNode:
    left: TreeNode
    right: TreeNode
    action: str


int_registers = [None for _ in range(31)]
float_registers = [None for _ in range(32)]

stack_free_blocks = [MemoryBlock(0, None)]
stack_list = []

            

def process(line):
    vals = line.split(" ")

    parse(vals)


    with open(FILE_NAME+".asm", "w") as f:
        f.write()


with open("beta.tg") as f:
    for line in f.readlines():
        process(line)
