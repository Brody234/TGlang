class MemoryBlock:
    start: int
    length: int

    def __init__(self, start, length):
        self.start = start
        self.length = length

int_registers = [None for _ in range(31)]
float_registers = [None for _ in range(32)]

stack_free_blocks = [MemoryBlock(0, None)]
stack_list = []

