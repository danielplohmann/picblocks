class FakeInstruction:
    def __init__(self, hex_bytes, escaped=None):
        self.bytes = hex_bytes
        self.escaped = escaped if escaped is not None else hex_bytes
        self.escapers = []

    def getEscapedBinary(self, escaper, escape_intraprocedural_jumps=False, lower_addr=None, upper_addr=None):
        self.escapers.append(escaper)
        return self.escaped


class FakeBlock:
    def __init__(self, instructions, offset=0):
        self.instructions = instructions
        self.length = len(instructions)
        self.offset = offset
        self.smda_function = None

    def getInstructions(self):
        return self.instructions


class FakeFunction:
    def __init__(self, blocks, offset=0, architecture="intel", escaper=None, report=None):
        self.blocks = blocks
        self.offset = offset
        self._escaper = escaper
        self.smda_report = report
        self.architecture = architecture
        for block in blocks:
            block.smda_function = self

    def getBlocks(self):
        return self.blocks

    @staticmethod
    def getInstructionEscaper(architecture):
        from smda.common.SmdaFunction import SmdaFunction

        return SmdaFunction.getInstructionEscaper(architecture)


class FakeReport:
    def __init__(self, functions=None, **kwargs):
        self.functions = functions or []
        self.family = kwargs.get("family", "win.test")
        self.version = kwargs.get("version", "1.0")
        self.bitness = kwargs.get("bitness", 32)
        self.sha256 = kwargs.get("sha256", "ab" * 32)
        self.filename = kwargs.get("filename", "test.exe")
        self.binary_size = kwargs.get("binary_size", 4096)
        self.is_library = kwargs.get("is_library", False)
        self.base_addr = kwargs.get("base_addr", 0x400000)
        self.status = kwargs.get("status", "ok")
        self.architecture = kwargs.get("architecture", "intel")
        self.message = kwargs.get("message", "ok")
        if "xcfg" in kwargs:
            self.xcfg = kwargs["xcfg"]
        else:
            self.xcfg = {index: function for index, function in enumerate(self.functions)}
        for function in self.functions:
            function.smda_report = self

    def getFunctions(self):
        if self.xcfg is None:
            return self.xcfg.items()
        return self.functions

    def getInstructionEscaper(self):
        from smda.common.SmdaFunction import SmdaFunction

        return SmdaFunction.getInstructionEscaper(self.architecture)


def make_function(num_blocks, instructions_per_block=4, hex_bytes="90", offset=0, escaped=None):
    blocks = []
    cursor = offset
    for _ in range(num_blocks):
        instructions = [FakeInstruction(hex_bytes, escaped=escaped) for _ in range(instructions_per_block)]
        blocks.append(FakeBlock(instructions, offset=cursor))
        cursor += instructions_per_block
    return FakeFunction(blocks, offset=offset)


class RecordingDisassembler:
    def __init__(self, report_factory):
        self.report_factory = report_factory
        self.calls = []

    def disassembleFile(self, filepath):
        self.calls.append(("file", filepath))
        return self.report_factory()

    def disassembleBuffer(self, buffer, base_addr, bitness):
        self.calls.append(("buffer", base_addr, bitness))
        return self.report_factory()

    def disassembleUnmappedBuffer(self, buffer):
        self.calls.append(("unmapped",))
        return self.report_factory()
