import hashlib
import json
import logging
import os
import re
import struct
import sys

from smda.common.SmdaReport import SmdaFunction
from smda.Disassembler import Disassembler
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

# Only do basicConfig if no handlers have been configured
if not logging.root.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOG = logging.getLogger(__name__)

# Memory dumps named like Malpedia's dump/dump7_0x<base> files, never a path
# segment such as /data/dumps/malware.exe.
_DUMP_FILENAME_RE = re.compile(r"(?:^|[^A-Za-z0-9])dump(?:7)?_0x[0-9a-fA-F]{4,16}", re.I)
_HEX_BASE_RE = re.compile(r"0x(?P<base_addr>[0-9a-fA-F]{1,16})", re.I)
_ARCH_RE = re.compile(r"(?P<bitness>(x86_64|x86-64|x86_32|x86|x64|x32|amd64|i386|i686|win32|win64|32bit|64bit))", re.I)


class BlockHasher:
    def parseBitnessFromFilename(self, filepath):
        # try to infer bitness from filename, in case we process a mapped image / memory dump
        name = os.path.basename(filepath)
        baddr_match = _HEX_BASE_RE.search(name)
        if baddr_match:
            parsed_bitness = 32 if len(baddr_match.group("base_addr")) <= 8 else 64
            LOG.info("Parsed bitness from file name: %d", parsed_bitness)
            return parsed_bitness
        architecture_match = _ARCH_RE.search(name)
        if architecture_match:
            tag = architecture_match.group("bitness").lower()
            parsed_bitness = 64 if any(k in tag for k in ("64", "amd64")) else 32
            LOG.info("Parsed bitness from file name: %d", parsed_bitness)
            return parsed_bitness
        LOG.warning("No bitness recognized from file name.")
        return None

    def parseBaseAddrFromFilename(self, filepath):
        # try to infer base addr from filename, in case we process a mapped image / memory dump
        name = os.path.basename(filepath)
        baddr_match = _HEX_BASE_RE.search(name)
        if baddr_match:
            parsed_base_addr = int(baddr_match.group("base_addr"), 16)
            LOG.info("Parsed base address from file name: 0x%08x %d", parsed_base_addr, parsed_base_addr)
            return parsed_base_addr
        LOG.warning("No base address recognized, using 0.")
        return 0

    def readFileContent(self, file_path):
        file_content = b""
        with open(file_path, "rb") as fin:
            file_content = fin.read()
        return file_content

    def _isMappedDumpFilename(self, filename):
        name = os.path.basename(filename)
        return bool(_DUMP_FILENAME_RE.search(name))

    def _isUsableSmdaReport(self, smda_report):
        if smda_report is None:
            return False
        if getattr(smda_report, "status", None) == "error":
            return False
        if getattr(smda_report, "xcfg", None) is None:
            return False
        return True

    def _logSmdaReport(self, smda_report, source):
        if self._isUsableSmdaReport(smda_report):
            LOG.info(smda_report)
            return
        LOG.warning(
            "SMDA analysis failed for %s: %s",
            source,
            getattr(smda_report, "message", "error"),
        )

    def _getInstructionEscaper(self, block):
        """Prefer the architecture-specific SMDA escaper; fall back to Intel on older SMDA."""
        smda_function = getattr(block, "smda_function", None)
        if smda_function is not None:
            escaper = getattr(smda_function, "_escaper", None)
            if escaper is not None:
                return escaper
            report = getattr(smda_function, "smda_report", None)
            if report is not None:
                getter = getattr(report, "getInstructionEscaper", None)
                if callable(getter):
                    resolved = getter()
                    if resolved is not None:
                        return resolved
            getter = getattr(type(smda_function), "getInstructionEscaper", None)
            if callable(getter):
                architecture = getattr(smda_function, "architecture", None)
                if architecture is None and report is not None:
                    architecture = getattr(report, "architecture", None)
                try:
                    resolved = getter(architecture)
                except TypeError:
                    resolved = getter()
                if resolved is not None:
                    return resolved
        return IntelInstructionEscaper

    def processBuffer(self, buffer, filename, bitness=None, baseaddress=None):
        LOG.info(f"now analyzing {filename}")
        DISASSEMBLER = Disassembler()
        name = os.path.basename(filename)
        # baseaddress=0 is a valid mapped base and must not be treated as "unset"
        if self._isMappedDumpFilename(name) or "_0x" in name or baseaddress is not None:
            BASE_ADDR = baseaddress if baseaddress is not None else self.parseBaseAddrFromFilename(filename)
            BITNESS = bitness if bitness is not None else self.parseBitnessFromFilename(filename)
            SMDA_REPORT = DISASSEMBLER.disassembleBuffer(buffer, BASE_ADDR, BITNESS)
        else:
            SMDA_REPORT = DISASSEMBLER.disassembleUnmappedBuffer(buffer)
        SMDA_REPORT.filename = os.path.basename(filename)
        self._logSmdaReport(SMDA_REPORT, filename)
        blockhash_report = self.extractBlockhashes(SMDA_REPORT)
        LOG.info("hashes extracted.")
        return blockhash_report

    def processFile(self, filepath):
        LOG.info(f"now analyzing {filepath}")
        INPUT_FILENAME = os.path.basename(filepath)
        DISASSEMBLER = Disassembler()
        if self._isMappedDumpFilename(filepath):
            BUFFER = self.readFileContent(filepath)
            BASE_ADDR = self.parseBaseAddrFromFilename(INPUT_FILENAME)
            BITNESS = self.parseBitnessFromFilename(INPUT_FILENAME)
            SMDA_REPORT = DISASSEMBLER.disassembleBuffer(BUFFER, BASE_ADDR, BITNESS)
        else:
            SMDA_REPORT = DISASSEMBLER.disassembleFile(filepath)
        SMDA_REPORT.filename = os.path.basename(INPUT_FILENAME)
        self._logSmdaReport(SMDA_REPORT, filepath)
        blockhash_report = self.extractBlockhashes(SMDA_REPORT)
        LOG.info("hashes extracted.")
        return blockhash_report

    def processSmda(self, smda_report):
        blockhash_report = self.extractBlockhashes(smda_report)
        return blockhash_report

    def calculateBlockhash(self, block, lower_addr, upper_addr, hash_size=4):
        escaper = self._getInstructionEscaper(block)
        escaped_binary_seq = []
        for instruction in block.getInstructions():
            escaped = instruction.getEscapedBinary(
                escaper,
                escape_intraprocedural_jumps=True,
                lower_addr=lower_addr,
                upper_addr=upper_addr,
            )
            if escaped:
                escaped_binary_seq.append(escaped)
        as_bytes = "".join(escaped_binary_seq).encode("ascii")
        digest = hashlib.sha256(as_bytes).digest()
        if hash_size == 8:
            return struct.unpack("<Q", digest[:8])[0]
        return struct.unpack("<I", digest[:4])[0]

    def getBlockhashesForFunction(
        self, smda_function: "SmdaFunction", image_lower: int, image_upper: int, min_block_size=4, hash_size=4
    ):
        blockhashes: dict = {}
        for block in smda_function.getBlocks():
            block_len = getattr(block, "length", 0) or 0
            if block_len >= min_block_size:
                block_size = sum(len(ins.bytes) // 2 for ins in block.getInstructions() if ins.bytes)
                block_hash = self.calculateBlockhash(
                    block, lower_addr=image_lower, upper_addr=image_upper, hash_size=hash_size
                )
                offset_tuple = {
                    "offset": block.offset,
                    "length": block.length,
                    "size": block_size,
                }
                if block_hash not in blockhashes:
                    blockhashes[block_hash] = {
                        "hash": block_hash,
                        "count": 1,
                        "offset_tuples": [offset_tuple],
                        "size": block_size,
                    }
                else:
                    blockhashes[block_hash]["offset_tuples"].append(offset_tuple)
                    blockhashes[block_hash]["count"] += 1
        return list(blockhashes.values())

    def extractBlockhashes(self, smda_report, min_block_size=4):
        family = getattr(smda_report, "family", None)
        if family is None:
            family = ""
        output = {
            "family": family,
            "version": smda_report.version,
            "bitness": smda_report.bitness,
            "sha256": smda_report.sha256,
            "filename": smda_report.filename,
            "filesize": smda_report.binary_size,
            "is_library": smda_report.is_library,
            "min_block_size": min_block_size,
            "num_hashes": 0,
            "num_functions": 0,
            "num_functions_hashed": 0,
            "num_blocks": 0,
            "num_all_blocks": 0,
            "block_bytes": 0,
            "blockhashes": {},
        }
        if not self._isUsableSmdaReport(smda_report):
            return output
        blockhashes = {}
        image_lower = smda_report.base_addr or 0
        image_upper = image_lower + (smda_report.binary_size or 0)
        function_id = 0
        num_all_blocks = 0
        num_blocks = 0
        num_functions = 0
        num_functions_hashed = 0
        for function in smda_report.getFunctions():
            num_functions += 1
            function_hashed = False
            for block in function.getBlocks():
                num_all_blocks += 1
                if block.length >= min_block_size:
                    num_blocks += 1
                    function_hashed = True
                    block_size = sum([len(ins.bytes) // 2 for ins in block.getInstructions()])
                    block_hash = self.calculateBlockhash(block, lower_addr=image_lower, upper_addr=image_upper)
                    if block_hash not in blockhashes:
                        blockhashes[block_hash] = {}
                    if block_size not in blockhashes[block_hash]:
                        blockhashes[block_hash][block_size] = set()
                    blockhashes[block_hash][block_size].add(function_id)
                    output["block_bytes"] += block_size
            if function_hashed:
                num_functions_hashed += 1
            function_id += 1
        num_hashes = 0
        for blockhash, by_size in blockhashes.items():
            for size, offsets in by_size.items():
                num_hashes += 1
                by_size[size] = sorted(list(offsets))
        output["num_functions"] = num_functions
        output["num_functions_hashed"] = num_functions_hashed
        output["num_blocks"] = num_blocks
        output["num_all_blocks"] = num_all_blocks
        output["num_hashes"] = num_hashes
        output["blockhashes"] = blockhashes
        return output


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <target_binary_path>")
        sys.exit(1)
    if os.path.isfile(sys.argv[1]):
        INPUT_FILENAME = os.path.basename(sys.argv[1])
        hasher = BlockHasher()
        blockhash_report = hasher.processFile(sys.argv[1])
        with open(INPUT_FILENAME + ".blocks", "w") as fout:
            json.dump(blockhash_report, fout, indent=1, sort_keys=True)
