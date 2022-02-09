import os
import re
import sys
import json
import struct
import hashlib
import logging

from smda.Disassembler import Disassembler
from smda.common.SmdaReport import SmdaReport, SmdaFunction
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

# Only do basicConfig if no handlers have been configured
if len(logging._handlerList) == 0:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOG = logging.getLogger(__name__)


class BlockHasher(object):

    def parseBitnessFromFilename(self, filepath):
        # try to infer base addr from filename, in case we process a mapped image / memory dump
        baddr_match = re.search(re.compile("0x(?P<base_addr>[0-9a-fA-F]{8,16})$"), filepath)
        if baddr_match:
            parsed_bitness = 32 if len(baddr_match.group("base_addr")) == 8 else 64
            LOG.info("Parsed bitness from file name: %d", parsed_bitness)
            return parsed_bitness
        architecture_match = re.search(re.compile("(?P<bitness>(x32|x64))"), filepath)
        if architecture_match:
            parsed_bitness = 32 if "x32" in architecture_match.group("bitness") else 64
            LOG.info("Parsed bitness from file name: %d", parsed_bitness)
            return parsed_bitness
        LOG.warning("No bitness recognized, using 0.")
        return None

    def parseBaseAddrFromFilename(self, filepath):
        # try to infer base addr from filename, in case we process a mapped image / memory dump
        baddr_match = re.search(re.compile("0x(?P<base_addr>[0-9a-fA-F]{5,16})"), filepath)
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

    def processBuffer(self, buffer, filename, bitness=None, baseaddress=None):
        LOG.info("now analyzing {}".format(filename))
        DISASSEMBLER = Disassembler()
        if "_0x" in filename or baseaddress:
            BASE_ADDR = baseaddress if baseaddress is not None else self.parseBaseAddrFromFilename(filename)
            BITNESS = bitness if bitness is not None else self.parseBitnessFromFilename(filename)
            SMDA_REPORT = DISASSEMBLER.disassembleBuffer(buffer, BASE_ADDR, BITNESS)
        else:
            SMDA_REPORT = DISASSEMBLER.disassembleUnmappedBuffer(buffer)
        SMDA_REPORT.filename = os.path.basename(filename)
        LOG.info(SMDA_REPORT)
        blockhash_report = self.extractBlockhashes(SMDA_REPORT)
        LOG.info("hashes extracted.")
        return blockhash_report

    def processFile(self, filepath):
        LOG.info("now analyzing {}".format(filepath))
        INPUT_FILENAME = os.path.basename(filepath)
        DISASSEMBLER = Disassembler()
        if "dump" in filepath:
            BUFFER = self.readFileContent(filepath)
            BASE_ADDR = self.parseBaseAddrFromFilename(INPUT_FILENAME)
            BITNESS = self.parseBitnessFromFilename(INPUT_FILENAME)
            SMDA_REPORT = DISASSEMBLER.disassembleBuffer(BUFFER, BASE_ADDR, BITNESS)
        else:
            SMDA_REPORT = DISASSEMBLER.disassembleFile(filepath)
        SMDA_REPORT.filename = os.path.basename(INPUT_FILENAME)
        LOG.info(SMDA_REPORT)
        blockhash_report = self.extractBlockhashes(SMDA_REPORT)
        LOG.info("hashes extracted.")
        return blockhash_report

    def processSmda(self, smda_report):
        blockhash_report = self.extractBlockhashes(smda_report)
        return blockhash_report

    def calculateBlockhash(self, block, lower_addr, upper_addr, hash_size=4):
        escaped_binary_seq = []
        for instruction in block.getInstructions():
            escaped_binary_seq.append(instruction.getEscapedBinary(IntelInstructionEscaper, lower_addr=lower_addr, upper_addr=upper_addr))
        as_bytes = bytes([ord(c) for c in "".join(escaped_binary_seq)])
        if hash_size == 8:
            return struct.unpack("Q", hashlib.sha256(as_bytes).digest()[:8])[0]
        return struct.unpack("I", hashlib.sha256(as_bytes).digest()[:4])[0]

    def getBlockhashesForFunction(self, smda_report: "SmdaReport", smda_function: "SmdaFunction", min_block_size=4, hash_size=4):
        image_lower = smda_report.base_addr
        image_upper = image_lower + smda_report.binary_size
        blockhashes = {}
        for block in smda_function.getBlocks():
            if block.length >= min_block_size:
                block_size = sum([len(ins.bytes) // 2 for ins in block.getInstructions()])
                block_hash = self.calculateBlockhash(block, lower_addr=image_lower, upper_addr=image_upper)
                if block_hash not in blockhashes:
                    blockhashes[block_hash] = {"hash": block_hash, "count": 0, "size": block_size}
                blockhashes[block_hash]["count"] += 1
        return list(blockhashes.values())

    def extractBlockhashes(self, smda_report, min_block_size=4):
        output = {
            "family": smda_report.family,
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
            "blockhashes": {}
        }
        blockhashes = {}
        image_lower = smda_report.base_addr
        image_upper = image_lower + smda_report.binary_size
        function_id = 0
        num_all_blocks = 0
        num_blocks = 0
        num_functions = 0
        num_functions_hashed = 0
        for function in smda_report.getFunctions():
            function_offset = function.offset
            num_functions += 1
            for block in function.getBlocks():
                num_all_blocks += 1
                if block.length >= min_block_size:
                    num_blocks += 1
                    block_size = sum([len(ins.bytes) // 2 for ins in block.getInstructions()])
                    block_hash = self.calculateBlockhash(block, lower_addr=image_lower, upper_addr=image_upper)
                    if block_hash not in blockhashes:
                        blockhashes[block_hash] = {}
                    if block_size not in blockhashes[block_hash]:
                        blockhashes[block_hash][block_size] = set()
                    blockhashes[block_hash][block_size].add(function_id)
                    output["block_bytes"] += block_size
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
