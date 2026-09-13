"""Parity checks against a real SMDA, not a fake.

Every other test in this suite drives BlockHasher through tests.fakes, so a change in
SMDA's own escaper or PIC-hash API would leave them all green while picblocks silently
went back to hashing everything as Intel. These disassemble a small synthetic buffer and
compare against the hash SMDA computes for the same block.
"""

import struct

import pytest
from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper
from smda.Disassembler import Disassembler
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

from picblocks.blockhasher import BlockHasher

# push ebp / mov ebp, esp / 4x nop / pop ebp / ret
INTEL_FUNCTION = bytes.fromhex("558bec909090905dc3")
# stp x29, x30, [sp, #-16]! / mov x0, #1 / mov x0, #1 / ldp x29, x30, [sp], #16 / ret
AARCH64_FUNCTION = b"".join(
    struct.pack("<I", word) for word in (0xA9BF7BFD, 0xD2800020, 0xD2800020, 0xA8C17BFD, 0xD65F03C0)
)
BASE_ADDR = 0x400000


def _disassemble(function_bytes, repetitions, **kwargs):
    buffer = (function_bytes * repetitions).ljust(0x400, b"\x00")
    return Disassembler().disassembleBuffer(buffer, BASE_ADDR, **kwargs)


def _hashable_blocks(report, min_block_size=4):
    return [
        block
        for function in report.getFunctions()
        for block in function.getBlocks()
        if (block.length or 0) >= min_block_size
    ]


@pytest.mark.parametrize(
    "function_bytes,repetitions,kwargs,architecture,escaper",
    [
        (INTEL_FUNCTION, 12, {"bitness": 32}, "intel", IntelInstructionEscaper),
        (AARCH64_FUNCTION, 16, {"architecture": "aarch64", "bitness": 64}, "aarch64", AArch64InstructionEscaper),
    ],
    ids=["intel", "aarch64"],
)
def test_blockhash_matches_smda_pic_block_hash(function_bytes, repetitions, kwargs, architecture, escaper):
    report = _disassemble(function_bytes, repetitions, **kwargs)
    assert report.architecture == architecture
    blocks = _hashable_blocks(report)
    assert blocks, "fixture produced no block long enough to hash"

    hasher = BlockHasher()
    image_lower = report.base_addr
    image_upper = image_lower + report.binary_size
    for block in blocks:
        assert hasher._getInstructionEscaper(block) is escaper
        assert hasher.calculateBlockhash(block, image_lower, image_upper, hash_size=8) == block.getPicBlockHash()


def test_aarch64_is_not_hashed_with_the_intel_escaper():
    """The bug this guards: every AArch64 block used to be escaped as Intel."""
    report = _disassemble(AARCH64_FUNCTION, 16, architecture="aarch64", bitness=64)
    blocks = _hashable_blocks(report)
    assert blocks

    hasher = BlockHasher()
    image_lower = report.base_addr
    image_upper = image_lower + report.binary_size
    block = blocks[0]
    as_intel = [
        instruction.getEscapedBinary(
            IntelInstructionEscaper,
            escape_intraprocedural_jumps=True,
            lower_addr=image_lower,
            upper_addr=image_upper,
        )
        for instruction in block.getInstructions()
    ]
    as_aarch64 = [
        instruction.getEscapedBinary(
            AArch64InstructionEscaper,
            escape_intraprocedural_jumps=True,
            lower_addr=image_lower,
            upper_addr=image_upper,
        )
        for instruction in block.getInstructions()
    ]
    assert as_intel != as_aarch64
    assert hasher.calculateBlockhash(block, image_lower, image_upper, hash_size=8) == block.getPicBlockHash()


def test_get_blockhashes_for_function_matches_smda_at_hash_size_8():
    """mcrit calls getBlockhashesForFunction(..., hash_size=8) on every add."""
    report = _disassemble(AARCH64_FUNCTION, 16, architecture="aarch64", bitness=64)
    hasher = BlockHasher()
    image_lower = report.base_addr
    image_upper = image_lower + report.binary_size
    for function in report.getFunctions():
        expected = {block.getPicBlockHash() for block in function.getBlocks() if (block.length or 0) >= 4}
        if not expected:
            continue
        produced = {
            entry["hash"] for entry in hasher.getBlockhashesForFunction(function, image_lower, image_upper, hash_size=8)
        }
        assert produced == expected


def test_unspecified_bitness_is_detected_from_the_code():
    """parseBitnessFromFilename returns None rather than guessing; SMDA fills it in."""
    report = _disassemble(INTEL_FUNCTION, 12, bitness=None)
    assert report.bitness == 32
