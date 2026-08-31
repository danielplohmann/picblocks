import os
import struct

import pytest
from smda.aarch64.AArch64InstructionEscaper import AArch64InstructionEscaper
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

from picblocks.blockhasher import BlockHasher
from tests.fakes import (
    FakeBlock,
    FakeFunction,
    FakeInstruction,
    FakeReport,
    RecordingDisassembler,
    make_function,
)


def test_num_functions_hashed_counts_functions_not_blocks():
    hasher = BlockHasher()
    function = make_function(num_blocks=12, instructions_per_block=4)
    report = FakeReport([function])
    output = hasher.extractBlockhashes(report)
    assert output["num_functions"] == 1
    assert output["num_blocks"] == 12
    assert output["num_functions_hashed"] == 1
    assert output["num_functions_hashed"] != output["num_blocks"]


def test_num_functions_hashed_skips_functions_without_long_enough_blocks():
    hasher = BlockHasher()
    hashed = make_function(num_blocks=2, instructions_per_block=4, offset=0)
    skipped = make_function(num_blocks=3, instructions_per_block=2, offset=100)
    output = hasher.extractBlockhashes(FakeReport([hashed, skipped]))
    assert output["num_functions"] == 2
    assert output["num_functions_hashed"] == 1
    assert output["num_blocks"] == 2


def test_error_report_does_not_crash_when_xcfg_is_none():
    hasher = BlockHasher()
    report = FakeReport(functions=[], status="error", xcfg=None, family=None, message="parse failed")
    output = hasher.extractBlockhashes(report)
    assert output["blockhashes"] == {}
    assert output["num_functions"] == 0
    assert output["family"] == ""


def test_none_family_normalized_to_empty_string():
    hasher = BlockHasher()
    report = FakeReport([make_function(1)], family=None)
    output = hasher.extractBlockhashes(report)
    assert output["family"] == ""


def test_calculate_blockhash_uses_function_escaper_not_hardcoded_intel():
    hasher = BlockHasher()
    instruction = FakeInstruction("90")
    block = FakeBlock([instruction] * 4)
    FakeFunction([block], escaper=AArch64InstructionEscaper)
    hasher.calculateBlockhash(block, 0, 0x1000)
    assert instruction.escapers
    assert set(instruction.escapers) == {AArch64InstructionEscaper}
    assert IntelInstructionEscaper not in instruction.escapers


def test_calculate_blockhash_uses_report_architecture_when_escaper_unset():
    hasher = BlockHasher()
    instruction = FakeInstruction("90")
    block = FakeBlock([instruction] * 4)
    function = FakeFunction([block], architecture="aarch64")
    FakeReport([function], architecture="aarch64")
    hasher.calculateBlockhash(block, 0, 0x1000)
    assert instruction.escapers
    assert set(instruction.escapers) == {AArch64InstructionEscaper}


def test_blockhash_is_little_endian_prefix():
    hasher = BlockHasher()
    instruction = FakeInstruction("90", escaped="90")
    block = FakeBlock([instruction] * 4)
    FakeFunction([block], escaper=IntelInstructionEscaper)
    digest = __import__("hashlib").sha256(b"90909090").digest()
    assert hasher.calculateBlockhash(block, 0, 0x1000, hash_size=4) == struct.unpack("<I", digest[:4])[0]
    assert hasher.calculateBlockhash(block, 0, 0x1000, hash_size=8) == struct.unpack("<Q", digest[:8])[0]


def test_get_blockhashes_for_function_mcrit_shape():
    hasher = BlockHasher()
    function = make_function(num_blocks=2, instructions_per_block=4)
    entries = hasher.getBlockhashesForFunction(function, 0, 0x1000, hash_size=8)
    assert len(entries) == 1
    entry = entries[0]
    assert set(entry) == {"hash", "count", "offset_tuples", "size"}
    assert entry["count"] == 2
    assert len(entry["offset_tuples"]) == 2
    assert isinstance(entry["hash"], int)
    for offset_tuple in entry["offset_tuples"]:
        assert set(offset_tuple) == {"offset", "length", "size"}
        assert offset_tuple["length"] == 4
        assert offset_tuple["size"] == 4
    # mcrit MongoDbStorage / MemoryStorage unpack loop
    picblockhashes = []
    for hash_entry in entries:
        for block_entry in hash_entry["offset_tuples"]:
            block_entry["hash"] = hash_entry["hash"]
            picblockhashes.append(block_entry)
    assert len(picblockhashes) == 2
    assert {item["hash"] for item in picblockhashes} == {entry["hash"]}


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/data/dumps/malware.exe", False),
        ("my_dump_analysis.exe", False),
        ("dump_0x10000000", True),
        ("/tmp/dump7_0x00400000", True),
        ("sample_0x140000000.bin", False),
        ("payload_0x401000.exe", False),
        ("win.family/sample_unpacked", False),
    ],
)
def test_dump_filename_detection_does_not_use_full_path_substring(path, expected):
    hasher = BlockHasher()
    assert hasher._isMappedDumpFilename(path) is expected


def test_process_file_does_not_treat_dumps_directory_as_raw_buffer(monkeypatch, tmp_path):
    hasher = BlockHasher()
    dummy = RecordingDisassembler(lambda: FakeReport([make_function(1)]))
    monkeypatch.setattr("picblocks.blockhasher.Disassembler", lambda: dummy)
    target = tmp_path / "dumps" / "malware.exe"
    target.parent.mkdir()
    target.write_bytes(b"MZ" + b"\x00" * 64)
    hasher.processFile(str(target))
    assert dummy.calls[0][0] == "file"


def test_process_file_uses_buffer_for_malpedia_dump_names(monkeypatch, tmp_path):
    hasher = BlockHasher()
    dummy = RecordingDisassembler(lambda: FakeReport([make_function(1)]))
    monkeypatch.setattr("picblocks.blockhasher.Disassembler", lambda: dummy)
    target = tmp_path / "dump_0x10000000"
    target.write_bytes(b"\x90" * 32)
    hasher.processFile(str(target))
    assert dummy.calls[0][0] == "buffer"
    assert dummy.calls[0][1] == 0x10000000
    assert dummy.calls[0][2] == 32


def test_process_buffer_honors_baseaddress_zero(monkeypatch):
    hasher = BlockHasher()
    dummy = RecordingDisassembler(lambda: FakeReport([make_function(1)]))
    monkeypatch.setattr("picblocks.blockhasher.Disassembler", lambda: dummy)
    hasher.processBuffer(b"MZ" + b"\x00" * 64, "payload.bin", bitness=32, baseaddress=0)
    assert dummy.calls[0] == ("buffer", 0, 32)


def test_process_buffer_without_base_uses_unmapped_mapper(monkeypatch):
    hasher = BlockHasher()
    dummy = RecordingDisassembler(lambda: FakeReport([make_function(1)]))
    monkeypatch.setattr("picblocks.blockhasher.Disassembler", lambda: dummy)
    hasher.processBuffer(b"MZ" + b"\x00" * 64, "payload.bin")
    assert dummy.calls[0] == ("unmapped",)


def test_process_buffer_treats_0x_in_basename_as_mapped(monkeypatch):
    hasher = BlockHasher()
    dummy = RecordingDisassembler(lambda: FakeReport([make_function(1)]))
    monkeypatch.setattr("picblocks.blockhasher.Disassembler", lambda: dummy)
    hasher.processBuffer(b"\x90" * 32, "sample_0x140000000.bin")
    assert dummy.calls[0][0] == "buffer"
    assert dummy.calls[0][1] == 0x140000000
    assert dummy.calls[0][2] == 64


def test_process_file_does_not_treat_0x_pe_name_as_dump(monkeypatch, tmp_path):
    hasher = BlockHasher()
    dummy = RecordingDisassembler(lambda: FakeReport([make_function(1)]))
    monkeypatch.setattr("picblocks.blockhasher.Disassembler", lambda: dummy)
    target = tmp_path / "payload_0x401000.exe"
    target.write_bytes(b"MZ" + b"\x00" * 64)
    hasher.processFile(str(target))
    assert dummy.calls[0][0] == "file"


def test_parse_bitness_from_unanchored_dump_name():
    hasher = BlockHasher()
    assert hasher.parseBitnessFromFilename("dump_0x400000.bin") == 32
    assert hasher.parseBitnessFromFilename("dump_0x10000000.bin") == 32
    assert hasher.parseBitnessFromFilename("dump_0x140000000.bin") == 64
    assert hasher.parseBitnessFromFilename("dump_0x0000000140000000.bin") == 64
    assert hasher.parseBitnessFromFilename("sample_x64.exe") == 64
    assert hasher.parseBitnessFromFilename("sample_x86.bin") == 32
    assert hasher.parseBitnessFromFilename("sample_i386.bin") == 32
    assert hasher.parseBitnessFromFilename("sample_amd64.bin") == 64
    assert hasher.parseBitnessFromFilename("sample_win32.exe") == 32
    assert hasher.parseBitnessFromFilename("sample_win64.exe") == 64
    assert hasher.parseBitnessFromFilename("plain.exe") is None


def test_dump_filename_detection_supports_short_hex_base():
    hasher = BlockHasher()
    assert hasher._isMappedDumpFilename("dump_0x400000") is True
    assert hasher._isMappedDumpFilename("dump7_0x400000") is True
    assert hasher.parseBaseAddrFromFilename("dump_0x400000") == 0x400000


def test_escaper_resolution_for_cil_and_dalvik():
    from smda.cil.CilInstructionEscaper import CilInstructionEscaper
    from smda.dalvik.DalvikInstructionEscaper import DalvikInstructionEscaper

    hasher = BlockHasher()
    cil_block = FakeBlock([FakeInstruction("00")] * 4)
    cil_func = FakeFunction([cil_block], architecture="cil")
    FakeReport([cil_func], architecture="cil")
    assert hasher._getInstructionEscaper(cil_block) == CilInstructionEscaper

    dalvik_block = FakeBlock([FakeInstruction("00")] * 4)
    dalvik_func = FakeFunction([dalvik_block], architecture="dalvik")
    FakeReport([dalvik_func], architecture="dalvik")
    assert hasher._getInstructionEscaper(dalvik_block) == DalvikInstructionEscaper


def test_extract_blockhashes_on_real_smda_error_status():
    from smda.common.SmdaReport import SmdaReport

    hasher = BlockHasher()
    report = SmdaReport(None)
    report.status = "error"
    report.message = "failed"
    report.filename = "truncated.bin"
    report.family = None
    report.version = None
    report.bitness = None
    report.sha256 = None
    report.binary_size = 0
    report.is_library = False
    report.base_addr = 0
    output = hasher.extractBlockhashes(report)
    assert output["num_hashes"] == 0
    assert output["family"] == ""


def test_real_smda_file_hashing_if_system_binary_exists():
    candidate = "/bin/true" if os.path.isfile("/bin/true") else "/usr/bin/true"
    if not os.path.isfile(candidate):
        pytest.skip("no system binary available")
    hasher = BlockHasher()
    output = hasher.processFile(candidate)
    assert output["num_functions"] >= 1
    assert output["num_functions_hashed"] <= output["num_functions"]
    assert output["num_functions_hashed"] <= output["num_blocks"]
    if output["num_blocks"]:
        assert output["block_bytes"] > 0
