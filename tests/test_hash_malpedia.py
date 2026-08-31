import struct

from hash_malpedia import NativeCodeIdentifier, dump_file_pattern, get_pe_offset, unpacked_file_pattern


def test_pe_offset_reads_dword_at_3c():
    buffer = bytearray(0x50)
    buffer[0x3C:0x40] = struct.pack("<I", 0x00010080)
    assert get_pe_offset(bytes(buffer)) == 0x00010080


def test_python_identifier_matches_python3_dll():
    identifier = NativeCodeIdentifier()
    assert identifier._identifyPython(b"xxxxpython3.dllxxxx") is True
    assert identifier._identifyPython(b"xxxxpython39.dllxxxx") is True
    assert identifier._identifyPython(b"xxxxpython27.dllxxxx") is True
    assert identifier._identifyPython(b"xxxxnotpythonxxxx") is False


def test_malpedia_filename_patterns():
    assert dump_file_pattern.search("dump_0x10000000")
    assert dump_file_pattern.search("dump7_0x00400000")
    assert unpacked_file_pattern.search("sample_unpacked")
    assert unpacked_file_pattern.search("sample_unpacked_x64")
    assert not unpacked_file_pattern.search("sample.exe")


def test_pool_worker_count_is_at_least_one():
    from multiprocessing import cpu_count
    from hash_malpedia import cpu_count as imported_cpu_count

    assert imported_cpu_count is cpu_count
    workers = max(1, (cpu_count() or 1) - 2)
    assert workers >= 1
