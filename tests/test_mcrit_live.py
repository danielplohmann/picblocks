"""Live mcrit integration: SMDA fixtures through a running Mongo-backed instance."""

import hashlib
import os
from pathlib import Path

import pytest

try:
    import requests
except ImportError:
    requests = None

from smda.Disassembler import Disassembler
from smda.intel.IntelInstructionEscaper import IntelInstructionEscaper

from picblocks.blockhasher import BlockHasher


def _smda_tests_dir():
    env = os.environ.get("SMDA_TESTS")
    if env:
        return Path(env)
    candidates = [
        Path("/home/ubuntu/github/smda/tests"),
        Path(__file__).resolve().parents[2] / "smda" / "tests",
        Path.cwd() / "smda" / "tests",
    ]
    for candidate in candidates:
        if (candidate / "cutwail_xored").is_file():
            return candidate
    return None


SMDA_TESTS = _smda_tests_dir()
MCRIT_URL = os.environ.get("MCRIT_URL", "http://127.0.0.1:8000")


def _decode_xored(path):
    data = Path(path).read_bytes()
    return bytes(byte ^ (index % 256) for index, byte in enumerate(data))


def _mcrit_up():
    if requests is None:
        return False
    try:
        response = requests.get(f"{MCRIT_URL}/status", timeout=2)
        return response.status_code == 200
    except Exception:
        return False


pytestmark = [
    pytest.mark.live_mcrit,
    pytest.mark.skipif(requests is None, reason="requests is not installed"),
    pytest.mark.skipif(not _mcrit_up(), reason=f"mcrit server is not running on {MCRIT_URL}"),
    pytest.mark.skipif(
        SMDA_TESTS is None,
        reason="SMDA test fixtures not found (set SMDA_TESTS to smda/tests)",
    ),
]


def _local_blockhashes(smda_function, report, force_escaper=None):
    hasher = BlockHasher()
    if force_escaper is not None:
        smda_function._escaper = force_escaper
    image_lower = report.base_addr or 0
    image_upper = image_lower + (report.binary_size or 0)
    picblockhashes = []
    for hash_entry in hasher.getBlockhashesForFunction(smda_function, image_lower, image_upper, hash_size=8):
        for block_entry in hash_entry["offset_tuples"]:
            block_entry["hash"] = hash_entry["hash"]
            picblockhashes.append(block_entry)
    return picblockhashes


def _submit_report(smda_report, family, filename):
    smda_report.family = family
    smda_report.filename = filename
    from mcrit.client.McritClient import McritClient

    client = McritClient(mcrit_server=MCRIT_URL)
    result = client.addReport(smda_report)
    assert result is not None
    sample_entry, _job_id = result
    return sample_entry


def test_mcrit_status_is_mongodb_backed():
    assert requests is not None
    payload = requests.get(f"{MCRIT_URL}/status", timeout=5).json()
    assert payload["status"] == "successful"
    assert payload["data"]["status"]["storage_type"] == "mongodb"


def test_intel_cutwail_picblockhashes_roundtrip_through_mcrit():
    buffer = _decode_xored(SMDA_TESTS / "cutwail_xored")
    report = Disassembler().disassembleUnmappedBuffer(buffer)
    assert report.status in ("ok", "timeout")
    assert report.architecture == "intel"
    assert report.num_functions >= 1
    sample = _submit_report(report, "win.cutwail", "cutwail.bin")
    from mcrit.client.McritClient import McritClient

    functions = McritClient(mcrit_server=MCRIT_URL).getFunctionsBySampleId(sample.sample_id)
    assert functions
    hashed = [function for function in functions if function.picblockhashes]
    assert hashed, "expected at least one function with picblockhashes"
    by_offset = {function.offset: function for function in functions}
    mismatches = 0
    checked = 0
    for smda_function in report.getFunctions():
        stored = by_offset.get(smda_function.offset)
        if stored is None:
            continue
        expected = _local_blockhashes(smda_function, report)
        stored_hashes = sorted((item["offset"], item["hash"]) for item in stored.picblockhashes)
        expected_hashes = sorted((item["offset"], item["hash"]) for item in expected)
        checked += 1
        if stored_hashes != expected_hashes:
            mismatches += 1
    assert checked >= 1
    assert mismatches == 0


def test_aarch64_picblockhashes_use_arch_escaper_not_intel():
    buffer = _decode_xored(SMDA_TESTS / "aarch64_static_xored")
    report = Disassembler().disassembleUnmappedBuffer(buffer)
    assert report.status in ("ok", "timeout")
    assert report.architecture == "aarch64"
    smda_functions = [function for function in report.getFunctions() if function.num_blocks]
    assert smda_functions
    sample = _submit_report(report, "elf.aarch64_static", "aarch64_static.bin")
    from mcrit.client.McritClient import McritClient

    stored_functions = McritClient(mcrit_server=MCRIT_URL).getFunctionsBySampleId(sample.sample_id)
    by_offset = {function.offset: function for function in stored_functions}
    arch_matches = 0
    intel_divergences = 0
    for smda_function in smda_functions:
        stored = by_offset.get(smda_function.offset)
        if stored is None or not stored.picblockhashes:
            continue
        arch_hashes = _local_blockhashes(smda_function, report)
        intel_hashes = _local_blockhashes(smda_function, report, force_escaper=IntelInstructionEscaper)
        stored_set = {(item["offset"], item["hash"]) for item in stored.picblockhashes}
        arch_set = {(item["offset"], item["hash"]) for item in arch_hashes}
        intel_set = {(item["offset"], item["hash"]) for item in intel_hashes}
        if stored_set == arch_set and stored_set:
            arch_matches += 1
        if arch_set != intel_set:
            intel_divergences += 1
    assert arch_matches >= 1
    assert intel_divergences >= 1


def test_worker_indexes_bashlite_binary_and_stores_blockhashes():
    buffer = _decode_xored(SMDA_TESTS / "bashlite_xored")
    from mcrit.client.McritClient import McritClient

    client = McritClient(mcrit_server=MCRIT_URL)
    digest = hashlib.sha256(buffer).hexdigest()
    sample = client.getSampleBySha256(digest)
    if sample is None:
        job = client.addBinarySample(buffer, filename="bashlite.elf", family="elf.bashlite")
        assert job is not None
        job_id = job if isinstance(job, str) else (job.get("job_id") if isinstance(job, dict) else str(job))
        assert isinstance(job_id, str)
        result = client.awaitResult(job_id)
        assert result is not None
        sample = client.getSampleBySha256(digest)
    assert sample is not None
    functions = client.getFunctionsBySampleId(sample.sample_id)
    hashed = [function for function in functions if function.picblockhashes]
    assert hashed
    first_hash = hashed[0].picblockhashes[0]["hash"]
    hits = client.getMatchesForPicBlockHash(first_hash)
    assert hits
