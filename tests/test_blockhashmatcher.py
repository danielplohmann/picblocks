import json
import re

from picblocks.blockhashmatcher import BlockHashMatcher, _utc_timestamp


def _report(family, filename, blockhashes, block_bytes, is_library=False):
    return {
        "family": family,
        "version": "1.0",
        "bitness": 32,
        "sha256": "ab" * 32,
        "filename": filename,
        "filesize": 1000,
        "is_library": is_library,
        "block_bytes": block_bytes,
        "blockhashes": blockhashes,
    }


def _matcher_with_family(hash_value, size, family="win.family"):
    matcher = BlockHashMatcher()
    matcher.family_to_id = {family: 0}
    matcher.family_id_to_family = {0: family}
    matcher.sample_id_to_sample = {0: "family.bin"}
    matcher.blockhashes = {
        hash_value: {
            size: [(0, 0, 0, False)],
        }
    }
    return matcher


def test_default_db_timestamp_uses_month_not_day_twice():
    matcher = BlockHashMatcher()
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", matcher.db_timestamp)
    # The old "%Y-%d-%d" format produced impossible dates such as 2026-31-31.
    year, month, day = matcher.db_timestamp.split("T")[0].split("-")
    assert 1 <= int(month) <= 12
    assert 1 <= int(day) <= 31
    assert _utc_timestamp()[:8] == matcher.db_timestamp[:8]


def test_match_percentages_use_instance_weighted_bytes():
    # 10 copies of a 16-byte matching block plus 16 unmatched bytes.
    matcher = _matcher_with_family(1, 16)
    query = _report(
        "win.query",
        "query.bin",
        {
            1: {16: list(range(10))},
            2: {16: [99]},
        },
        block_bytes=176,
    )
    result = matcher.match(query)
    family = result["family_matches"][0]
    assert family["direct_bytes"] == 160
    assert abs(family["direct_perc"] - (100.0 * 160 / 176)) < 1e-9
    assert family["direct_blocks"] == 10
    assert result["unmatched_score"] == 16
    assert result["unmatched_blocks"] == 1
    assert result["unmatched_hashes"] == 1


def test_unmatched_hashes_and_size_miss_are_counted():
    matcher = _matcher_with_family(1, 16)
    query = _report(
        "win.query",
        "query.bin",
        {
            1: {8: [0, 1]},  # hash hit, size miss
            99: {16: [2]},  # hash miss
        },
        block_bytes=40,
    )
    result = matcher.match(query)
    assert result["unmatched_hashes"] == 2
    assert result["unmatched_blocks"] == 3
    assert result["unmatched_score"] == 8 * 2 + 16
    assert result["family_matches"] == []


def test_empty_block_bytes_does_not_divide_by_zero():
    matcher = _matcher_with_family(1, 16)
    query = _report("win.query", "empty.bin", {1: {16: [0]}}, block_bytes=0)
    result = matcher.match(query)
    assert result["family_matches"][0]["direct_perc"] == 0.0
    assert result["family_matches"][0]["nonlib_perc"] == 0.0


def test_none_family_does_not_split_across_json_roundtrip(tmp_path):
    matcher = BlockHashMatcher()
    for index in range(2):
        path = tmp_path / f"sample{index}.blocks"
        path.write_text(json.dumps(_report(None, f"s{index}.bin", {"1": {"4": [0]}}, 4)))
        matcher.load(str(path))
    assert matcher.family_to_id == {"": 0}
    db_path = tmp_path / "db.json"
    matcher.saveDb(str(db_path))
    reloaded = BlockHashMatcher()
    reloaded.loadDb(str(db_path))
    extra = tmp_path / "extra.blocks"
    extra.write_text(json.dumps(_report(None, "extra.bin", {"2": {"4": [0]}}, 4)))
    reloaded.load(str(extra))
    assert set(reloaded.family_to_id.keys()) == {""}
    assert len(reloaded.family_id_to_family) == 1


def test_save_db_creates_nested_parent_directory(tmp_path):
    matcher = BlockHashMatcher()
    nested_path = tmp_path / "deeply" / "nested" / "dir" / "db.json"
    matcher.saveDb(str(nested_path))
    assert nested_path.is_file()


def test_load_handles_missing_filename_and_empty_blockhashes(tmp_path):
    matcher = BlockHashMatcher()
    path = tmp_path / "sample_without_filename.blocks"
    path.write_text(json.dumps({"family": "win.test"}))
    matcher.load(str(path))
    assert 0 in matcher.sample_id_to_sample
    assert matcher.sample_id_to_sample[0] == "sample_without_filename.blocks"
