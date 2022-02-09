import os
import sys
import json
import math
import logging
import datetime
from collections import defaultdict, Counter

try:
    # optionally use tqdm to render progress (should not be a package requirement)
    import tqdm
except:
    tqdm = None

from .blockhasher import BlockHasher

# Only do basicConfig if no handlers have been configured
if len(logging._handlerList) == 0:
    logging.basicConfig(level=logging.INFO, format="%(asctime)-15s %(message)s")
LOG = logging.getLogger(__name__)


class BlockHashMatcher(object):

    def __init__(self):
        self.db_timestamp = datetime.datetime.utcnow().strftime("%Y-%d-%dT%H:%M:%SZ")
        self.blockhashes = {}
        self.family_to_id = {}
        self.family_id_to_family = {}
        self.sample_id_to_sample = {}

    def load(self, filepath):
        """ load a single blockhash report """
        with open(filepath, "r") as fin:
            blockhash_report = json.load(fin)
            family = blockhash_report["family"]
            if family not in self.family_to_id:
                family_id = len(self.family_to_id)
                self.family_to_id[family] = family_id
                self.family_id_to_family[family_id] = family
            family_id = self.family_to_id[family]
            sample_id = len(self.sample_id_to_sample)
            self.sample_id_to_sample[sample_id] = blockhash_report["filename"]
            for blockhash, data in blockhash_report["blockhashes"].items():
                int_hash = int(blockhash)
                if int_hash not in self.blockhashes:
                    self.blockhashes[int_hash] = {}
                for size, fids in data.items():
                    int_size = int(size)
                    if int_size not in self.blockhashes[int_hash]:
                        self.blockhashes[int_hash][int_size] = []
                    for fid in fids:
                        is_library = False if "is_library" not in blockhash_report else blockhash_report["is_library"]
                        self.blockhashes[int_hash][int_size].append((family_id, sample_id, fid, is_library))

    def loadDb(self, filepath):
        """ load a previously processed database of blockhashes """
        with open(filepath, "r") as fin:
            blockhash_db = json.load(fin)
            self.db_timestamp = blockhash_db["timestamp"]
            self.family_to_id = blockhash_db["family_to_id"]
            self.family_id_to_family = {int(k): v for k, v in blockhash_db["family_id_to_family"].items()}
            self.sample_id_to_sample = {int(k): v for k, v in blockhash_db["sample_id_to_sample"].items()}
            self.blockhashes = {int(k): {int(ki): vi for ki, vi in v.items()} for k, v in blockhash_db["blockhashes"].items()}

    def saveDb(self, filepath):
        """ save the current database of blockhashes """
        with open(filepath, "w") as fout:
            json_db = {
                "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "family_to_id": self.family_to_id,
                "family_id_to_family": self.family_id_to_family,
                "sample_id_to_sample": self.sample_id_to_sample,
                "blockhashes": self.blockhashes,
            }
            json.dump(json_db, fout)

    def getDbStats(self):
        """ return statistics for currently loaded DB """
        family_ids = set()
        library_ids = set()
        function_ids = set()
        num_hashes = 0
        num_hash_and_sizes = 0
        num_bytes = 0
        num_bytes_unique = 0
        hash_size_counts = Counter()
        for block_hash, sizes in self.blockhashes.items():
            num_hashes += 1
            hash_size_counts[len(sizes)] += 1
            for size, entries in sizes.items():
                num_hash_and_sizes += 1
                num_bytes_unique += size
                for entry in entries:
                    family_id, sample_id, fid, is_library = entry
                    function_ids.add(f"{sample_id}.{fid}")
                    num_bytes += size
                    if is_library:
                        library_ids.add(family_id)
                    else:
                        family_ids.add(family_id)
        return {
            "num_families": len(family_ids),
            "num_libraries": len(library_ids),
            "num_files": len(self.sample_id_to_sample),
            "num_functions": len(function_ids),
            "num_hashes": num_hashes,
            "num_hash_and_sizes": num_hash_and_sizes,
            "num_bytes": num_bytes,
            "num_bytes_unique": num_bytes_unique,
            "hash_size_counts": dict(hash_size_counts)
        }

    def match(self, blockhash_report):
        """ match a blockhash report against the database """
        match_report = {
            "num_families": len(self.family_to_id),
            "num_samples": len(self.sample_id_to_sample),
            "num_blockhashes": len(self.blockhashes),
            "bitness": blockhash_report['bitness'],
            "sha256": blockhash_report['sha256'],
            "input_filename": blockhash_report['filename'],
            "input_block_bytes": blockhash_report['block_bytes'],
            "input_block_hashes": len(blockhash_report['blockhashes']),
            "unmatched_score": 0,
            "unmatched_hashes": 0,
            "family_matches": []
        }
        LOG.debug(f"Using {len(self.family_to_id)} families, {len(self.sample_id_to_sample)} samples with {len(self.blockhashes)} hashes for matching.")
        sample_matches = defaultdict(int)
        # bytes
        family_bytes = defaultdict(int)
        non_library_bytes = defaultdict(int)
        adj_family_bytes = defaultdict(int)
        unique_family_bytes = defaultdict(int)
        # blocks
        family_blocks = defaultdict(int)
        non_library_blocks = defaultdict(int)
        adj_family_blocks = defaultdict(int)
        unique_family_blocks = defaultdict(int)
        unmatched_score = 0
        unmatched_blocks = 0
        for blockhash, data in blockhash_report["blockhashes"].items():
            int_hash = int(blockhash)
            for size, fids in data.items():
                int_size = int(size)
                family_ids = set()
                sample_ids = set()
                for fid in fids:
                    if int_hash in self.blockhashes:
                        if int_size in self.blockhashes[int_hash]:
                            families = set([entry[0] for entry in self.blockhashes[int_hash][int_size]])
                            has_library = any([entry[3] for entry in self.blockhashes[int_hash][int_size]])
                            family_adjustment_value = 1 if len(families) < 3 else 1 + int(math.log(len(families), 2))
                            for entry in self.blockhashes[int_hash][int_size]:
                                family_id, sample_id, fid, is_library = entry
                                if family_id not in family_ids:
                                    family_ids.add(family_id)
                                    family_bytes[family_id] += int_size
                                    family_blocks[family_id] += 1
                                    if not has_library:
                                        non_library_bytes[family_id] += int_size
                                        non_library_blocks[family_id] += 1
                                        adj_family_bytes[family_id] += int_size / family_adjustment_value
                                        adj_family_blocks[family_id] += 1 / family_adjustment_value
                                        if len(families) == 1:
                                            unique_family_bytes[family_id] += int_size
                                            unique_family_blocks[family_id] += 1
                                    else:
                                        # TODO we could collect the function names of functions we potentially recognize here.
                                        pass
                                # TODO make use of sample matches in the output
                                if sample_id not in sample_ids:
                                    sample_ids.add(sample_id)
                                    sample_matches[sample_id] += int_size
                        else:
                            unmatched_score += int_size
                    else:
                        unmatched_score += int_size
                        unmatched_blocks += 1
        match_report["unmatched_score"] = unmatched_score
        match_report["unmatched_blocks"] = unmatched_blocks
        LOG.debug(f"Input: {blockhash_report['filename']} ({blockhash_report['family']}/{blockhash_report['version']}) - {blockhash_report['block_bytes']:,d} bytes.")
        LOG.debug(f"Unmatched blocks: {unmatched_blocks:,d}, {unmatched_score:,d} bytes.")
        LOG.debug("Family matches: ")
        index = 1
        LOG.debug("*" * 93)
        LOG.debug(f"{'#':>2}: {'id':>5} | {'family':>30} | {'bytescore':>9} | {'%':>6} | {'nolib%':>6} | {'adj%':>6} | {'uniq%':>6}")
        for family_id, direct_bytes in sorted(family_bytes.items(), key=lambda x: x[1], reverse=True):
            nonlib_bytes = non_library_bytes[family_id]
            adj_bytes = adj_family_bytes[family_id]
            unique_bytes = unique_family_bytes[family_id]
            family_result = {
                "index": index,
                "family": self.family_id_to_family[family_id],
                "direct_bytes": direct_bytes,
                "direct_blocks": family_blocks[family_id],
                "direct_perc": 100 * direct_bytes / blockhash_report['block_bytes'],
                "nonlib_bytes": int(nonlib_bytes),
                "nonlib_blocks": non_library_blocks[family_id],
                "nonlib_perc": 100 * nonlib_bytes / blockhash_report['block_bytes'],
                "freq_bytes": int(adj_bytes),
                "freq_blocks": adj_family_blocks[family_id],
                "freq_perc": 100 * adj_bytes / blockhash_report['block_bytes'],
                "uniq_bytes": int(unique_bytes),
                "uniq_blocks": unique_family_blocks[family_id],
                "uniq_perc": 100 * unique_bytes / blockhash_report['block_bytes']
            }
            match_report["family_matches"].append(family_result)
            if index < 20 or unique_bytes > 0:
                LOG.debug(f"{index:>5,d}: {family_id:>5,d} | {self.family_id_to_family[family_id]:>30} | {direct_bytes:>9,d} | {100 * direct_bytes / blockhash_report['block_bytes']:>6.2f} | {100 * nonlib_bytes / blockhash_report['block_bytes']:>6.2f} | {100 * adj_bytes / blockhash_report['block_bytes']:>6.2f} | {100 * unique_bytes / blockhash_report['block_bytes']:>6.2f}")
            index += 1
        LOG.debug("*" * 93)
        return match_report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <block_files_path> <optional:target_binary_path>")
        sys.exit(1)
    blocks_path = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else None
    hasher = BlockHasher()
    matcher = BlockHashMatcher()
    if target is not None and os.path.isfile(target):
        if os.path.exists("db/picblocksdb.json"):
            print("Loading cached DB: db/picblocksdb.json")
            matcher.loadDb("db/picblocksdb.json")
        else:
            print("No cached DB found, aggregating blockhash reports...")
            dir_iter = tqdm.tqdm(os.listdir(blocks_path)) if tqdm is not None else os.listdir(blocks_path)
            for filename in dir_iter:
                if filename.endswith(".blocks"):
                    matcher.load(blocks_path + os.sep + filename)
            print("saving DB...")
            matcher.saveDb("db/picblocksdb.json")
        blockhash_report = hasher.processFile(target)
        print(f"#> hashed input file: {blockhash_report['num_hashes']} hashes covering {blockhash_report['block_bytes']} bytes.")
        matcher.match(blockhash_report)
    else:
        print("Aggregating blockhash reports to create a new DB...")
        dir_iter = tqdm.tqdm(os.listdir(blocks_path)) if tqdm is not None else os.listdir(blocks_path)
        for filename in dir_iter:
            if filename.endswith(".blocks"):
                matcher.load(blocks_path + os.sep + filename)
        print("saving DB...")
        matcher.saveDb("db/picblocksdb.json")
