# Simple script to generate statistics against a given database.
# Very alpha stage, use at your own risk
# v:0.1 alpha

import json
import logging
import os
import time

from picblocks.blockhashmatcher import BlockHashMatcher

# TODO: Refactoring needed ! Importing from external and unique source

try:
    from pymongo import MongoClient

    c = MongoClient("mongodb://localhost:27017", serverSelectionTimeoutMS=2000)
    c.admin.command("ping")
    db = c["malpedia"]
    m_s = db["matching_db_against_itself"]
    s_s = db["statistics"]
except Exception:
    db = None
    m_s = None
    s_s = None

bl = "block-reports/"
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)-15s: %(name)-32s - %(message)s"
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)

# Tracing verified family DB composition
family_verified_frequency = {}
# Tracing verified families VS detected (recognized, calculated) families
family_verified_vs_detected = {}


def make_stats(matching_report):
    th = 70

    # checking if verified family is in the fammily frequency study
    verified_family = matching_report["original_family"]

    # keep trace of verified families
    if verified_family in family_verified_frequency:
        family_verified_frequency[verified_family] += 1
    else:
        family_verified_frequency[verified_family] = 1

    if verified_family not in family_verified_vs_detected:
        family_verified_vs_detected[verified_family] = {}

    for family in matching_report["family_matches"]:
        if float(family["nonlib_perc"]) < float(th):
            continue

        if verified_family not in family_verified_vs_detected:
            family_verified_vs_detected[verified_family] = {}

        if family["family"] in family_verified_vs_detected[verified_family]:
            family_verified_vs_detected[verified_family][family["family"]] += 1
        else:
            family_verified_vs_detected[verified_family][family["family"]] = 1
        logging.info(
            f"Adding to verified family {verified_family}, similarity to family {family['family']} ({family['nonlib_perc']:0.3f})"
        )
    return family_verified_vs_detected


def persist_matching_report(matching_report):
    if m_s is not None:
        m_s.insert_one(matching_report)
        logging.info("Matching report saved on DB !")
        return
    logging.info("MongoDB unavailable, skipping matching-report persist.")


def persist_stats():
    payload = {
        "family_verified_frequency": family_verified_frequency,
        "family_verified_vs_detected": family_verified_vs_detected,
    }
    if s_s is not None:
        s_s.insert_one(payload)
        logging.info("Statistics saved on DB !")
        return
    os.makedirs("db", exist_ok=True)
    stats_path = os.path.join("db", "stats.json")
    with open(stats_path, "w") as fout:
        json.dump(payload, fout)
    logging.info("MongoDB unavailable, wrote statistics to %s", stats_path)


def main():
    matcher = BlockHashMatcher()
    start = time.time()
    logging.info("Loading BlocksDB")
    if os.path.exists("db/picblocksdb.json"):
        matcher.loadDb("db/picblocksdb.json")
    logging.info("Done! (%5.2fs)", (time.time() - start))

    logging.info("Matching Existing Reports to entire DB")
    for root, _subdir, files in sorted(os.walk(bl)):
        for filename in sorted(files):
            logging.info(f"Working on {filename}")
            _f, e = os.path.splitext(filename)
            if e == ".blocks":
                with open(os.path.join(root, filename)) as fin:
                    bh_report = json.load(fin)
                    matching_report = matcher.match(bh_report)
                    matching_report["original_family"] = bh_report["family"]
                    persist_matching_report(matching_report)
                    make_stats(matching_report)

    persist_stats()


if __name__ == "__main__":
    main()
