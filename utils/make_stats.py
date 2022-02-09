# Simple script to generate statistics against a given database.
# Very alpha stage, use at your own risk
# v:0.1 alpha

import os
import time
import logging
from picblocks.blockhasher import BlockHasher
from picblocks.blockhashmatcher import BlockHashMatcher

#TODO: Refactoring needed ! Importing from external and unique source
import json

try:
    from pymongo import MongoClient
    c       = MongoClient("mongodb://localhost:27017")
    db      = c['malpedia']
    m_s     = db['matching_db_against_itself']
    s_s     = db['statistics']
except:
    db = None

bl = 'block-reports/'
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)-15s: %(name)-32s - %(message)s"
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)

matcher = BlockHashMatcher()
start = time.time()
logging.info("Loading BlocksDB")
if os.path.exists("db/picblocksdb.json"):
    matcher.loadDb("db/picblocksdb.json")
logging.info("Done! (%5.2fs)", (time.time() - start))

# Tracing verified family DB composition
family_verified_frequency = {}
# Tracing verified families VS detected (recognized, calculated) families
family_verified_vs_detected = {}

def make_stats(matching_report):
    th = 70

    # checking if verified family is in the fammily frequency study
    verified_family =  matching_report['original_family']

    # keep trace of verified families
    if verified_family in family_verified_frequency:
            family_verified_frequency[verified_family] += 1
    else:
            family_verified_frequency[verified_family] = 1

    if verified_family not in family_verified_vs_detected :
        family_verified_vs_detected[verified_family] = {}

    for family in matching_report['family_matches']:
        if float(family['nonlib_perc']) < float(th):
            continue

        if verified_family not in family_verified_vs_detected:
            family_verified_vs_detected[verified_family] = {}

        if family['family'] in family_verified_vs_detected[verified_family]:
            family_verified_vs_detected[verified_family][family['family']] += 1
        else:
            family_verified_vs_detected[verified_family][family['family']] = 1
        logging.info("Adding to verified family %s, similarity to family %s (%0.3f)" % (verified_family, family['family'], family['nonlib_perc']))
    return family_verified_vs_detected


logging.info("Matching Existing Reports to entire DB")
for root, subdir, files in sorted(os.walk(bl)):
    for filename in sorted(files):
        logging.info("Working on %s" % filename)
        f, e = os.path.splitext(filename)
        if e == ".blocks":
            with open(os.path.join(root, filename)) as fin:
                bh_report = json.load(fin)
                matching_report = matcher.match(bh_report)
                matching_report['original_family'] = bh_report['family']
                m_s.insert_one(matching_report)
                logging.info("Matching report saved on DB !")
                make_stats(matching_report)


s_s.insert_one({'family_verified_frequency': family_verified_frequency, 'family_verified_vs_detected':family_verified_vs_detected})

