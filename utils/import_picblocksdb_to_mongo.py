# Simple script to convert actual json DB into a more querable mongo DB
# Aim of this script is to mantain inalterate (or close to) the original
# jsondb structure, not to make a better one !
# Use at your own risk
# v:0.1 alpha

#TODO: Refactoring needed ! Importing from external and unique source
import json
from pymongo import MongoClient
c       = MongoClient("mongodb://localhost:27017")
db      = c['malpedia']
f_to_id = db['family_to_id']
f_to_f  = db['family_id_to_family']
blocks  = db['blockhashes']
s_to_s  = db['sample_id_to_sample']

with open('db/picblocksdb.json') as f:
    print("[+] Reading heavy file ...")
    f_d = json.load(f)

    print("[+] Creating blockhashes collection")
    for key, value in f_d['blockhashes'].items():
        b = {'k': key, 'v': value}
        blocks.insert_one(b)


    print("[+] Creating sample_id_to_sample collection")
    for key, value in f_d['sample_id_to_sample'].items():
        b = {'k': key, 'v': value}
        s_to_s.insert_one(b)

    print("[+] Conversion family_to_id keys() to mongo convention")
    for key, value in f_d['family_to_id'].items():
        print("[+] Working on the following keys: %s" % key)
        if key.find('.') >= 0:
            ky = key.replace('.','_')
        b = {'k' : key, 'v': value}
        f_to_id.insert_one(b)

    print("[+] Conversion family_id_to_family values()")
    for key, value in f_d['family_id_to_family'].items():
        print("[+] Working on the following keys: %s" % key)
        if key.find('.') >= 0:
            key = key.replace('.','_')
        b = {'k' : key, 'v': value}
        f_to_f.insert_one(b)

c.close()
