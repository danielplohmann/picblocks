import json
import os
import sys

from pymongo import MongoClient


def import_db(db_path="db/picblocksdb.json", mongo_uri="mongodb://localhost:27017"):
    if not os.path.isfile(db_path):
        print(f"[-] Database file not found: {db_path}")
        return False

    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
    client.admin.command("ping")
    db = client["malpedia"]
    f_to_id = db["family_to_id"]
    f_to_f = db["family_id_to_family"]
    blocks = db["blockhashes"]
    s_to_s = db["sample_id_to_sample"]

    with open(db_path, encoding="utf-8") as f:
        print("[+] Reading database file...")
        f_d = json.load(f)

    if "blockhashes" in f_d:
        print("[+] Creating blockhashes collection...")
        blocks.drop()
        block_docs = [{"k": key, "v": value} for key, value in f_d["blockhashes"].items()]
        if block_docs:
            blocks.insert_many(block_docs)

    if "sample_id_to_sample" in f_d:
        print("[+] Creating sample_id_to_sample collection...")
        s_to_s.drop()
        sample_docs = [{"k": key, "v": value} for key, value in f_d["sample_id_to_sample"].items()]
        if sample_docs:
            s_to_s.insert_many(sample_docs)

    if "family_to_id" in f_d:
        print("[+] Creating family_to_id collection...")
        f_to_id.drop()
        family_docs = [{"k": key, "v": value} for key, value in f_d["family_to_id"].items()]
        if family_docs:
            f_to_id.insert_many(family_docs)

    if "family_id_to_family" in f_d:
        print("[+] Creating family_id_to_family collection...")
        f_to_f.drop()
        fid_docs = [{"k": key, "v": value} for key, value in f_d["family_id_to_family"].items()]
        if fid_docs:
            f_to_f.insert_many(fid_docs)

    client.close()
    print("[+] DB import completed successfully.")
    return True


if __name__ == "__main__":
    db_file = sys.argv[1] if len(sys.argv) > 1 else "db/picblocksdb.json"
    import_db(db_path=db_file)
