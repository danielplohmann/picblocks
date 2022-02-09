import re
import os
import time
import logging
import hashlib

from waitress import serve
from werkzeug.utils import secure_filename
from flask import Flask, request, render_template, jsonify

from picblocks.blockhasher import BlockHasher
from picblocks.blockhashmatcher import BlockHashMatcher


logging.basicConfig(level=logging.INFO, format="%(asctime)-15s: %(name)-30s - %(message)s")
LOG = logging.getLogger("flask-app")

#TODO: Refactoring needed! Importing from external and unique source
USE_DB = False
db = None
if USE_DB:
    try:
        from pymongo import MongoClient
        c       = MongoClient("mongodb://localhost:27017")
        db      = c['malpedia']
        f_to_id = db['family_to_id']
        f_to_f  = db['family_id_to_family']
        blocks  = db['blockhashes']
        s_to_s  = db['sample_id_to_sample']
        s_s     = db['statistics']
    except:
        db = None
        LOG.error("Could not initialize database.")


app = Flask(__name__)
matcher = BlockHashMatcher()
start = time.time()
LOG.info("Loading BlocksDB")
if os.path.exists("db/picblocksdb.json"):
    matcher.loadDb("db/picblocksdb.json")
LOG.info("Done! (%5.2fs)", (time.time() - start))


def render_report(report, template):
    file_name = report['input_filename']
    sha256    = report['sha256']
    bitness   = report['bitness']
    extracted = report['input_block_hashes']
    block_b   = report['input_block_bytes']
    unmatched = report['unmatched_blocks']
    unmatch_sc= report['unmatched_score']
    # collect output and deliver at the end
    output = f""
    output += f"<table>\n<tr><th>#</th><th>family</th><th colspan='3'>direct match</th><th colspan='3'>libraries excluded</th><th colspan='3'>frequency adjusted</th><th colspan='3'>uniquely matched</th></tr>\n"
    index = 0
    alternate = 0
    for entry in report["family_matches"]:
        dark = "ed" if alternate % 2 == 0 else "od"
        light = "el" if alternate % 2 == 0 else "ol"
        green = "gd" if alternate % 2 == 0 else "gl"
        if entry['uniq_bytes'] > 0 or index < 20:
            style20 = " style='border-bottom: 2px solid black;'" if index == 19 else ""
            malpedia_link = f"<a href='https://malpedia.caad.fkie.fraunhofer.de/details/"+ entry['family'] +"' target='_blank'>"+str(entry['family'])+"</a>"
            #TODO: just improve this durity and rep. code
            _a = f"{entry['index']:>5,d}"
            _b = f"{entry['direct_bytes']:,d}"
            _c = f"{entry['direct_blocks']:,d}"
            _d = f"{entry['direct_perc']:>5.2f}%"
            _e = f"{entry['nonlib_bytes']:,d}"
            _f = f"{entry['nonlib_blocks']:,d}"
            _g = f"{entry['nonlib_perc']:>5.2f}%"
            _h = f"{entry['freq_bytes']:,d}"
            _i = f"{entry['freq_blocks']:5.2f}"
            _l = f"{entry['freq_perc']:>5.2f}%"
            _1 = f"{entry['uniq_bytes']:,d}"
            _2 = f"{entry['uniq_blocks']:,d}"
            _3 = f"{entry['uniq_perc']:>5.2f}%"
            output += f"<tr"+style20+"><td class='"+light+"'>"+_a+"</td><td class='"+light+"'>"+malpedia_link+"</td>"
            output += f"<td class='"+dark+"' style='text-align:right'>"+_b+"</td><td class='"+dark+"' style='text-align:right'>"+_c+"</td><td class='"+dark+"' style='text-align:right'>"+_d+"</td>"
            output += f"<td class='"+light+"' style='text-align:right'>"+_e+"</td><td class='"+light+"' style='text-align:right'>"+_f+"</td><td class='"+light+"' style='text-align:right'>"+_g+"</td>"
            output += f"<td class='"+dark+"' style='text-align:right'>"+_h+"</td><td class='"+dark+"' style='text-align:right'>"+_i+"</td><td class='"+dark+"' style='text-align:right'>"+_l+"</td>"
            if entry['uniq_bytes'] > 0:
                light = green
            output += f"<td class='"+light+"' style='text-align:right'>"+_1+"</td><td class='"+light+"' style='text-align:right'>"+_2+"</td><td class='"+light+"' style='text-align:right'>"+_3+"</td></tr>"
            alternate += 1
        index += 1
    output += "</table>\n"
    output += "<p></p>"
    output += "<h3>Information</h3>"
    output += "<p>results per matching class shown as (bytes, blocks, percent of bytes).<br />"
    output += "libraries excluded: filter out blocks known from a set of 3rd party libraries, including MSVC.<br />"
    output += "frequency adjusted: for the remainder, block scores are increasingly penalized when occurring in three or more families.<br />"
    output += "uniquely matched: Block score for blocks only found in this family.</p>"
    return render_template(template, file_name=file_name, sha256=sha256, bitness=bitness, extracted=extracted, unmatched=unmatched, unmatch_sc=unmatch_sc, out_html=output)


@app.route("/")
def index():
    LOG.info("request to /index")
    return render_template('index.html', db_timestamp=matcher.db_timestamp)

@app.route("/about")
def about():
    LOG.info("request to /about")
    stats = matcher.getDbStats()
    return render_template(
        'about.html', 
        num_families=stats["num_families"],
        num_libraries=stats["num_libraries"],
        num_files=stats["num_files"],
        num_functions=stats["num_functions"],
        num_hashes=stats["num_hashes"],
        num_hash_and_sizes=stats["num_hash_and_sizes"],
        num_bytes=stats["num_bytes"],
        num_bytes_unique=stats["num_bytes_unique"],
        db_timestamp=matcher.db_timestamp
    )


@app.route('/stats', methods=['GET'])
def get_stats():
    LOG.info("request to /stats")
    if request.method == 'GET':
        stats = []
        if USE_DB and db:
            f_c = f_to_id.find({}).count()
            s_c = s_to_s.find({}).count()
            b_c = blocks.find({}).count()
            cursor = s_s.find({})
            stats = list(cursor)
            return render_template('stats.html', db_online ="online", tracked_families=f_c, number_samples=s_c, number_blocks=b_c, s_stats=stats)
        else:
            return render_template('disabled.html')


@app.route('/blocks', methods=['GET', 'POST'])
def upload_file():
    LOG.info("request to /blocks")
    if request.method == 'POST':
        f = request.files['binary']
        binary = f.read()
        LOG.info(f"received binary with sha256: {hashlib.sha256(binary).hexdigest()}")
        form_bitness = int(request.form["bitness"]) if ("bitness" in request.form and request.form["bitness"] in ["32", "64"]) else None
        form_baseaddress = int(request.form["baseaddress"], 16) if ("baseaddress" in request.form and re.match("^0x[0-9a-fA-F]{1,16}$", request.form["baseaddress"])) else None
        hasher = BlockHasher()
        blockhash_report = hasher.processBuffer(binary, secure_filename(f.filename), bitness=form_bitness, baseaddress=form_baseaddress)
        report = matcher.match(blockhash_report)
        LOG.info("matching completed.")
        return render_report(report, "report.html")


@app.route('/api/blocks', methods=['POST'])
def upload_api_file():
    LOG.info("request to /api/blocks")
    if request.method == 'POST':
        binary = request.stream.read()
        LOG.info(f"received binary with sha256: {hashlib.sha256(binary).hexdigest()}")
        hasher = BlockHasher()
        blockhash_report = hasher.processBuffer(binary, f"sha256:{hashlib.sha256(binary).hexdigest()}")
        report = matcher.match(blockhash_report)
        LOG.info("matching completed.")
        return jsonify(report)


if __name__ == '__main__':
    # start up server as WSGI applet through waitress
    serve(app, host="127.0.0.1", port=9001)
