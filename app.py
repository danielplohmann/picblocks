import re
import os
import time
import logging
import hashlib
import json

from waitress import serve
from werkzeug.utils import secure_filename
from flask import Flask, request, render_template, jsonify

from picblocks.blockhasher import BlockHasher
from picblocks.blockhashmatcher import BlockHashMatcher

#TODO: Refactoring needed ! Importing from external and unique source
import json
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

LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)-15s: %(name)-32s - %(message)s"
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT)


app = Flask(__name__)


matcher = BlockHashMatcher()
start = time.time()
logging.info("Loading BlocksDB")
if os.path.exists("db/picblocksdb.json"):
    matcher.load_db("db/picblocksdb.json")
logging.info("Done! (%5.2fs)", (time.time() - start))

def render_report(report, template):
    file_name = report['input_filename']
    sha256    = report['sha256']
    bitness   = report['bitness']
    extracted = report['input_block_hashes']
    block_b   = report['input_block_bytes']
    unmatched = report['unmatched_blocks']
    unmatch_sc= report['unmatched_score']

    output = f""
    output += f"<table>\n<tr><th>#</th><th>family</th><th>direct match</th><th>libraries excluded</th><th>frequency adjusted</th><th>uniquely matched</th></tr>\n"
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
    output += "<p>results per matching class shown as (bytes, blocks, percent of bytes).<br />"
    output += "libraries excluded: filter out blocks known from a set of 3rd party libraries, including MSVC.<br />"
    output += "frequency adjusted: for the remainder, block scores are increasingly penalized when occurring in three or more families.<br />"
    output += "uniquely matched: Block score for blocks only found in this family.</p>"

    return render_template(template, file_name= file_name, sha256= sha256, bitness= bitness, extracted= extracted, unmatched= unmatched, unmatch_sc= unmatch_sc, out_html= output)

#def render_report(report):
#    output = f"<html>\n<head><title>Bextracted locksDB Results</title><style>table {{ border: 2px solid black; border-collapse: collapse; }} td,th {{ border: thin solid black; padding: 5px}} .gd {{background-color: #a6ffa6}} .gl {{background-color: #d9ffd9}} .ed {{background-color: #aaaaaa}} .el {{background-color: #cccccc}} .od {{background-color: #eeeeee}} .ol {{background-color: #f8f8f8}}</style></head>\n<body>\n"
#    output += "<h1>Malpedia BlocksDB block_b   Results</h1>\n"
#    output += (f"<p>version: v1.0.6 -unmatched  database: 2021-09-12</p>")
#    output += (f"<p>Matching against unmatch_sc{report['num_families']:,d} families with {report['num_samples']:,d} samples and a total of {report['num_blockhashes']:,d} block hashes.</p>\n")
#    output += f"<h3>Input:</h3>"
#    output += f"<table>"
#    output += f"<tr><td>file</td><td>{report['input_filename']}</td></tr>"
#    output += f"<tr><td>sha256</td><td>{report['sha256']}</td></tr>"
#    output += f"<tr><td>bitness</td><td>{report['bitness']}</td></tr>"
#    output += f"<tr><td>extracted</td><td>{report['input_block_hashes']:,d} block hashes with {report['input_block_bytes']:,d} bytes.</td></tr></table>\n"
#    output += (f"<p>Not matched: {report['unmatched_blocks']} blocks with {report['unmatched_score']:,d} bytes.</p>\n")
#    output += ("<h2>Family matches:</h2>\n")
#    output += f"<table>\n<tr><th>#</th><th>family</th><th colspan='3'>direct match</th><th colspan='3'>libraries excluded</th><th colspan='3'>frequency adjusted</th><th colspan='3'>uniquely matched</th></tr>\n"
#    index = 0
#    alternate = 0
#    for entry in report["family_matches"]:
#        dark = "ed" if alternate % 2 == 0 else "od"
#        light = "el" if alternate % 2 == 0 else "ol"
#        green = "gd" if alternate % 2 == 0 else "gl"
#        if entry['uniq_bytes'] > 0 or index < 20:
#            style20 = " style='border-bottom: 2px solid black;'" if index == 19 else ""
#            malpedia_link = f"<a href='https://malpedia.caad.fkie.fraunhofer.de/details/{entry['family']}' target='_blank'>{entry['family']}</a>"
#            output += f"<tr{style20}><td class='{light}'>{entry['index']:>5,d}</td><td class='{light}'>{malpedia_link}</td>"
#            output += f"<td class='{dark}' style='text-align:right'>{entry['direct_bytes']:,d}</td><td class='{dark}' style='text-align:right'>{entry['direct_blocks']:,d}</td><td class='{dark}' style='text-align:right'>{entry['direct_perc']:>5.2f}%</td>"
#            output += f"<td class='{light}' style='text-align:right'>{entry['nonlib_bytes']:,d}</td><td class='{light}' style='text-align:right'>{entry['nonlib_blocks']:,d}</td><td class='{light}' style='text-align:right'>{entry['nonlib_perc']:>5.2f}%</td>"
#            output += f"<td class='{dark}' style='text-align:right'>{entry['freq_bytes']:,d}</td><td class='{dark}' style='text-align:right'>{entry['freq_blocks']:5.2f}</td><td class='{dark}' style='text-align:right'>{entry['freq_perc']:>5.2f}%</td>"
#            if entry['uniq_bytes'] > 0:
#                light = green
#            output += f"<td class='{light}' style='text-align:right'>{entry['uniq_bytes']:,d}</td><td class='{light}' style='text-align:right'>{entry['uniq_blocks']:,d}</td><td class='{light}' style='text-align:right'>{entry['uniq_perc']:>5.2f}%</td></tr>"
#            alternate += 1
#        index += 1
#    output += "</table>\n"
#    output += "<p>results per matching class shown as (bytes, blocks, percent of bytes).<br />"
#    output += "libraries excluded: filter out blocks known from a set of 3rd party libraries, including MSVC.<br />"
#    output += "frequency adjusted: for the remainder, block scores are increasingly penalized when occurring in three or more families.<br />"
#    output += "uniquely matched: Block score for blocks only found in this family.</p>"
#    output += "<h2>Another one!</h2>"
#    output += """      <form action = "/blocks" method = "POST" enctype = "multipart/form-data">
#         <input type = "file" name = "binary" /><input type = "submit"/>
#         <p>optional parameters (when handling a buffer):</p>
#        <div>
#            <input type="radio" id="bit32" name="bitness" value="32" checked>
#            <label for="bit32">32bit</label>
#        </div>
#        <div>
#            <input type="radio" id="bit64" name="bitness" value="64">
#            <label for="bit64">64bit</label>
#        </div>
#        <div>
#            <input style="visibility:hidden;" type="radio" id="bit0" name="bitness" value="0" checked>
#        </div>
#        <div>
#            <label for="baseaddress">Base address:</label>
#            <input type="text" id="baseaddress" name="baseaddress"  placeholder="0x">
#        </div>
#      </form>"""
#    output += "</body></html>"
#    return output


@app.route("/")
def index():
    return render_template('index.html')

@app.route('/stats', methods=['GET'])
def get_stats():
    if request.method == 'GET':
        if db:
            f_c = f_to_id.find({}).count()
            s_c = s_to_s.find({}).count()
            b_c = blocks.find({}).count()
            cursor = s_s.find({})
            stats = list(cursor)
            return render_template('stats.html', db_online ="online", tracked_families = f_c, number_samples = s_c, number_blocks = b_c, s_stats = stats)
        else:
            return render_template('stats.html', db_online ="offline", tracked_families = "0", number_samples = "0", number_blocks = "0", s_stats = stats)

@app.route('/blocks', methods=['GET', 'POST'])
def upload_file():
    logging.info("new request to /blocks")
    if request.method == 'POST':
        f = request.files['binary']
        binary = f.read()
        logging.info(f"received binary with sha256: {hashlib.sha256(binary).hexdigest()}")
        form_bitness = int(request.form["bitness"]) if ("bitness" in request.form and request.form["bitness"] in ["32", "64"]) else None
        form_baseaddress = int(request.form["baseaddress"], 16) if ("baseaddress" in request.form and re.match("^0x[0-9a-fA-F]{1,16}$", request.form["baseaddress"])) else None
        hasher = BlockHasher()
        blockhash_report = hasher.processBuffer(binary, secure_filename(f.filename), bitness=form_bitness, baseaddress=form_baseaddress)
        report = matcher.match(blockhash_report)
        return render_report(report, "report.html")


@app.route('/api/blocks', methods=['POST'])
def upload_api_file():
    logging.info("new request to /api/blocks")
    if request.method == 'POST':
        binary = request.stream.read()
        logging.info(f"received binary with sha256: {hashlib.sha256(binary).hexdigest()}")
        hasher = BlockHasher()
        blockhash_report = hasher.processBuffer(binary, f"sha256:{hashlib.sha256(binary).hexdigest()}")
        report = matcher.match(blockhash_report)
        return jsonify(report)


if __name__ == '__main__':
    # start up server as WSGI applet through waitress
    serve(app, host="127.0.0.1", port=9001)
