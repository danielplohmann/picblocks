from io import BytesIO

import pytest

from app import app as flask_app
from app import render_report


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as client:
        yield client


def test_index_does_not_default_hidden_zero_bitness(client):
    html = client.get("/").get_data(as_text=True)
    assert 'id="bit0"' not in html
    assert 'value="0"' not in html
    assert 'id="bit32"' in html
    assert 'id="bit64"' in html
    assert 'checked' not in html.split('id="bit32"', 1)[1].split(">", 1)[0]


def test_report_renders_extracted_byte_count():
    report = {
        "input_filename": "sample.exe",
        "sha256": "ab" * 32,
        "bitness": 32,
        "input_block_hashes": 3,
        "input_block_bytes": 48,
        "unmatched_blocks": 1,
        "unmatched_score": 16,
        "family_matches": [
            {
                "index": 1,
                "family": "win.emotet",
                "direct_bytes": 32,
                "direct_blocks": 2,
                "direct_perc": 66.66,
                "nonlib_bytes": 32,
                "nonlib_blocks": 2,
                "nonlib_perc": 66.66,
                "freq_bytes": 32,
                "freq_blocks": 2,
                "freq_perc": 66.66,
                "uniq_bytes": 16,
                "uniq_blocks": 1,
                "uniq_perc": 33.33,
            }
        ],
    }
    with flask_app.app_context():
        html = render_report(report, "report.html")
    assert "3 block hashes with 48 bytes." in html


def test_report_escapes_hostile_family_names():
    report = {
        "input_filename": "sample.exe",
        "sha256": "ab" * 32,
        "bitness": 32,
        "input_block_hashes": 1,
        "input_block_bytes": 16,
        "unmatched_blocks": 0,
        "unmatched_score": 0,
        "family_matches": [
            {
                "index": 1,
                "family": "<script>alert(1)</script>",
                "direct_bytes": 16,
                "direct_blocks": 1,
                "direct_perc": 100.0,
                "nonlib_bytes": 16,
                "nonlib_blocks": 1,
                "nonlib_perc": 100.0,
                "freq_bytes": 16,
                "freq_blocks": 1,
                "freq_perc": 100.0,
                "uniq_bytes": 16,
                "uniq_blocks": 1,
                "uniq_perc": 100.0,
            }
        ],
    }
    with flask_app.app_context():
        html = render_report(report, "report.html")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def _empty_blockhash_report(filename, bitness=None):
    return {
        "family": "",
        "version": None,
        "bitness": bitness,
        "sha256": "ab" * 32,
        "filename": filename,
        "filesize": 1,
        "is_library": False,
        "block_bytes": 0,
        "blockhashes": {},
        "num_hashes": 0,
    }


def test_blocks_form_passes_baseaddress_zero(monkeypatch, client):
    captured = {}

    def fake_process(self, buffer, filename, bitness=None, baseaddress=None):
        captured["bitness"] = bitness
        captured["baseaddress"] = baseaddress
        return _empty_blockhash_report(filename, bitness)

    monkeypatch.setattr("app.BlockHasher.processBuffer", fake_process)
    response = client.post(
        "/blocks",
        data={
            "binary": (BytesIO(b"MZ"), "payload.bin"),
            "baseaddress": "0x0",
            "bitness": "32",
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert captured["baseaddress"] == 0
    assert captured["bitness"] == 32


def test_blocks_form_without_bitness_does_not_send_zero(monkeypatch, client):
    captured = {}

    def fake_process(self, buffer, filename, bitness=None, baseaddress=None):
        captured["bitness"] = bitness
        captured["baseaddress"] = baseaddress
        return _empty_blockhash_report(filename, bitness)

    monkeypatch.setattr("app.BlockHasher.processBuffer", fake_process)
    response = client.post(
        "/blocks",
        data={"binary": (BytesIO(b"MZ"), "payload.bin")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert captured["bitness"] is None
    assert captured["baseaddress"] is None


def test_stats_route_is_disabled_without_mongo(client):
    html = client.get("/stats").get_data(as_text=True)
    assert "disabled" in html.lower()


def test_api_blocks_reports_unmatched_hashes(monkeypatch, client):
    def fake_process(self, buffer, filename, bitness=None, baseaddress=None):
        return {
            "family": "",
            "version": None,
            "bitness": 32,
            "sha256": "ab" * 32,
            "filename": filename,
            "filesize": 1,
            "is_library": False,
            "block_bytes": 16,
            "blockhashes": {1: {16: [0]}},
            "num_hashes": 1,
        }

    monkeypatch.setattr("app.BlockHasher.processBuffer", fake_process)
    response = client.post("/api/blocks", data=b"MZ")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["unmatched_hashes"] == 1
    assert payload["unmatched_blocks"] == 1
    assert payload["unmatched_score"] == 16


def test_stats_template_uses_injected_data_not_fixture():
    with flask_app.app_context():
        html = flask_app.jinja_env.get_template("stats.html").render(
            db_online="online",
            tracked_families=2,
            number_samples=4,
            number_blocks=8,
            s_stats=[
                {
                    "family_verified_frequency": {"win.foo": 2},
                    "family_verified_vs_detected": {"win.foo": {"win.foo": 1}},
                }
            ],
        )
    assert "s_stats.js" not in html
    assert "win.foo" in html
    assert "Tracked Families" in html
    assert ">2<" in html


def test_blocks_get_returns_index(client):
    response = client.get("/blocks")
    assert response.status_code == 200
    assert "Malpedia BlocksDB" in response.get_data(as_text=True)


def test_blocks_post_empty_or_missing_file_returns_index(client):
    res1 = client.post("/blocks", data={}, content_type="multipart/form-data")
    assert res1.status_code == 200
    res2 = client.post("/blocks", data={"binary": (BytesIO(b""), "")}, content_type="multipart/form-data")
    assert res2.status_code == 200


def test_api_blocks_empty_payload_returns_400(client):
    response = client.post("/api/blocks", data=b"")
    assert response.status_code == 400
    assert response.get_json()["error"] == "Empty or missing request payload"


def test_api_blocks_accepts_query_parameters(monkeypatch, client):
    captured = {}

    def fake_process(self, buffer, filename, bitness=None, baseaddress=None):
        captured["filename"] = filename
        captured["bitness"] = bitness
        captured["baseaddress"] = baseaddress
        return _empty_blockhash_report(filename, bitness)

    monkeypatch.setattr("app.BlockHasher.processBuffer", fake_process)
    response = client.post(
        "/api/blocks?bitness=64&baseaddress=0x140000000&filename=sample.bin",
        data=b"MZ\x00\x00",
    )
    assert response.status_code == 200
    assert captured["filename"] == "sample.bin"
    assert captured["bitness"] == 64
    assert captured["baseaddress"] == 0x140000000


def test_stats_route_uses_stats_json_fallback(tmp_path, monkeypatch, client):
    stats_file = tmp_path / "stats.json"
    stats_file.write_text('{"family_verified_frequency": {"win.test": 1}, "family_verified_vs_detected": {}}')
    monkeypatch.setattr("os.path.exists", lambda p: True if p == "db/stats.json" else False)
    monkeypatch.setattr("builtins.open", lambda p, *args, **kwargs: stats_file.open("r") if p == "db/stats.json" else open(p, *args, **kwargs))
    response = client.get("/stats")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "offline (cached)" in html

