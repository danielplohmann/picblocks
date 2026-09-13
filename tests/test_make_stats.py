import json
import os

import utils.make_stats as make_stats


def test_persist_stats_without_mongo_writes_json(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    make_stats.s_s = None
    make_stats.m_s = None
    make_stats.family_verified_frequency = {"win.foo": 1}
    make_stats.family_verified_vs_detected = {"win.foo": {"win.foo": 1}}
    make_stats.persist_stats()
    stats_path = tmp_path / "db" / "stats.json"
    assert stats_path.is_file()
    payload = json.loads(stats_path.read_text())
    assert payload["family_verified_frequency"]["win.foo"] == 1


def test_persist_matching_report_without_mongo_does_not_raise():
    make_stats.m_s = None
    make_stats.persist_matching_report({"family_matches": []})


def test_readme_and_makefile_use_picblocks_package():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    readme = open(os.path.join(root, "README.md"), encoding="utf-8").read()
    makefile = open(os.path.join(root, "Makefile"), encoding="utf-8").read()
    assert "python -m picblocks.blockhashmatcher" in readme
    assert "python -m blocks.blockhashmatcher" not in readme
    assert "python -m utils.make_stats" in readme
    assert "python -m utils.make_stats.py" not in readme
    assert "pytest tests" in makefile
    assert "--rcfile=.pylintrc picblocks" in makefile
    assert "nose" not in makefile
    setup = open(os.path.join(root, "setup.py"), encoding="utf-8").read()
    assert "smda>=4.2.13" in setup
    requirements = open(os.path.join(root, "requirements.txt"), encoding="utf-8").read()
    assert "smda>=4.2.13" in requirements
    assert "smda==1.12.7" not in requirements


def test_import_db_missing_file_returns_false(tmp_path):
    from utils.import_picblocksdb_to_mongo import import_db

    assert import_db(db_path=str(tmp_path / "nonexistent.json")) is False
