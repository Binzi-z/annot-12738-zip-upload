import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, "logs", "auth.log")

RULE_BY_KIND = {
    "web_scan": "web_scan",
    "webshell": "archive_webshell",
    "privilege_escalation": "privilege_escalation",
}


def run(tmp_path, log=LOG):
    out = tmp_path / "out.json"
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "detector", "detector.py"), log, str(out)],
        capture_output=True, text=True,
    )
    return r, out


def load(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text(encoding="utf-8"))


def test_corpus_and_labels():
    assert os.path.exists(LOG)
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    assert len(data["events"]) == 3


def test_detector_runs(tmp_path):
    r, out = run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "findings" in json.loads(out.read_text(encoding="utf-8"))


def test_findings_have_required_fields(tmp_path):
    for f in load(tmp_path)["findings"]:
        for key in ("rule", "first_seen", "last_seen", "entities", "evidence"):
            assert f.get(key), (key, f)
        assert f["first_seen"] <= f["last_seen"]
        assert all("line" in e and "ts" in e for e in f["evidence"])


def test_labels_all_hit(tmp_path):
    findings = load(tmp_path)["findings"]
    with open(os.path.join(ROOT, "labels.json"), encoding="utf-8") as fh:
        labels = json.load(fh)["events"]
    for lab in labels:
        rule = RULE_BY_KIND[lab["kind"]]
        matches = [f for f in findings if f["rule"] == rule]
        assert matches, lab
        ent = matches[0]["entities"]
        if "ip" in lab:
            assert lab["ip"] == ent.get("ip"), (lab, ent)
        if "user" in lab:
            assert lab["user"] == ent.get("user"), (lab, ent)


def test_no_false_positives(tmp_path):
    findings = load(tmp_path)["findings"]
    assert len(findings) == 3
    # benign look-alikes: 2 denied probes, failed logins then success
    flagged = {f["entities"].get("ip") for f in findings}
    assert "10.20.1.88" not in flagged
    assert "10.20.1.77" not in flagged


def test_webshell_timeline(tmp_path):
    findings = load(tmp_path)["findings"]
    f = next(f for f in findings if f["rule"] == "archive_webshell")
    stages = [t["stage"] for t in f["timeline"]]
    assert stages == ["upload", "extract", "access"]
    assert f["timeline"][0]["archive"] == "/upload.php"
    assert f["timeline"][1]["path"] == "/uploads/"
    assert f["timeline"][2]["file"] == "/uploads/shell.php"
    assert f["timeline"][2]["query"] == "cmd=id"


def test_partial_chain_goes_to_needs_review(tmp_path):
    log = tmp_path / "partial.log"
    log.write_text(
        'Oct 01 08:00:00 web01 nginx: 10.9.9.9 - - "/upload.php" 200 100 "UA"\n'
        'Oct 01 08:05:00 web01 nginx: 10.8.8.8 - - "/uploads/evil.php?cmd=id" 200 100 "UA"\n',
        encoding="utf-8")
    r, out = run(tmp_path, str(log))
    assert r.returncode == 0, r.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["findings"] == []
    assert len(data["needs_review"]) == 2
    assert all(x["missing"] for x in data["needs_review"])


def test_benign_image_archive_no_alert(tmp_path):
    log = tmp_path / "benign.log"
    log.write_text(
        'Oct 01 08:00:00 web01 nginx: 10.9.9.9 - - "/upload.php" 200 100 "UA"\n'
        'Oct 01 08:00:10 web01 nginx: 10.9.9.9 - - "/uploads/pic.png" 200 100 "UA"\n'
        'Oct 01 08:00:20 web01 nginx: 10.9.9.9 - - "/uploads/doc.pdf" 200 100 "UA"\n',
        encoding="utf-8")
    r, out = run(tmp_path, str(log))
    assert r.returncode == 0, r.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["findings"] == []


def test_empty_log_yields_no_findings(tmp_path):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    r, out = run(tmp_path, str(empty))
    assert r.returncode == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["findings"] == []
    assert data["needs_review"] == []
