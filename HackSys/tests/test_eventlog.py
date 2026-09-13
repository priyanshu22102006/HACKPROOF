import json
import os

from hacksys.eventlog import EventLog, verify_chain
from hacksys.models import Event


def test_chain_is_intact(tmp_path):
    path = str(tmp_path / "events.jsonl")
    log = EventLog(path)
    for i in range(20):
        log.append(Event(kind="test.event", collector="t", summary=f"event {i}"))

    result = verify_chain(path)
    assert result["ok"]
    assert result["events"] == 20
    assert result["tip"] == log.tip


def test_edited_line_is_detected(tmp_path):
    path = str(tmp_path / "events.jsonl")
    log = EventLog(path)
    for i in range(5):
        log.append(Event(kind="test.event", collector="t", summary=f"event {i}"))

    lines = open(path).read().splitlines()
    rec = json.loads(lines[2])
    rec["summary"] = "tampered"
    lines[2] = json.dumps(rec)
    open(path, "w").write("\n".join(lines) + "\n")

    result = verify_chain(path)
    assert not result["ok"]
    assert any(p["issue"] == "content_modified" for p in result["problems"])


def test_deleted_line_is_detected(tmp_path):
    path = str(tmp_path / "events.jsonl")
    log = EventLog(path)
    for i in range(5):
        log.append(Event(kind="test.event", collector="t", summary=f"event {i}"))

    lines = open(path).read().splitlines()
    del lines[2]
    open(path, "w").write("\n".join(lines) + "\n")

    result = verify_chain(path)
    assert not result["ok"]
    issues = {p["issue"] for p in result["problems"]}
    assert "prev_hash_mismatch" in issues or "sequence_gap" in issues


def test_resume_continues_the_chain(tmp_path):
    path = str(tmp_path / "events.jsonl")
    first = EventLog(path)
    first.append(Event(kind="a", collector="t", summary="one"))
    tip = first.tip

    second = EventLog(path)
    assert second.tip == tip
    assert second.count == 1
    second.append(Event(kind="b", collector="t", summary="two"))

    assert verify_chain(path)["ok"]
