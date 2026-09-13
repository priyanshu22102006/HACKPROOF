from hacksys.config import Config
from hacksys.context import ClipboardIndex, Context, FileHashIndex
from hacksys.eventlog import EventLog
from hacksys.util import normalize_code


def test_file_index_finds_duplicates():
    idx = FileHashIndex(capacity=10)
    idx.put("/a/one.py", "deadbeef")
    idx.put("/b/two.py", "deadbeef")
    assert idx.paths_with_hash("deadbeef", exclude="/a/one.py") == ["/b/two.py"]


def test_file_index_updates_on_change():
    idx = FileHashIndex(capacity=10)
    idx.put("/a/one.py", "aaa")
    idx.put("/a/one.py", "bbb")
    assert idx.paths_with_hash("aaa") == []
    assert idx.paths_with_hash("bbb") == ["/a/one.py"]


def test_clipboard_match_ignores_reformatting():
    clip = ClipboardIndex()
    body = "def add(a, b):\n    return a + b"
    clip.add({"sha256": "x", "_normalized": normalize_code(body), "_at": 0})

    reformatted = "def add(a,   b):\n\n        return a + b\n"
    hit = clip.find_in_text(normalize_code(reformatted), min_chars=10)
    assert hit is not None


def test_zone_classification(tmp_path):
    project = tmp_path / "submission"
    staging = tmp_path / "Downloads"
    project.mkdir()
    staging.mkdir()

    cfg = Config(
        home=str(tmp_path / "home"),
        project_paths=[str(project)],
        sensitive_roots=[str(staging)],
    ).normalise()
    ctx = Context(cfg, EventLog(str(tmp_path / "events.jsonl")))

    assert ctx.classify(str(project / "main.py")) == "project"
    assert ctx.classify(str(staging / "leaked.py")) == "staging"
    assert ctx.classify(str(tmp_path / "elsewhere.py")) == "elsewhere"


def test_config_template_round_trips_without_tomllib(tmp_path):
    """The fallback parser must read back exactly what `init` writes."""
    from hacksys.config import _parse_simple_toml, render_template

    cfg = Config(
        participant_id="satoru",
        team_id="nitrkl-07",
        project_paths=["/Users/x/submission", "/Users/x/api"],
        window_start="2026-09-13T09:00:00+00:00",
        window_end="2026-09-14T21:00:00+00:00",
        registered_gpg_fingerprint="3AA5C34371567BD2",
    )
    parsed = _parse_simple_toml(render_template(cfg))

    assert parsed["identity"]["participant_id"] == "satoru"
    assert parsed["window"]["window_end"] == "2026-09-14T21:00:00+00:00"
    assert parsed["paths"]["project_paths"] == ["/Users/x/submission", "/Users/x/api"]
    assert parsed["collectors"]["enable_clipboard"] is True
    assert parsed["collectors"]["clipboard_interval"] == 1.5
    assert parsed["thresholds"]["bulk_commit_lines"] == 600
