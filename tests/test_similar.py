"""Duplicate-tool detection tests: behavioral similarity (no srt needed)."""
import json
import pathlib

from attest import similar


def _mk(tools_dir: pathlib.Path, name: str, desc: str, cmd: str,
        doms: list[str], allow: list[str]) -> None:
    d = tools_dir / name
    d.mkdir()
    (d / "tool.yaml").write_text(
        f"name: {name}\ndescription: {desc}\ncommand: {cmd}\n"
        f"claims:\n  origin: operator-approved\n  allow: [{', '.join(allow)}]\n"
        f"  deny: [exec]\nsandbox:\n  srt_settings: srt-settings.json\n")
    (d / "srt-settings.json").write_text(json.dumps({
        "network": {"allowedDomains": doms},
        "filesystem": {"allowWrite": ["/tmp"]}}))


def test_detects_same_endpoint_duplicates(tmp_path):
    _mk(tmp_path, "us-quote", "US stock real-time quotes via Yahoo Finance",
        "python3 q.py", ["query1.finance.yahoo.com"], ["network", "stdout", "exit"])
    _mk(tmp_path, "stocks-fast", "Realtime US stock quotes (Yahoo Finance)",
        "python3 f.py", ["query1.finance.yahoo.com"], ["network", "stdout", "exit"])
    _mk(tmp_path, "sha-tool", "SHA-256 of input string", "sh sha.sh", [], ["stdout", "exit"])

    pairs = similar.find_duplicates(tmp_path)
    # 同一域名 = 强信号;无关工具 = 无配对
    assert len(pairs) == 1
    assert {pairs[0]["a"], pairs[0]["b"]} == {"us-quote", "stocks-fast"}
    assert "query1.finance.yahoo.com" in pairs[0]["why"]
    assert pairs[0]["similarity"] >= 0.5


def test_jaccard_bounds():
    assert similar.jaccard({"a"}, {"a", "b"}) == 0.5
    assert similar.jaccard(set(), set()) == 0.0
    assert similar.jaccard({"x"}, {"x"}) == 1.0


def test_no_false_positive_across_unrelated(tmp_path):
    _mk(tmp_path, "sha-tool", "SHA-256 of input", "sh sha.sh", [], ["stdout", "exit"])
    _mk(tmp_path, "fx-rate", "Currency conversion open.er-api.com", "python3 f.py",
        ["open.er-api.com"], ["network", "stdout"])
    _mk(tmp_path, "cache-tool", "Append line to cache.log", "sh c.sh", [], ["stdout", "file-write"])
    assert similar.find_duplicates(tmp_path) == []