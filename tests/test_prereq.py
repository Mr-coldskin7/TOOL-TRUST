import os
import pathlib

from attest.prereq import (
    hard_check,
    infer_requires,
    infer_requires_full,
    validate_requires,
)

REQ = {
    "env": ["PDF_ENGINE"],
    "files": ["input/report.pdf"],
    "exec": ["python3"],
    "cwd": ".",
    "writable": ["out"],
}


def test_all_present_passes(monkeypatch, tmp_path):
    monkeypatch.setenv("PDF_ENGINE", "xelatex")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "input").mkdir()
    (tmp_path / "input" / "report.pdf").write_text("x")
    (tmp_path / "out").mkdir()
    (tmp_path / "out").chmod(0o755)
    assert validate_requires(REQ, cwd=str(tmp_path)) == []
    assert hard_check(REQ, cwd=str(tmp_path))["verdict"] == "pass"


def test_missing_env_detected(monkeypatch):
    monkeypatch.delenv("PDF_ENGINE", raising=False)
    missing = validate_requires({"env": ["PDF_ENGINE"]})
    assert len(missing) == 1
    assert missing[0]["kind"] == "env"
    assert missing[0]["name"] == "PDF_ENGINE"


def test_missing_file_detected(tmp_path):
    missing = validate_requires({"files": ["nope.txt"]}, cwd=str(tmp_path))
    assert len(missing) == 1
    assert missing[0]["kind"] == "file"


def test_missing_exec_detected(monkeypatch):
    # 强制 PATH 为空，python3 应找不到
    monkeypatch.setenv("PATH", "/nonexistent")
    missing = validate_requires({"exec": ["python3"]})
    assert any(m["kind"] == "exec" for m in missing)


def test_missing_cwd_detected(tmp_path):
    missing = validate_requires({"cwd": "no_such_dir"}, cwd=str(tmp_path))
    assert any(m["kind"] == "cwd" for m in missing)


def test_not_writable_dir_detected(tmp_path, monkeypatch):
    if os.geteuid() == 0:
        return  # root 能写任何目录，跳过
    d = tmp_path / "ro"
    d.mkdir()
    d.chmod(0o555)
    missing = validate_requires({"writable": ["ro"]}, cwd=str(tmp_path))
    assert any(m["kind"] == "writable" for m in missing)
    d.chmod(0o755)


def test_empty_requires_passes():
    assert validate_requires(None) == []
    assert validate_requires({}) == []
    assert hard_check({})["verdict"] == "pass"


def test_hard_check_fail_is_default_reject():
    r = hard_check({"env": ["DOES_NOT_EXIST_XYZ"]})
    assert r["verdict"] == "fail"
    assert r["missing"]


# ---- infer_requires：滤系统噪音 ----

def _ev(class_, args, syscall="openat"):
    return {"class": class_, "syscall": syscall, "args": args}


def test_infer_filters_system_noise():
    events = [
        _ev("file-read", 'AT_FDCWD, "/etc/ld.so.cache", O_RDONLY'),   # 噪音
        _ev("file-read", 'AT_FDCWD, "/usr/lib/libc.so.6", O_RDONLY'),  # 噪音
        _ev("file-read", 'AT_FDCWD, "./input/report.pdf", O_RDONLY'),  # 真实输入
        _ev("file-read", '"/etc/passwd", O_RDONLY'),                 # 真实配置
        _ev("exec", '"./tool", ["tool"]', syscall="execve"),                # 工具自身,排除
        _ev("exec", '"/usr/bin/python3", ["python3"]', syscall="execve"),    # 真实子进程
    ]
    req = infer_requires(events)
    assert "./input/report.pdf" in req["files"]
    assert "/etc/passwd" in req["files"]
    assert "/etc/ld.so.cache" not in req["files"]
    assert "/usr/lib/libc.so.6" not in req["files"]
    assert "python3" not in req["files"]  # 不把 exec 当 file
    assert not any(f.endswith("/tool") for f in req["files"])
    assert any(x.endswith("python3") for x in req["exec"])


def test_infer_requires_full_adds_writable():
    req = infer_requires_full([], ["/tmp/out"])
    assert req["writable"] == ["/tmp/out"]


def test_infer_ignores_read_buffer_content():
    # read(fd, \"\177ELF...\", 832) 的 args 是缓冲区内容，不是路径，必须排除
    events = [_ev("file-read", '3, "\\177ELF\\2\\1\\1\\0", 832', syscall="read"),
              _ev("file-read", 'AT_FDCWD, "/input/data.bin", O_RDONLY')]
    req = infer_requires(events)
    assert "/input/data.bin" in req["files"]
    assert not any(f.startswith("\\177") for f in req["files"])
    assert len(req["files"]) == 1
