"""Static sniff (SAST-lite): scan a tool's SOURCE before it is approved.

Fills the honest gap of first-connect: dynamic scan (srt --scan) says what the
tool NEEDED at runtime; static sniff says what the code CONTAINS — two
independent evidence channels for the human's review. Findings are advisory,
never a verdict: empire rules belong to the operator at --approve time.

Backends:
  - python: built-in AST walk (no deps): eval/exec/compile, os.system/popen,
    subprocess, network libs, write-to-path, dynamic patterns
  - shell  : shellcheck when available, else a small built-in pattern set
Findings are recorded per severity (high/medium/info) with line + snippet.
"""
import ast
import pathlib
import shutil
import subprocess

# python dangerous call targets → (class, severity)
_PY_RULES: dict[str, tuple[str, str]] = {
    "eval": ("exec", "medium"),
    "exec": ("exec", "medium"),
    "compile": ("exec", "medium"),
    "os.system": ("exec", "high"),
    "os.popen": ("exec", "high"),
    "subprocess.call": ("exec", "medium"),
    "subprocess.run": ("exec", "medium"),
    "subprocess.Popen": ("exec", "medium"),
    "subprocess.check_call": ("exec", "medium"),
    "subprocess.check_output": ("exec", "medium"),
    "socket.socket": ("network", "info"),
    "http.client.HTTPConnection": ("network", "info"),
    "urllib.request.urlopen": ("network", "info"),
    "requests.get": ("network", "info"),
    "requests.post": ("network", "info"),
    "open": ("file-write", "info"),  # mode decides; recorded for review
}

_OPEN_WRITE_MODES = {"w", "wb", "a", "ab", "x", "xb", "w+", "a+"}
_OPEN_SHADY = ("~/.", "/etc/", "/Users/", "/home/", ".env", ".ssh", ".git/")


def _py_findings(source: str) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [{"severity": "high", "rule": "syntax",
                 "line": 1, "code": "unparseable source"}]
    findings: list[dict] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = getattr(node.func, "attr", "")
            obj = getattr(node.func, "value", None)
            name = ""
            if isinstance(obj, ast.Name):
                name = obj.id
            target = f"{name}.{attr}" if name else attr
            kind, sev = _PY_RULES.get(target, (None, None))
            if kind is None and target == "open" and not isinstance(obj, ast.Name):
                kind, sev = ("file-write", "info")
            if kind:
                sni = _snippet(source, node.lineno)
                if target in ("eval", "exec", "compile", "os.system", "os.popen"):
                    kind, sev = "exec", "medium" if target in (
                        "eval", "exec", "compile") else "high"
                findings.append({
                    "severity": sev, "rule": kind, "target": target,
                    "line": node.lineno, "code": sni})
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id
            if name == "open":
                mode = _open_mode(node.args)
                path = _open_path(node.args, source)
                sev = "high" if (_open_is_write(mode) and any(
                    s in (path or "") for s in _OPEN_SHADY)) else "info"
                findings.append({
                    "severity": sev, "rule": "file-write", "target": "open",
                    "line": node.lineno, "code": _snippet(source, node.lineno)})
            elif name in _PY_RULES:
                kind, sev = _PY_RULES[name]
                findings.append({
                    "severity": sev, "rule": kind, "target": name,
                    "line": node.lineno, "code": _snippet(source, node.lineno)})
    return findings


def _open_args(args: list) -> tuple[str, str]:
    path = mode = ""
    if args:
        try:
            path = ast.literal_eval(args[0]) if args[0] else ""
        except Exception:
            path = ""
    if len(args) > 1:
        try:
            mode = ast.literal_eval(args[1]) if args[1] else ""
        except Exception:
            mode = ""
    return str(path), str(mode)


def _open_mode(args: list) -> str:
    return _open_args(args)[1]


def _open_path(args: list, source: str) -> str:
    return _open_args(args)[0]


def _open_is_write(mode: str) -> bool:
    return any(m in mode for m in ("w", "a", "x", "+"))


def _snippet(source: str, lineno: int) -> str:
    try:
        return source.splitlines()[lineno - 1].strip()[:90]
    except Exception:
        return ""


_SH_BAITS = (
    "curl ", "wget ", "nc ", "base64 -d", "eval ", "exec ", "| sh", "> /etc/",
    "> /Users/", "> ~/", ".ssh", ".env", "chmod 777", "sudo ",
)
_SH_RULES = dict(
    curl="network", wget="network", nc="network",
    base64="obfuscation", eval="exec", exec="exec",
    ssh="secret-access", env="secret-access",
    etc="write-etc", sudo="privilege",
)


def _sh_findings(source: str) -> list[dict]:
    findings: list[dict] = []
    for i, line in enumerate(source.splitlines(), start=1):
        low = line.lower()
        for bait in _SH_BAITS:
            if bait in low:
                rule = next((r for r in _SH_RULES if r in low), "pattern")
                findings.append({"severity": "info", "rule": rule,
                                 "target": bait.strip(), "line": i,
                                 "code": line.strip()[:90]})
                break
    return findings


def scan_static(tool_dir: pathlib.Path, command: str | None = None) -> list[dict]:
    """Static findings for a tool's primary source file (from its command).

    Args:
      tool_dir: tool directory.
      command:  tool.yaml 'command' (e.g. 'python3 fetch.py'); resolved to a
                relative source when possible.

    Returns:
      List of {"severity", "rule", "target", "line", "code"} (may be empty).
    """
    cmd_parts = (command or "").split()
    source_rel = None
    for part in cmd_parts:
        if part.endswith((".py", ".sh")):
            source_rel = part
            break
    if not source_rel:
        py_files = sorted(tool_dir.glob("*.py"))
        sh_files = sorted(tool_dir.glob("*.sh"))
        if py_files:
            source_rel, is_sh = py_files[0].name, False
        elif sh_files:
            source_rel, is_sh = sh_files[0].name, True
        else:
            return []
    else:
        is_sh = source_rel.endswith(".sh")
    src = pathlib.Path(tool_dir) / source_rel
    if not src.exists():
        return []
    source = src.read_text(errors="replace")

    if is_sh:
        sc = shutil.which("shellcheck")
        if sc:
            r = subprocess.run([sc, "-f", "json", str(src)],
                               capture_output=True, text=True, timeout=30)
            try:
                import json
                comments = json.loads(r.stdout or "[]")
                findings = []
                for c in comments:
                    findings.append({
                        "severity": c.get("level", "info"),
                        "rule": "shellcheck:" + c.get("code", "0"),
                        "target": c.get("rule", ""),
                        "line": c.get("line", 0),
                        "code": (c.get("message", "") or "")[:90]})
                return findings
            except Exception:
                pass
        return _sh_findings(source)

    bandit = shutil.which("bandit")
    if bandit:
        import json as _json
        r = subprocess.run(
            [bandit, "-q", "-f", "json", str(src)],
            capture_output=True, text=True, timeout=60)
        try:
            data = _json.loads(r.stdout)
            findings = []
            for r_ in data.get("results", []):
                findings.append({
                    "severity": r_.get("issue_severity", "info"),
                    "rule": "bandit:" + r_.get("test_id", "?"),
                    "target": r_.get("test_name", ""),
                    "line": r_.get("line_number", 0),
                    "code": (r_ .get("code", "") or "")[:90]})
            return findings
        except Exception:
            pass
    return _py_findings(source)