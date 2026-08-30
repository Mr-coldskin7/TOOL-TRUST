#!/usr/bin/env python3
"""repo-stats：仓库概览（纯文件扫描，file-read only，不 exec git）。

用法：python3 repo_stats.py [ROOT]   默认 /repo（体检挂载），否则当前目录。
输出：文件数/行数/TODO-FIXME 密度/测试文件数/文件类型 Top 10。有上限防失控。
"""
import json
import pathlib
import sys

SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".obs", ".pytest_cache", "dist", "build", ".next", "target"}
SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".pyc", ".woff2", ".zip", ".bin", ".class", ".jar"}
MAX_FILES = 4000
MAX_LINES_PER_FILE = 5000


def scan(root: pathlib.Path) -> dict:
    files = 0
    lines = 0
    todo = 0
    tests = 0
    by_ext: dict[str, int] = {}
    total_bytes = 0
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        rel = p.relative_to(root)
        if any(part in SKIP_DIRS for part in rel.parts[:-1]):
            continue
        if p.suffix.lower() in SKIP_EXTS:
            continue
        files += 1
        if files > MAX_FILES:
            break
        total_bytes += p.stat().st_size
        ext = p.suffix.lower() or "(none)"
        by_ext[ext] = by_ext.get(ext, 0) + 1
        if "test" in p.name.lower() or p.name.startswith("test_"):
            tests += 1
        try:
            n = 0
            for i, line in enumerate(p.open("r", errors="ignore")):
                if i >= MAX_LINES_PER_FILE:
                    break
                n += 1
                low = line.lower()
                if "todo" in low or "fixme" in low or "hack" in low:
                    todo += 1
            lines += n
        except OSError:
            pass
    top = sorted(by_ext.items(), key=lambda kv: -kv[1])[:10]
    return {
        "root": str(root),
        "files": min(files, MAX_FILES),
        "total_lines": lines,
        "todo_fixme": todo,
        "test_files": tests,
        "total_bytes_mb": round(total_bytes / 1048576, 2),
        "top_extensions": dict(top),
    }


def main() -> int:
    root = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if root is None:
        repo = pathlib.Path("/repo")
        root = repo if repo.is_dir() else pathlib.Path(".")
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 1
    print(json.dumps(scan(root), ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
