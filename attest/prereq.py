"""运行前置条件(requires)：上岗前硬校验 + 从观察事件自动推断。

分工（与 claims 平行）：
  claims        = 工具"会做什么"副作用        （体检阶段对账）
  requires      = 工具"要什么"才能正确运行     （上岗前 pre-flight，缺一 abort）
  consequences  = 工具在宿主会"动哪些路径"      （框架物理隔离据此强制 scope）

硬校验是确定性逻辑：缺任一前置 → 返回 missing 列表(非空即失败)。
默认拒绝：requires 缺失只说明"现在跑不能保证正确"，不浪费 token/算力硬上。
"""
import os
import pathlib
import re
import shutil

# ---- 运行时系统噪音：自动推断 requires 时排除，不当作 host 依赖 ----
NOISE_PREFIXES = (
    "/etc/ld.so",
    "/etc/localtime",
    "/etc/machine-id",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/usr/lib",
    "/usr/share/zoneinfo",
    "/usr/lib64",
    "/lib64",
    "/lib/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/var/lib/dpkg",
    # 容器内观察路径（/src = 工具源码挂载点），不属于 host 前置依赖
    "/src",
    # python 解释器运行时内部（stdlib/site-packages/解释器查找），不是 host 前置依赖
    "/usr/bin/python3",
    "/usr/local/bin/python3",
    "/usr/local/sbin/python3",
    "/usr/sbin/python3",
    "/usr/local/lib/python3",
    "/usr/lib/python3",
    "/usr/bin/lib/python3",
    "/root/.local",
    "/etc/hosts",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/usr/share/locale",
)
# 工具自己的编译产物/工具链，不当作 host exec 依赖
_TOOLCHAIN = ("g++", "gcc", "cc", "ld", "as", "make", "clang", "clang++")

_PATH_RE = re.compile(r'"([^"]*)"')

# 参数里首项(或含)真实路径的 syscall；read/write 的 args 是
# fd + 缓冲区内容(含引号字符串)，不是路径，必须排除，否则读到 ELF 魔数。
_PATH_SYSCALLS = {
    "open", "openat", "openat2", "creat",
    "access", "faccessat", "faccessat2",
    "stat", "fstat", "lstat", "newfstatat", "statx",
    "unlink", "unlinkat", "mkdir", "mkdirat", "rmdir",
    "rename", "renameat", "renameat2", "truncate", "ftruncate",
    "chmod", "fchmod", "chown", "fchown", "symlink", "mknod",
}


# ---------- 硬校验 ----------

def _resolve(base: pathlib.Path, p: str) -> pathlib.Path:
    return pathlib.Path(p) if os.path.isabs(p) else base / p


def validate_requires(requires: dict | None, cwd: str | None = None) -> list[dict]:
    """校验 requires 是否满足。返回 missing 列表；空 = 全部满足(可通过)。

    每一项代表一个前置缺失，含 kind + 具体定位，供 agent 补齐环境而非硬跑。
    """
    missing: list[dict] = []
    base = pathlib.Path(cwd) if cwd else pathlib.Path.cwd()
    req = requires or {}

    for var in req.get("env") or []:
        if not os.environ.get(var):
            missing.append(
                {"kind": "env", "name": var, "detail": f"environment variable {var} is not set"}
            )

    for p in req.get("files") or []:
        if not _resolve(base, p).exists():
            missing.append({"kind": "file", "name": p, "detail": f"missing file/dir: {p}"})

    for exe in req.get("exec") or []:
        if shutil.which(exe) is None:
            missing.append(
                {"kind": "exec", "name": exe, "detail": f"executable not on PATH: {exe}"}
            )

    if req.get("cwd"):
        cd = _resolve(base, req["cwd"])
        if not cd.is_dir():
            missing.append(
                {"kind": "cwd", "name": req["cwd"], "detail": f"working dir not found: {req['cwd']}"}
            )

    for w in req.get("writable") or []:
        wp = _resolve(base, w)
        if not wp.exists():
            missing.append({"kind": "writable", "name": w, "detail": f"writable dir missing: {w}"})
        elif not os.access(wp, os.W_OK):
            missing.append(
                {"kind": "writable", "name": w, "detail": f"dir not writable: {w}"}
            )

    return missing


def hard_check(requires: dict | None, cwd: str | None = None) -> dict:
    """硬性拒绝包装：缺任一前置 → verdict fail + missing 列表。"""
    missing = validate_requires(requires, cwd)
    return {
        "requires": requires or {},
        "missing": missing,
        "verdict": "fail" if missing else "pass",
        "note": (
            "pre-flight aborted: missing prerequisite(s), refusing to run "
            "(avoid wasting tokens/compute)" if missing else "all prerequisites present"
        ),
    }


# ---------- 从观察事件自动推断 ----------

def _quoted_path(args: str) -> str | None:
    m = _PATH_RE.search(args or "")
    return m.group(1) if m else None


def _is_noise(p: str) -> bool:
    return any(p.startswith(n) for n in NOISE_PREFIXES)


def infer_requires(events: list[dict]) -> dict:
    """从观察事件推断 requires。best-effort：只抓真实数据/输入依赖，滤掉系统噪音。

    - file-read 打开的真实路径  → files（工具要读的本地文件/输入）
    - execve 的二进制           → exec（依赖的可执行）
    - 工具自己的 exec 二进制(编译产物/工具链)排除
    - env：strace 观察不到环境变量名，推断不了，留空由作者手填
    - writable：调用方把 file-write 白名单路径传进来，见 infer_requires_full()
    """
    files: set[str] = set()
    exes: set[str] = set()

    for e in events:
        c = e.get("class")
        if c == "file-read":
            if e.get("syscall") not in _PATH_SYSCALLS:
                continue  # read/readv 内容是缓冲区，不是路径
            p = _quoted_path(e.get("args") or "")
            if p and not _is_noise(p):
                files.add(p)
        elif c == "exec":
            p = _quoted_path(e.get("args") or "")
            if p and not p.endswith(_TOOLCHAIN):
                # exec 只滤工具链；解释器/真实子进程二进制是有意义的前置，不滤系统噪音
                exes.add(p)

    return {"env": [], "files": sorted(files), "exec": sorted(exes)}


def infer_requires_full(events: list[dict], writable_paths: list[str]) -> dict:
    """推断 requires + 把 file-write 白名单路径并进 writable（工具要在宿主可写这些区）。"""
    req = infer_requires(events)
    req["writable"] = sorted(set(req.get("writable") or []) | set(writable_paths or []))
    return req
