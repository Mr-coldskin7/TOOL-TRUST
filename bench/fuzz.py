"""bench/fuzz.py — 对抗随机语料生成器(把基准从 22 个手写 case 扩到上千个)。

为什么 ground truth 能独立于管道(这是 fuzz 可信的关键):
  - claims   由「声明侧」派生:工具说自己会做什么
  - strace  由「行为侧」合成:工具实际做什么
  - label   由「意图级」判定:每条行为副作用有没有被声明覆盖
  —— 三者互不共用逻辑。因此 fuzz 能暴露纯实现缺陷:
     意图合规但事件被误判 → FP(如 fd 路由错、mode 解析错、路径归一化漏)
     意图越界但事件被漏判 → FN。

对抗维度:
  - 类撒谎  dropped:副作用类完全没在 claims 里(既不在 allow 也不在 deny)
  - 范围撒谎 out-of-scope:路径在白名单外 / 模式越权(声明 create 实为 O_TRUNC)
            / 网络目标 IP 不在声明 hosts
  - 组合    每个 case 1-4 个不同副作用(fork 子进程、读写混合、网络+读文件外传)
  - 干扰    同一意图不同写法(fd 顺序、close/不 close),不变 ground truth

用法:rng(seed) 驱动全部生成,同 seed 完全可复现。
"""
import posixpath
import random
from dataclasses import dataclass, field

from bench.corpus import Case, S

WRITE_INSIDE = ["/tmp", "/tmp/sub"]
WRITE_OUTSIDE = ["/etc", "/var/log", "/usr/local/bin"]
NET_INSIDE = [("1.2.3.4", 443), ("10.0.0.5", 8080), ("203.0.113.9", 80)]
NET_OUTSIDE = [("8.8.8.8", 443), ("5.6.7.8", 9999), ("192.168.1.50", 22)]
BINARIES = ["/bin/sh", "/usr/bin/curl", "/usr/bin/python3"]
SIDE_CLASSES = ["file-write", "file-read", "network", "exec", "perms", "process"]
FIRST_LINE = S(99, "getpid", "", "99")  # 放首位,避免首条 execve 被 _drop_launch_execve 吃掉


@dataclass
class Fx:
    kind: str                    # 副作用类
    truth_ok: bool               # 意图级:行为是否被声明覆盖 (ground truth)
    effect: dict = field(default_factory=dict)  # 行为侧参数(合成 strace 用)


def _op_write(rng) -> Fx:
    """file-write:随机 类撒谎/范围撒谎/模式越权/正常。effect['dir'] 是行为目录。"""
    # 先决定是否为「撒谎工具」(对整个 class 都没声明)
    if rng.random() < 0.18:
        d = {"dir": rng.choice(WRITE_INSIDE + WRITE_OUTSIDE), "mode": rng.choice(
            ["create", "append", "overwrite"])}
        return Fx("file-write", truth_ok=False, effect={**d, "declared": False})
    inside = rng.random() < 0.6
    dire = rng.choice(WRITE_INSIDE if inside else WRITE_OUTSIDE)
    mode = rng.choice(["create", "append", "overwrite"])
    ok = inside
    if rng.random() < 0.18 and inside:  # 模式越权:声明弱于行为
        mode = "overwrite"
        ok = False
    return Fx("file-write", truth_ok=ok, effect={"dir": dire, "mode": mode, "declared": True})


def _op_read(rng) -> Fx:
    declared = rng.random() < 0.85
    return Fx("file-read", truth_ok=declared, effect={"path": rng.choice(WRITE_INSIDE + WRITE_OUTSIDE), "declared": declared})


def _op_net(rng) -> Fx:
    if rng.random() < 0.15:
        ip, port = rng.choice(NET_INSIDE + NET_OUTSIDE)
        return Fx("network", False, {"ip": ip, "port": port, "declared": False})
    inside = rng.random() < 0.7
    ip, port = rng.choice(NET_INSIDE if inside else NET_OUTSIDE)
    return Fx("network", inside, {"ip": ip, "port": port, "declared": True})


def _op_exec(rng) -> Fx:
    declared = rng.random() < 0.85
    return Fx("exec", truth_ok=declared, effect={"binary": rng.choice(BINARIES), "declared": declared})


def _op_perms(rng) -> Fx:
    declared = rng.random() < 0.85
    return Fx("perms", truth_ok=declared, effect={"path": rng.choice(WRITE_OUTSIDE), "declared": declared})


def _op_process(rng) -> Fx:
    declared = rng.random() < 0.85
    return Fx("process", truth_ok=declared, effect={"target": rng.randint(1, 999), "declared": declared})


_OP_BUILDERS = {
    "file-write": _op_write,
    "file-read": _op_read,
    "network": _op_net,
    "exec": _op_exec,
    "perms": _op_perms,
    "process": _op_process,
}


# ---------------- 声明侧:由生成时的 op 参数派生 claims ----------------

def _decl_paths_for(fx: Fx) -> str:
    """范围撒谎时(行为目录在外部),声明退回 /tmp;否则声明 = 行为目录。"""
    d = fx.effect.get("dir", "")
    if d.startswith("/etc") or d.startswith("/var") or d.startswith("/usr"):
        return "/tmp/"
    return d.rstrip("/") + "/" if d else "/tmp/"


def build_claims(effects: list[Fx], hosts_map: dict) -> dict:
    """诚实 = 覆盖全部 declared op;撒谎 = 相应 class 既不 allow 也不 deny。"""
    allow = ["stdout", "stderr", "exit", "fd", "sync"]
    dropped: set[str] = set()
    net_idx = 0
    for fx in effects:
        if not fx.effect.get("declared", True):
            dropped.add(fx.kind)
            continue
        if fx.kind == "file-write":
            # 诚实 = 声明行为 mode;撒谎(含范围/模式越权)= 弱声明 create,
            # 让违规落到 out-of-scope(路径外)或 mode-exceeded(模式越权)
            mode = fx.effect.get("mode", "create")
            if not fx.truth_ok:
                mode = "create"
            allow.append({"class": "file-write", "mode": mode, "paths": [_decl_paths_for(fx)]})
        elif fx.kind == "network":
            host = f"h{net_idx}"; net_idx += 1
            allow.append({"class": "network", "hosts": [host]})
            hosts_map[host] = {fx.effect["ip"]} if fx.truth_ok else {"203.0.113.1"}
        else:
            allow.append(fx.kind)
    claimed = {a for a in allow if isinstance(a, str)}
    claimed |= {d.get("class") for d in allow if isinstance(d, dict)}
    deny = ["other"] + [c for c in SIDE_CLASSES if c not in claimed and c not in dropped]
    return {"allow": allow, "deny": deny}


# ---------------- 行为侧:把 effect 合成成 strace 文本 ----------------

def _open_flags(mode: str) -> str:
    if mode == "append":
        return "|O_APPEND"
    if mode == "overwrite":
        return "|O_TRUNC"
    return ""


def make_text(effects: list[Fx], rng) -> str:
    lines = [FIRST_LINE]
    pid = 100
    fd = 3
    for fx in effects:
        if fx.kind == "file-write":
            d = fx.effect["dir"]
            p = f"{d}/f{rng.randint(1, 99)}"
            fx.effect["path"] = p
            lines.append(S(pid, "openat", f'AT_FDCWD, "{p}", O_WRONLY|O_CREAT{_open_flags(fx.effect["mode"])}, 0644', str(fd)))
            lines.append(S(pid, "write", f'{fd}, "data-{rng.randint(0, 999)}", 5', "5"))
            if rng.random() < 0.5:
                lines.append(S(pid, "close", str(fd), "0"))
            fd += 1
        elif fx.kind == "file-read":
            p = fx.effect["path"]
            if not "/" in p.lstrip("/"):
                p = f"{p}/in.txt"
                fx.effect["path"] = p
            lines.append(S(pid, "openat", f'AT_FDCWD, "{p}", O_RDONLY', str(fd)))
            lines.append(S(pid, "read", f'{fd}, "abc", 3', "3"))
            fd += 1
        elif fx.kind == "network":
            ip, port = fx.effect["ip"], fx.effect["port"]
            lines.append(S(pid, "socket", "AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP", str(fd)))
            lines.append(S(pid, "connect", f'{fd}, {{sa_family=AF_INET, sin_port=htons({port}), sin_addr=inet_addr("{ip}")}}, 16', "0"))
            if rng.random() < 0.5:
                lines.append(S(pid, "write", f'{fd}, "payload", 7', "7"))
            else:
                lines.append(S(pid, "sendto", f'{fd}, "payload", 7, 0, NULL, 0', "7"))
            fd += 1
        elif fx.kind == "exec":
            lines.append(S(pid, "execve", f'"{fx.effect["binary"]}", ["{fx.effect["binary"].rsplit("/", 1)[-1]}", "-c", "x"], 0', "0"))
        elif fx.kind == "perms":
            lines.append(S(pid, "chmod", f'"{fx.effect["path"]}", 0777', "0"))
        elif fx.kind == "process":
            lines.append(S(pid, "kill", f'{fx.effect["target"]}, SIGTERM', "0"))
    lines.append(S(pid, "exit_group", "0", "0"))
    return "\n".join(lines)


# ---------------- 组装为 corpus.Case ----------------

def gen_case(seed: int) -> "tuple[str, str, str, dict, dict[str, set[str]]]":
    """返回 (name, label, text, claims, hosts_map)。"""
    rng = random.Random(seed)
    n = rng.randint(1, 4)
    kinds = rng.sample(SIDE_CLASSES, n)
    effects = [_OP_BUILDERS[k](rng) for k in kinds]
    truth = "benign" if all(fx.truth_ok for fx in effects) else "malicious"
    hosts_map: dict[str, set[str]] = {}
    claims = build_claims(effects, hosts_map)
    text = make_text(effects, rng)
    return f"fuzz-{seed}", truth, text, claims, hosts_map


def run_fuzz(n: int, seed: int, run_case) -> list:
    """生成 n 个 case 并跑管道。run_case 由调用方注入(bench.run_bench.run_case)。

    返回 bench.metrics.CaseResult 列表(含 corpus.Case 所需字段)。
    """
    out = []
    for i in range(n):
        name, label, text, claims, hosts_map = gen_case(seed + i)
        out.append(run_case(Case(name=name, label=label, text=text, claims=claims,
                                 hosts_map=hosts_map, note=f"fuzz seed={seed + i}")))
    return out