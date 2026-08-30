"""claims vs 观察事件 对账。确定性逻辑，默认拒绝。

对账规则：

  第一关 class：     事件.class 必须出现在 allow 里，否则 violation (not-claimed)
  第二关 paths：     file-write 必须命中某条声明的 paths 白名单，否则 violation (out-of-scope)
  第三关 mode：      实际意图模式必须被声明模式覆盖，否则 violation (mode-exceeded)
  network.hosts：    若 network 声明带 hosts 白名单，所有带目标 IP 的网络事件必须
                     命中声明的 host 解析出的 IP 集合，否则 violation (net-out-of-scope)

其它无副作用 class（stdout/exit/file-read…）只需过第一关。
"""
import socket

from attest.rules import MODE_ALLOWS


def _normalize_allow(allow: list) -> list[dict]:
    """兼容旧格式：字符串 'file-read' → {'class': 'file-read'}"""
    out = []
    for item in allow:
        if isinstance(item, str):
            out.append({"class": item})
        else:
            out.append(item)
    return out


def _path_in_paths(path: str, paths: list[str]) -> bool:
    return any(path.startswith(p) for p in paths)


def _default_resolver(hosts: list[str]) -> set[str]:
    """把声明的 host 解析成 IP 集。解析失败的 host 跳过（不因 DNS 抖动全盘否决）。"""
    out: set[str] = set()
    for h in hosts:
        try:
            for info in socket.getaddrinfo(h, None):
                out.add(info[4][0])
        except socket.gaierror:
            continue
    return out


def reconcile(
    events: list[dict], claims: dict, resolver=None
) -> list[dict]:
    """事件列表对账 claims。返回 violation 列表，含证据。

    resolver 可注入（测试确定性用）：hosts -> IP 集。
    """
    allow = _normalize_allow(claims.get("allow", []))
    deny = set(claims.get("deny", []))
    host_resolver = resolver or _default_resolver

    by_class: dict[str, list[dict]] = {}
    for ev in events:
        by_class.setdefault(ev["class"], []).append(ev)

    violations = []
    for c in sorted(by_class):
        evs = by_class[c]
        decls = [a for a in allow if a["class"] == c]

        if c in deny:
            _add(violations, c, "denied", evs)
            continue
        if not decls:
            # 无副作用 class 有事件但没声明 → 默认拒绝
            _add(violations, c, "not-claimed", evs)
            continue
        if c == "file-write":
            _check_file_write(decls, evs, violations)
        elif c == "network":
            _check_network_hosts(decls, evs, violations, host_resolver)

    return violations


def _check_network_hosts(
    decls: list[dict], evs: list[dict], violations: list[dict], resolver
) -> None:
    """network 声明带 hosts 白名单 → 带目标 IP 的事件必须命中解析集合。

    豁免两类基础设施流量（不是工具的数据目标）：
      - port 53：DNS 解析（工具解析白名单 host 本身就要查 DNS）
      - 127.x：本机/容器内部连接（如 Docker embedded DNS 127.0.0.11）
    """
    host_decls = [d for d in decls if isinstance(d, dict) and d.get("hosts")]
    if not host_decls:
        return
    allowed: set[str] = set()
    for d in host_decls:
        allowed |= resolver(d["hosts"])
    for ev in evs:
        ip = ev.get("ip")
        port = ev.get("port")
        if not ip:
            continue
        if port == 53 or ip.startswith("127."):
            continue  # DNS/本机基础设施流量
        if ip not in allowed:
            _add_one(
                violations,
                ev,
                "net-out-of-scope",
                f"ip={ip}:{port or '?'} not in declared network hosts",
            )


def _check_file_write(
    decls: list[dict], evs: list[dict], violations: list[dict]
) -> None:
    """file-write 二级判定：paths 白名单 + mode 覆盖。"""
    for ev in evs:
        path = ev.get("path")
        mode = ev.get("mode")
        # 无法提取路径的事件（如 write(fd)），其 openat 同属一件事已判定过，
        # 无法单独证明在范围内 → 保守放行（openat 那次的判定为准）
        if path is None:
            continue

        # 第二关：路径必须在某条声明的白名单内
        in_scope = [d for d in decls if _path_in_paths(path, d.get("paths", []))]
        if not in_scope:
            _add_one(
                violations,
                ev,
                "out-of-scope",
                f"path={path} not in any declared write whitelist",
            )
            continue

        # 第三关：意图模式必须被覆盖（声明 create 却 O_TRUNC = 违规）
        allowed_modes = set()
        for d in in_scope:
            m = d.get("mode")
            if m and m in MODE_ALLOWS:
                allowed_modes |= MODE_ALLOWS[m]
            else:
                allowed_modes |= MODE_ALLOWS["overwrite"]  # 未声明 mode = 宽松
        if mode is not None and mode not in allowed_modes:
            _add_one(
                violations,
                ev,
                "mode-exceeded",
                f"path={path} mode={mode} not covered by declared modes",
            )


def _add(violations: list[dict], c: str, reason: str, evs: list[dict]) -> None:
    violations.append(
        {
            "class": c,
            "reason": reason,
            "syscalls": sorted({e["syscall"] for e in evs}),
            "evidence": evs[0].get("args", "") if evs else "",
        }
    )


def _add_one(violations: list[dict], ev: dict, reason: str, detail: str) -> None:
    violations.append(
        {
            "class": ev.get("class", "file-write"),
            "reason": reason,
            "syscalls": [ev["syscall"]],
            "evidence": ev.get("args", ""),
            "detail": detail,
        }
    )