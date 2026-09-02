"""provenance：给工具加「身份证」——源码内容 hash + 版本快照（SCA 式供应链信任）。

设计（minimal）：
  - `tool.yaml` 增加可选 `provenance: {source, version, hash}`。
  - `hash` = 工具目录内【源码文件】的稳定 SHA-256（按相对路径排序），
    排除 tool.yaml 自身、report.json、编译产物、缓存、.DS_Store。
  - gate 每次调用时重算 hash：
      与声明 hash 不符            → 工具被篡改(tampered) → deny
      缓存报告无 provenance 快照  → 从未按 provenance 验证过(stale) → deny
      报告记录的 version ≠ 声明   → 升级后旧的证明不能继续作保(stale-version) → deny
  - 没有 provenance 的工具走旧逻辑，不受影响（兼容存量）。

为什么排 tool.yaml：claims 本身是「身份声明」，对账失败由 reconcile 运行时兜底；
provenance 守护的是【可执行内容】——行为证明那次观察的对象。
"""
import hashlib
import pathlib

# 不参与 hash 的文件（生成物 / 声明自身 / 系统杂物）
_EXCLUDE_NAMES = {"tool.yaml", "report.json", "test", ".DS_Store"}
_EXCLUDE_PARTS = {"__pycache__", ".obs", ".venv", ".git"}


def tool_source_files(tool_dir: pathlib.Path) -> list[pathlib.Path]:
    """工具目录内的源码文件（可执行内容）。排序稳定。"""
    out = []
    for p in tool_dir.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(tool_dir).as_posix()
        if p.name in _EXCLUDE_NAMES:
            continue
        if any(part in _EXCLUDE_PARTS for part in p.parts):
            continue
        out.append(p)
    out.sort(key=lambda p: p.relative_to(tool_dir).as_posix())
    return out


def compute_tool_hash(tool_dir: pathlib.Path | str) -> str:
    """源码内容哈希：路径 + NUL + 内容字节，跨机器/架构稳定。"""
    h = hashlib.sha256()
    for p in tool_source_files(pathlib.Path(tool_dir)):
        h.update(p.relative_to(tool_dir).as_posix().encode())
        h.update(b"\0")
        h.update(p.read_bytes())
    return h.hexdigest()


def snapshot(manifest: dict) -> dict | None:
    """观察时把 provenance 快照进报告。无 provenance 返回 None。"""
    prov = manifest.get("provenance")
    if not prov:
        return None
    import datetime
    return {
        "source": prov.get("source"),
        "version": prov.get("version"),
        "hash": prov.get("hash"),
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }