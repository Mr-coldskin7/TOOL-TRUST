"""provenance: give a tool an ID — source-content hash + version snapshot.

Minimal design (SCA-style supply-chain trust):
  - `tool.yaml` gains optional `provenance: {source, version, hash}`.
  - `hash` = stable SHA-256 over the tool directory's SOURCE files (sorted by
    relative path), excluding tool.yaml itself, report.json, build artifacts,
    caches, .DS_Store.
  - The gate recomputes the hash on every call:
      hash mismatch with version unchanged     → tampered → deny
      report has no snapshot / version drift   → stale / stale-version → deny
  - Tools without provenance keep the old behavior (backwards compatible).

Why tool.yaml is excluded: claims are the "identity statement" (reconcile is the
runtime fallback); provenance guards the EXECUTABLE CONTENT that was attested.
"""
import hashlib
import pathlib

# Files not part of the hash (generated / the declaration itself / junk).
_EXCLUDE_NAMES = {"tool.yaml", "report.json", "test", ".DS_Store"}
_EXCLUDE_PARTS = {"__pycache__", ".obs", ".venv", ".git"}


def tool_source_files(tool_dir: pathlib.Path) -> list[pathlib.Path]:
    """Source files of a tool dir (the executable content), sorted stably."""
    out = []
    for p in tool_dir.rglob("*"):
        if not p.is_file():
            continue
        if p.name in _EXCLUDE_NAMES:
            continue
        if any(part in _EXCLUDE_PARTS for part in p.parts):
            continue
        out.append(p)
    out.sort(key=lambda p: p.relative_to(tool_dir).as_posix())
    return out


def compute_tool_hash(tool_dir: pathlib.Path | str) -> str:
    """Source-content hash: relative path + NUL + bytes per file.

    Args:
      tool_dir: tool directory.

    Returns:
      hexdigest stable across machines/architectures.
    """
    h = hashlib.sha256()
    for p in tool_source_files(pathlib.Path(tool_dir)):
        h.update(p.relative_to(tool_dir).as_posix().encode())
        h.update(b"\0")
        h.update(p.read_bytes())
    return h.hexdigest()


def snapshot(manifest: dict) -> dict | None:
    """Build the provenance block recorded into a report at observation time.

    Args:
      manifest: tool.yaml contents.

    Returns:
      {"source", "version", "hash", "at"} or None when no provenance declared.
    """
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