"""docker build: compile tools inside a container + mtime cache."""
import pathlib
import posixpath
import re
import subprocess
import tempfile

_BASE_DOCKERFILE = """\
# attest observation base image: toolchain + strace + language runtimes
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \\
    g++ gcc strace python3 ca-certificates \\
    && rm -rf /var/lib/apt/lists/*
"""
_BUILD_OUT_RE = re.compile(r"-o\s+(\S+)")

EXCLUDED = {"tool.py", "tool.yaml", "obs.txt"}


def ensure_base_image(base_image: str) -> None:
    """Build the base image if missing (inline Dockerfile, temp dir).

    Args:
      base_image: image tag (e.g. attest-base:latest).

    Returns:
      None.
    """
    if _image_exists(base_image):
        return
    with tempfile.TemporaryDirectory() as td:
        df = pathlib.Path(td) / "Dockerfile"
        df.write_text(_BASE_DOCKERFILE)
        subprocess.run(["docker", "build", "-t", base_image, td], check=True)


def _image_exists(name: str) -> bool:
    """Return True when a local docker image exists."""
    r = subprocess.run(["docker", "image", "inspect", name], capture_output=True)
    return r.returncode == 0


def _artifact_name(build_cmd: str) -> str | None:
    """Extract '-o <artifact>' from a build command, or None."""
    m = _BUILD_OUT_RE.search(build_cmd)
    return m.group(1) if m else None


def _source_files(tool_dir: pathlib.Path, artifact: str | None) -> list[pathlib.Path]:
    """List tool_dir source files (excludes generated/artifact files)."""
    return [
        p
        for p in tool_dir.iterdir()
        if p.is_file()
        and p.name not in EXCLUDED
        and (artifact is None or p.name != artifact)
    ]


def _needs_rebuild(tool_dir: pathlib.Path, build_cmd: str) -> bool:
    """mtime cache: True when the artifact is missing or older than sources."""
    artifact = _artifact_name(build_cmd)
    if artifact is None:
        return True
    artifact_path = tool_dir / artifact
    if not artifact_path.exists():
        return True
    sources = _source_files(tool_dir, artifact)
    artifact_mtime = artifact_path.stat().st_mtime
    return any(s.stat().st_mtime > artifact_mtime for s in sources)


def build_tool(manifest: dict, tool_dir: pathlib.Path) -> None:
    """Run manifest's build command inside the container (skips if cached).

    Args:
      manifest: tool.yaml contents.
      tool_dir: tool directory (mounted at /src).

    Returns:
      None.
    """
    ensure_base_image(manifest["base_image"])
    if not _needs_rebuild(tool_dir, manifest["build"]):
        return
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{tool_dir.resolve()}:/src",
            "-w",
            "/src",
            manifest["base_image"],
            "sh",
            "-c",
            manifest["build"],
        ],
        check=True,
    )