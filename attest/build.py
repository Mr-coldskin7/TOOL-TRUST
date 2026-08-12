"""docker build：容器内编译工具 + mtime 缓存。"""
import pathlib
import re
import subprocess

_BASE_DOCKERFILE = pathlib.Path(__file__).parent.parent / "docker" / "attest-base"
_BUILD_OUT_RE = re.compile(r"-o\s+(\S+)")

EXCLUDED = {"tool.py", "tool.yaml", "obs.txt"}


def ensure_base_image(base_image: str) -> None:
    """检查 base 镜像存在，缺失则从 docker/attest-base 构建。"""
    if _image_exists(base_image):
        return
    subprocess.run(
        ["docker", "build", "-t", base_image, str(_BASE_DOCKERFILE)], check=True
    )


def _image_exists(name: str) -> bool:
    r = subprocess.run(["docker", "image", "inspect", name], capture_output=True)
    return r.returncode == 0


def _artifact_name(build_cmd: str) -> str | None:
    m = _BUILD_OUT_RE.search(build_cmd)
    return m.group(1) if m else None


def _source_files(tool_dir: pathlib.Path, artifact: str | None) -> list[pathlib.Path]:
    return [
        p
        for p in tool_dir.iterdir()
        if p.is_file()
        and p.name not in EXCLUDED
        and (artifact is None or p.name != artifact)
    ]


def _needs_rebuild(tool_dir: pathlib.Path, build_cmd: str) -> bool:
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
    """容器内执行 manifest['build']。产物新过源码则跳过（mtime 缓存）。"""
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
