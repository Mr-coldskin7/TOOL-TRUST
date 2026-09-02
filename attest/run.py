"""docker run: trace a tool with strace -f inside the container."""
import os
import pathlib
import shutil
import subprocess
import tempfile

# colima file sharing excludes mac private dirs (/var/folders); obs dir must
# land inside the repo root
OBS_ROOT = pathlib.Path(__file__).resolve().parent.parent / ".obs"


def run_tool(manifest: dict, tool_dir: pathlib.Path, inputs: list[str]) -> str:
    """Run the tool under strace in its container; return strace text as str.

    - --cap-add=SYS_PTRACE: strace inside the container needs ptrace permission
    - no -e trace filter: default-deny reconciliation needs to see unclaimed classes
    - strace output is collected via a mounted volume (never written into tool_dir)

    Args:
      manifest: tool.yaml contents.
      tool_dir: tool directory (mounted read-only at /src).
      inputs:   extra argv entries.

    Returns:
      Raw strace text (empty if unavailable).
    """
    OBS_ROOT.mkdir(exist_ok=True)
    obs_dir = pathlib.Path(tempfile.mkdtemp(dir=str(OBS_ROOT)))
    try:
        obs_host = obs_dir / "obs.txt"
        cmd = [
            "docker",
            "run",
            "--rm",
            "--cap-add=SYS_PTRACE",
            "-v",
            f"{tool_dir.resolve()}:/src:ro",
            "-w",
            "/src",
            "-v",
            f"{obs_dir.resolve()}:/obs",
        ]
        # repository: true — tool operates on the host repo; mount cwd read-only at /repo
        if manifest.get("repository"):
            repo = pathlib.Path(os.getcwd()).resolve()
            cmd += ["-v", f"{repo}:/repo:ro"]
        cmd += [
            manifest["base_image"],
            "strace",
            "-f",
            "-o",
            "/obs/obs.txt",
            *manifest["command"].split(),
            *inputs,
        ]
        subprocess.run(cmd, capture_output=True, text=True)
        return obs_host.read_text() if obs_host.exists() else ""
    finally:
        shutil.rmtree(obs_dir, ignore_errors=True)