"""docker run：容器内 strace 全量跟踪工具运行。"""
import pathlib
import shutil
import subprocess
import tempfile

# colima 文件共享不含 mac 私有目录（/var/folders），obs 目录必须落在项目根下
OBS_ROOT = pathlib.Path(__file__).resolve().parent.parent / ".obs"


def run_tool(manifest: dict, tool_dir: pathlib.Path, inputs: list[str]) -> str:
    """运行工具并 strace，返回 strace 文本。

    - --cap-add=SYS_PTRACE：容器内 strace 需 ptrace 权限
    - 不限定 -e trace=：默认拒绝对账依赖看到未声明 class
    - strace 输出经挂载卷取回 host，不落工具目录
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
            f"{tool_dir.resolve()}:/src",
            "-w",
            "/src",
            "-v",
            f"{obs_dir.resolve()}:/obs",
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
