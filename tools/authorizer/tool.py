import subprocess
from fastmcp import FastMCP

_TOOL_DIR = __import__("pathlib").Path(__file__).resolve().parent


def register(mcp: FastMCP) -> None:
    # authorizer tools run the shared attest/authorize layer. `approve` is the
    # legislative step — deploy with MCP permission rules requiring human
    # confirmation (e.g. pi: tools.authorizer_approve = ask) so the agent can
    # request but never self-authorize.
    backend = f"python3 {_TOOL_DIR / 'authorizer.py'}"

    def authorizer_status() -> str:
        """Authorization overview: every tool × state/net/writes/approved-at"""
        r = subprocess.run([*backend.split(), "status"], capture_output=True,
                           text=True, timeout=60)
        return r.stdout or r.stderr

    def authorizer_onboard(tool: str, sample_input: str = "") -> str:
        """Propose permissions for a tool: run it in the minimal sandbox (evidence only, NO approval)"""
        args = [*backend.split(), "onboard", tool] + (
            [sample_input] if sample_input else [])
        r = subprocess.run(args, capture_output=True, text=True, timeout=120)
        return r.stdout or r.stderr

    def authorizer_approve(tool: str) -> str:
        """APPROVE a tool: legislate + lock its permissions (requires human confirmation via MCP)"""
        r = subprocess.run([*backend.split(), "approve", tool], capture_output=True,
                           text=True, timeout=60)
        return r.stdout or r.stderr

    def authorizer_revoke(tool: str) -> str:
        """Revoke authorization: remove contract.json, back to unmanaged"""
        r = subprocess.run([*backend.split(), "revoke", tool], capture_output=True,
                           text=True, timeout=60)
        return r.stdout or r.stderr

    mcp.tool(authorizer_status)
    mcp.tool(authorizer_onboard)
    mcp.tool(authorizer_approve)
    mcp.tool(authorizer_revoke)