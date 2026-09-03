"""Permission discovery (srt scan): unit tests for stderr parsing (any platform)."""
from attest import scan


def test_permission_error_paths():
    stderr = (
        "[SandboxDebug] denying: google.com:443\n"
        "PermissionError: [Errno 1] Operation not permitted: '/Users/x/evil.txt'\n"
        "can't open '/tmp/x': Permission denied\n"
        "normal output line\n"
    )
    paths = scan._eperm_paths(stderr)
    assert "/Users/x/evil.txt" in paths
    assert "/tmp/x" in paths
    # net-denying lines must NOT be picked up as fs paths
    assert "google.com" not in paths


def test_no_false_positives():
    assert scan._eperm_paths("clean run, no errors\n") == []


def test_scan_suggestions_from_denials():
    """Pure: denial evidence → minimal suggested grant."""
    denials = [
        {"kind": "net-block", "target": "open.er-api.com", "port": 443},
        {"kind": "fs-deny", "target": "/var/tmp/state.json", "port": None},
    ]
    suggested = scan._build_suggested(denials, scan.MIN_SETTINGS)
    assert suggested["network"]["allowedDomains"] == ["open.er-api.com"]
    assert "/var/tmp/state.json" in suggested["filesystem"]["allowWrite"]
    # defaults preserved, no denied-domains bloat
    assert suggested["network"]["deniedDomains"] == []
    assert "/tmp" in suggested["filesystem"]["allowWrite"]