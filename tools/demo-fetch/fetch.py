"""Sample onboarding tool: fetch GitHub zen + append to /tmp/demo-fetch.log.

Demonstrates the permission-discovery loop: needs api.github.com (network)
and /tmp write. No sandbox settings yet — intentionally unapproved.
"""
import json
import urllib.request


def main() -> None:
    req = urllib.request.Request(
        "https://api.github.com/zen",
        headers={"User-Agent": "tool-trust-demo", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        zen = resp.read().decode().strip()
    with open("/tmp/demo-fetch.log", "a") as f:
        f.write(zen + "\n")
    print(json.dumps({"zen": zen, "log": "/tmp/demo-fetch.log"}, ensure_ascii=False))


if __name__ == "__main__":
    main()