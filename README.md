# tool-trust

**Attested MCP Tool Hub.** Turn everyday scripts into trustworthy, self-declaring MCP tools. Each tool ships with a machine-readable behavioral contract — permissions discovered by running it inside sandbox-runtime (`srt`), then enforced on every call by that same sandbox.

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](tests/)
[![CI](https://github.com/Mr-coldskin7/TOOL-TRUST/actions/workflows/ci.yml/badge.svg)](https://github.com/Mr-coldskin7/TOOL-TRUST/actions/workflows/ci.yml)

---

## Why

LLM agents increasingly call command-line tools on your behalf. But a tool's README rarely matches what it actually does. `tool-trust` closes that gap:

1. **Discover** the tool's permissions by running it once inside the minimal `srt` sandbox and reading what it needed (blocked hosts, denied paths).
2. **Legislate** — an operator reviews the evidence and approves a contract (`operator-approved`).
3. **Enforce** every runtime call inside `srt`: any breach flips the gate to `violation-deny`.
4. **Expose** the tool through a standard MCP server so any MCP-capable client (pi, Claude Code, etc.) can use it.

No reputation scores, no manual security reviews. The first tool you write can already produce its first enforceable contract.

---

## How It Works

Everything runs inside `srt` — discovery and enforcement use the same sandbox:

```
┌─────────────┐   srt --scan (minimal    ┌──────────────────┐
│  tool.py    │ ───────────────────────► │ suggested access  │  observe.py --scan:
│  tool.yaml  │   sandbox, read denials) │  (blocked hosts /  │  ONE-TIME permission
└─────────────┘                         │   denied paths)    │  discovery (evidence,
                                        └────────┬─────────┘   never legislation)
                                                 │  operator --approve (legislation)
                                                 ▼
                                        ┌──────────────────┐
                                        │  contract         │
                                        │  operator-approved│
                                        │  (contract.json   │
                                        │   committed)      │
                                        └────────┬─────────┘
                                                 │
                        ┌────────────────────────┼─────────────────────────┐
                        ▼                        ▼                         ▼
                ┌──────────────┐        ┌──────────────┐         ┌────────────────────┐
                │  srt (exec)  │        │  gate.py     │         │  server.py         │
                │ enforces each │        │ requires +   │         │ registers only     │
                │ call: deny =  │        │ provenance + │         │ contracts that     │
                │ violation-deny│        │ verdict      │         │ are operator-      │
                └──────────────┘        └──────────────┘         │ approved           │
                                                                    └────────────────────┘
```

- **`observe.py --scan`** — one-time permission discovery inside the minimal srt sandbox (evidence, never legislation).
- **`--approve`** — the operator legislates; commits `contract.json`; only `operator-approved` contracts are enforced.
- **`srt`** — enforces every approved call (seatbelt/bubblewrap); breaches → `violation-deny` + audit.
- **`gate.py`** — bouncer: verdict / requires / provenance gates, then hands approved contracts to srt.
- **`server.py`** — stdio MCP server; registers tools whose contracts are operator-approved.

---

### 1. Install

Requires Python 3.12+, `uv`, and **`srt`** (sandbox-runtime — discovery AND enforcement):

```bash
npm install -g @anthropic-ai/sandbox-runtime   # srt CLI (sandbox runtime)
# Linux only: the srt backend needs bubblewrap
apt install bubblewrap
```

```bash
git clone https://github.com/Mr-coldskin7/TOOL-TRUST.git
cd TOOL-TRUST
uv sync
```

`gate` refuses to enforce as `srt-not-installed` with install hints if it is missing.

---

## Public Tools

| Tool | What it does | Claims | Enforced by srt |
|------|--------------|--------|-----------------|
| `us_quote` | US stock real-time quotes (Yahoo Finance) | network | ✓ (query1/2.finance.yahoo.com) |
| `us_market` | US stock technical snapshot | network | ✓ (query1.finance.yahoo.com) |
| `fx_rate`  | Currency conversion (open.er-api.com) | network | ✓ (open.er-api.com) |
| `repo_stats` | Repository overview (files, lines, TODOs) | read-only filesystem | ✓ (defaults only) |
| `sha_tool` | SHA-256 of input string | pure compute | ✓ (defaults only) |
| `cache_tool` | Append a line to `/tmp/cache.log` | append-only write | ✓ (write /tmp) |
| `env_gate` | Demo hard-deny when host env mismatches | no side effects | ✓ (meta: requires-gated) |

Every `✓` tool was permission-discovered via `observe.py <tool> --scan` (run inside
the minimal sandbox, read what it needed), operator-approved, and now runs
inside srt on every call — breaches flip the gate decision to `violation-deny`.

> **Personal tools** (`cityu_mail`, `us_news`) live under `tools/` but are gitignored. They are not committed and only work on the author's machine. Copy them as templates if you want your own private tools.

---

## Quick Start

## Public Tools

```bash
npm install -g @anthropic-ai/sandbox-runtime   # srt CLI (sandbox runtime)
# Linux only: the srt backend needs bubblewrap
#   apt install bubblewrap   (or: brew install bubblewrap)
```

```bash
git clone https://github.com/Mr-coldskin7/TOOL-TRUST.git
cd TOOL-TRUST
uv sync
```

`gate` refuses to enforce as `srt-not-installed` with install hints if it is missing.

### 2. Attest & run a tool locally

```bash
# Discover what a tool needs (permission evidence from the minimal sandbox)
uv run python observe.py fx-rate --scan USD CNY 1
# -> needs 1 permission: allowedDomains [open.er-api.com]

# Write the reviewed srt-settings.json, then legislate:
uv run python observe.py fx-rate --approve --yes
# -> origin=operator-approved + committed contract.json (gate snapshot)
```

Every call now runs enforced inside `srt` — out-of-contract access flips the
gate to `violation-deny`.

### 3. Run the MCP server

```bash
uv run python server.py --stdio
```

Then point your MCP client at it. For example, in **pi**:

```json
{
  "mcpServers": {
    "toolhub": {
      "command": "uv",
      "args": ["run", "python", "server.py", "--stdio"],
      "cwd": "/path/to/TOOL-TRUST"
    }
  }
}
```

Reload (`/reload` in pi) and call:

```text
toolhub_us_quote ticker=AAPL
```

### 4. Register a new tool

Use the included skill (in `.claude/skills/register-tool/`):

```text
/register-tool create a tool that fetches the current weather for a city
```

The skill will generate source, manifest, attestation wrapper, and a smoke test.

---

## Security Model

| Layer | Role | Key Point |
|-------|------|-----------|
| **Attestation** (`observe.py`) | One-time behavioral sample | Produces a report, not a proof of innocence. |
| **Requires** (`prereq.py`) | Pre-flight hard check | `exec`, `files`, `env`, `writable` must all be present; otherwise the call is refused before it starts. |
| **Gate** (`gate.py`) | Per-call decision | Cached `verdict=fail` → refuse; runtime `claims` mismatch → refuse. |
| **Server filter** (`server.py`) | Registration-time filter | Tools with failed attestation are not registered, so the agent cannot even see them. |

Runtime enforcement is delegated to **srt** (mature sandbox: seatbelt on macOS,
bubblewrap on Linux) — approved contracts run inside it on the host, deny =
out-of-scope. Container + strace is kept ONLY for one-time candidate
discovery (observe), since non-blocking observation cannot be done by an
enforcement sandbox. Per-call isolation is therefore real (via srt) but the
policy language stays ours (claims → contract); we do not hand-roll kernel
rules.

### Path whitelist hardening

The `file-write` claim uses a path whitelist. We normalize paths and enforce directory boundaries so `/tmp/../etc/passwd` cannot bypass `/tmp/`.

---

## Architecture

```text
TOOL-TRUST/
├── attest/              # core logic
│   ├── live.py          # srt backend: sandboxed execution + violation parse
│   ├── scan.py          # permission discovery (run in minimal sandbox → needs)
│   ├── contract.py      # claims origin lifecycle (author-built → operator-approved)
│   ├── rules.py         # syscall → behavior class
│   ├── reconcile.py     # claims vs observed events
│   ├── prereq.py        # requires hard check
│   ├── parse.py         # event parsing (inference)
│   ├── provenance.py    # source hash / version identity
│   ├── gate.py          # decision gate + runtime invocation
│   └── report.py        # contract/report builder
├── observe.py           # srt-native CLI: --scan / --approve / --check-requires
├── server.py            # stdio MCP server
├── tools/               # registered tools (each: tool.yaml + contract.json + srt-settings.json)
│   ├── us-quote/
│   ├── us-market/
│   ├── fx-rate/
│   ├── repo_stats/
│   ├── sha_tool/
│   ├── cache-tool/
│   ├── env_gate/
│   ├── cpp-test/
│   └── conditional-evil/   # boundary fixture, not registered
├── bench/               # synthetic corpus + metrics (no srt needed)
├── tests/               # pytest suite
└── .claude/skills/register-tool/  # skill for adding tools
```

---

## Development

Run tests:

```bash
uv run pytest -q
```

### Quantitative metrics

The pipeline is a deterministic classifier, so we hold it to a quantitative bar. `bench/` runs a hand-built corpus of synthetic `strace` logs (each with a ground-truth `benign`/`malicious` label) through the **same code path** as `observe.py`, then reports a confusion matrix plus precision/recall/F1/accuracy:

```bash
uv run python bench/run_bench.py                # corpus 22 case
uv run python bench/run_bench.py --fuzz 500     # + 500 adversarial random cases
uv run python bench/run_bench.py --json         # machine-readable (CI included)
```

Current baseline: **522 cases, precision=recall=F1=accuracy=1.000** (22 handwritten + 500 adversarially fuzzed). Sample size is read into the numbers via a 95% Wilson confidence interval: accuracy CI `[0.993, 1.0]`, precision/recall CI `[0.987, 1.0]` — so the headline number is never a bare `1.000`.

Why the fuzz corpus is not a self-fulfilling prophecy: `bench/fuzz.py` generates random cases from an **intent model** — claims derive from the *declared* side, strace text from the *behavior* side, and the ground-truth label from an intent-level comparison that shares no code with the event-level reconciliation pipeline. Building it surfaced two real engine defects that the 22 hand cases missed (a root-path whitelist boundary bug and an fd-class correlation error in the generator), which were fixed with regression tests.

The bench measures the **reconciliation engine only** — not srt enforcement, not the subprocess-launch internals of the runtime gate, and not tool-source malice (a single sandboxed smoke is a sample, `conditional-evil` proves the gap). These boundaries are printed in every report alongside the metrics.

Run a tool directly without MCP:

```bash
uv run python observe.py fx-rate USD HKD 100
```

Inspect a tool's latest attestation report:

```bash
cat tools/<name>/report.json | jq
```

---

## Roadmap

Detailed, regularly-updated work list: **[TODO.md](TODO.md)**.

- [x] Attested pipeline: srt permission discovery (scan) → operator-approved contract → enforced execution
- [x] Structured claims: `file-write` with `mode` + `paths` whitelist
- [x] `requires` pre-flight: auto-inference + hard check
- [x] Decision gate + server-side registration filter
- [x] Script tools end-to-end (python/sh)
- [x] Network tools with `hosts` allowlist (scan-discovered allowedDomains)
- [x] Path traversal hardening (`..` bypass fixed)
- [x] Boundary fixture (`conditional-evil`) to stress-test gate
- [ ] Full manifest-driven registration: add a tool by only editing `tool.yaml`
- [ ] `toolhub` health scan: detect stale/failed attestation reports
- [x] **Tool provenance (supply-chain trust)**: `source`/`version`/`hash` in manifest; tampered source → gate deny; version bump → attestation invalidates (SCA-style)
- [ ] **First-connect human review** for unknown-source tools (browser-unknown-CA model) — Tool Misuse mitigation
- [ ] **Caller identity in gate**: record session/agent making the call — Identity Spoofing mitigation
- [ ] Multi-language runtime support (Node, Go) in base image
- [ ] Telemetry dashboard from `cache_tool` logs

## Direction (why the roadmap looks like this)

tool-trust exists because AI agents trust too much. Modern attacks on agents
(Prompt Injection, Tool Misuse, Intent Breaking, Identity Spoofing, Code
Attacks) all exploit some **unconditional trust** — the model trusts text,
tools, plans, identities, and code execution. We take exactly one of those
points (tool behavior) out of the cloud and replace trust with **verifiable
fact**: the sandbox-runtime tells us what a tool actually needs (blocked
hosts/denied paths from a minimal-sandbox smoke), and a deterministic
gate enforces exactly that on every call.

That framing decides the next three directions:

1. **Tool provenance (SCA-style supply-chain trust)** — a manifest that
   carries `source` / `version` / `hash`. A version bump invalidates the
   attestation; a tampered `tool.py` is refused at the gate. This closes the
   one real blind spot in the current threat model: a tool that *honestly*
   declares malicious behavior still passes attestation today (behavior
   attestation is drift-detection, not malware detection).
2. **First-connect human review for unknown sources** — unknown-origin tools
   need a one-time human approval before first use, mirroring how browsers
   treat self-signed CAs. This is the engineering answer to Tool Misuse
   ("agent gets tricked into adding a malicious MCP server").
3. **Caller identity in the gate** — record which session/agent invokes each
   tool, so a compromised calling agent cannot impersonate a legitimate one
   (Identity Spoofing).

Further out: **executable-plan accountability**. Claim-vs-reality
verification already proves a *tool* does what it says; the same idea
applied to an agent's *execution plan* (declare steps → verify steps
actually run) is the candidate answer to Intent Breaking — the one vector
with no clean engineering solution today.

---

## License

MIT
