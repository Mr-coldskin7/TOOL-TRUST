# tool-trust

**Attested MCP Tool Hub.** Turn everyday scripts into trustworthy, self-declaring MCP tools. Each tool ships with a machine-readable behavioral attestation report produced inside a Docker sandbox.

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](tests/)

---

## Why

LLM agents increasingly call command-line tools on your behalf. But a tool's README rarely matches what it actually does. `tool-trust` closes that gap:

1. **Observe** the tool once inside a minimal Docker container with `strace`.
2. **Reconcile** observed syscalls against the tool's manifest (`tool.yaml`).
3. **Decide** at runtime: pass only if the attestation is clean and the current host meets its declared prerequisites.
4. **Expose** the tool through a standard MCP server so any MCP-capable client (pi, Claude Code, etc.) can use it.

No reputation scores, no manual security reviews. The first tool you write can already produce its first attestation report.

---

## How It Works

```
┌─────────────┐     Docker + strace     ┌──────────────────┐
│  tool.py    │ ────────────────────────► │  JSON report     │
│  tool.yaml  │     observe.py          │  (verdict /      │
└─────────────┘                         │   claims /       │
                                        │   violations)    │
                                        └────────┬─────────┘
                                                 │
                    ┌────────────────────────────┼────────────────────────────┐
                    │                            │                            │
                    ▼                            ▼                            ▼
            ┌───────────────┐          ┌───────────────┐          ┌──────────────────┐
            │  server.py    │          │  gate.py      │          │  runtime agent   │
            │  skips fail   │          │  requires +   │          │  calls tool if     │
            │  attestation  │          │  claims check │          │  verdict=pass    │
            └───────────────┘          └───────────────┘          └──────────────────┘
```

- **`observe.py`** is the one-time health check.
- **`gate.py`** is the bouncer on every call.
- **`server.py`** is the stdio MCP server that only registers tools whose latest report says `pass`.

---

## Public Tools

| Tool | What it does | Claims |
|------|--------------|--------|
| `cpp_test` | Convert input text to uppercase | pure compute |
| `us_quote` | US stock real-time quotes (Yahoo Finance) | network |
| `us_market` | US stock technical snapshot | network |
| `fx_rate`  | Currency conversion (open.er-api.com) | network |
| `repo_stats` | Repository overview (files, lines, TODOs) | read-only filesystem |
| `sha_tool` | SHA-256 of input string | pure compute |
| `cache_tool` | Append a line to `/tmp/cache.log` | append-only write |
| `env_gate` | Demo hard-deny when host env mismatches | no side effects |

> **Personal tools** (`cityu_mail`, `us_news`) live under `tools/` but are gitignored. They are not committed and only work on the author's machine. Copy them as templates if you want your own private tools.

---

## Quick Start

### 1. Install

Requires Python 3.12+, `uv`, and Docker.

```bash
git clone https://github.com/Mr-coldskin7/TOOL-TRUST.git
cd TOOL-TRUST
uv sync
```

### 2. Attest & run a tool locally

```bash
# Generate claims from a clean run
uv run python observe.py cpp-test --generate-claims hello

# Verify a later run still matches the claims
uv run python observe.py cpp-test hello | jq .verdict
# "pass"
```

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

We intentionally **do not** wrap every call in a kernel sandbox (bwrap/sandbox-exec). The tool already lives inside the agent's bash runtime; adding per-call kernel isolation is over-engineering for this threat model. Docker isolation is used **only during observation** to discover truth; runtime enforcement relies on the attestation report + gate.

### Path whitelist hardening

The `file-write` claim uses a path whitelist. We normalize paths and enforce directory boundaries so `/tmp/../etc/passwd` cannot bypass `/tmp/`.

---

## Architecture

```text
TOOL-TRUST/
├── attest/              # core attestation logic
│   ├── build.py         # Docker base image (now inline) + tool build
│   ├── run.py           # run tool in container under strace
│   ├── parse.py         # parse strace output
│   ├── rules.py         # syscall → behavior class
│   ├── reconcile.py     # claims vs observed events
│   ├── prereq.py        # requires inference & hard check
│   ├── gate.py          # decision gate + runtime invocation
│   └── report.py        # JSON report builder
├── observe.py           # one-shot attestation CLI
├── server.py            # stdio MCP server
├── tools/               # registered tools
│   ├── us-quote/
│   ├── us-market/
│   ├── fx-rate/
│   ├── repo_stats/
│   ├── sha_tool/
│   ├── cache-tool/
│   ├── env_gate/
│   ├── cpp-test/
│   └── conditional-evil/   # boundary fixture, not registered
├── bench/               # synthetic corpus + metrics (no Docker needed)
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

The bench measures the **reconciliation engine only** — not Docker isolation, not the subprocess-launch internals of the runtime gate, and not tool-source malice (a single observed run is a sample, `conditional-evil` proves the gap). These boundaries are printed in every report alongside the metrics.

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

- [x] Attestation pipeline: Docker sandbox + strace → JSON report
- [x] Structured claims: `file-write` with `mode` + `paths` whitelist
- [x] `requires` pre-flight: auto-inference + hard check
- [x] Decision gate + server-side registration filter
- [x] C++/Python tools end-to-end
- [x] Network tools with `hosts` whitelist + resolver injection
- [x] Path traversal hardening (`..` bypass fixed)
- [x] Boundary fixtures (`evil-write`, `conditional-evil`) to stress-test gate
- [ ] Full manifest-driven registration: add a tool by only editing `tool.yaml`
- [ ] `toolhub` health scan: detect stale/failed attestation reports
- [ ] **Tool provenance (supply-chain trust)**: `source`/`version`/`hash` in manifest; version change → attestation invalidates (SCA-style); gate refuses tampered tools
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
fact**: a Docker sandbox observes what a tool actually does, and a
deterministic reconciliation engine compares it against what the tool
declared.

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
