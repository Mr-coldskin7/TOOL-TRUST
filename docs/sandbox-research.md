# Sandbox vs. Attestation — Research Notes

> Date: 2026-09-02  
> Context: A colleague suggested replacing the tool-trust attestation pipeline with an off-the-shelf sandbox ("policy triggers a record, so just drop one in"). This document records the research conclusion and the precise scope in which a sandbox helps.

## TL;DR

- **"Record on trigger" is real and commoditized.** Falco, Tracee, KubeArmor, Anthropic sandbox-runtime, secimport, landrun, etc. all implement the pattern.
- **A sandbox cannot replace the whole product.** It can replace the *measurement* half (`observe.py` + `attest/rules.py`), but not the *reconciliation* half (claims vs. reality, verdict, gate, provenance).
- **The real win is host-level observation.** Running outside Docker eliminates container drift (the `pread64`/`sendfile64` noise in `attest/rules.py`) and makes generated `tool.yaml` claims portable across machines.
- **Recommendation:** Make the measurement backend pluggable; evaluate `sandbox-runtime` first, then `secimport`. Keep claims/reconcile/gate untouched.

---

## 1. What the colleague proposed

The suggestion was essentially:

> "Use a sandbox that records violations when a policy fires, instead of parsing strace yourself."

That maps to the first half of our pipeline:

```text
build → trace → classify → reconcile → report → gate
        ^^^^^^^^^^^^^^^^
        measurement half (sandbox can replace)
                        ^^^^^^^^^^^^^^^^^^^^^^
                        reconciliation half (sandbox cannot replace)
```

The intuition is correct: syscall → behavior-class rules are not a unique value proposition. Many tools already do it. But the second half—turning a declared `tool.yaml` claims inventory into a pass/fail verdict, attributing violations to specific claims, and caching that decision for the gate—is not what sandboxes are built for.

---

## 2. Record-on-trigger landscape

| Project | Stars | Mechanism | Relevance to tool-trust |
|---|---|---|---|
| [falcosecurity/falco](https://github.com/falcosecurity/falco) | 9.3k | Rules-as-code over syscall / eBPF events; rule hit → alert record | Textbook "record on trigger". Its rules are the upstream version of `attest/rules.py`. |
| [aquasecurity/tracee](https://github.com/aquasecurity/tracee) | 4.6k | eBPF signature detection, semantic event stream | Same pattern, more forensics-oriented. |
| [kubearmor/KubeArmor](https://github.com/kubearmor/KubeArmor) | 2.6k | LSM policy enforcement + event recording | Policy → record → (optional) block. Close to log-only observation. |
| [anthropics/sandbox-runtime](https://github.com/anthropics/sandbox-runtime) (srt) | 5.1k | Native MCP-server sandbox with violation store | Closest to the colleague's idea: `srt npx ...mcp-server` wraps an MCP server and emits violation events with raw paths. |
| [avilum/secimport](https://github.com/avilum/secimport) | 243 | Python + eBPF per-module syscall sandbox | Best fit for our all-Python tools; can observe on the host; block/record switchable. |
| [Zouuup/landrun](https://github.com/Zouuup/landrun), [fencesandbox/fence](https://github.com/fencesandbox/fence), [landlock-lsm/go-landlock](https://github.com/landlock-lsm/go-landlock), [multikernel/sandlock](https://github.com/multikernel/sandlock) | 358–2.3k | Unprivileged Landlock / seccomp sandboxes | Lightweight, host-level, can be run in complain/log-only mode. |

All of them answer **"was this operation allowed?"** or **"what violated the policy?"**. None of them answer **"does the observed behavior match the claims declared in `tool.yaml`?"**.

---

## 3. Why a drop-in sandbox cannot replace the whole product

### 3.1 Runtime is not supposed to enter the sandbox

Our current `observe.py` uses Docker + `strace -f` in **non-blocking** mode. It records what the tool does when it is *unconstrained*, then compares that behavior against the claims in `tool.yaml`.

If we replaced this with an **enforcing** sandbox, the tool would hit `EPERM` during observation. The trace would then show the *crippled* behavior, not the tool's natural behavior. That trace cannot be reconciled with the claims, because the claims describe what the tool *wants* to do, not what the sandbox *let* it do.

Therefore any sandbox integration must use a **log-only / complain / audit** mode:

- AppArmor complain mode
- SELinux permissive mode
- Falco detection mode
- srt violation store
- secimport recording mode

That is exactly what `strace` is doing today, just via an official channel.

### 3.2 The product's second half is unique

No off-the-shelf sandbox produces:

1. An attestation report with a `pass` / `fail` verdict.
2. Mapping of each violation to a specific claim in `tool.yaml`.
3. A cached `report.json` used by the gate at runtime.
4. Provenance verification (`source`, `version`, `hash`) invalidating stale reports.
5. A `requires` pre-flight check independent of observation.

These are tool-trust's differentiation. A sandbox can feed cleaner events into the pipeline, but the pipeline itself stays.

---

## 4. The real value of a sandbox for this project

### 4.1 Eliminate container drift

`attest/rules.py` already carries comments about amd64 glibc noise:

```python
_WRITE_SYSCALLS = {
    ...
    "pwrite64", "sendfile64",  # 64-bit variants (amd64 glibc noise)
}
_READ_SYSCALLS = {
    ...
    "pread64",  # amd64 runtime noise: glibc calls pread64 instead of pread
    ...
}
```

These variants appear because the observed process runs inside a minimal Linux container with a specific glibc. A sandbox that observes on the **host** sees the same syscalls the tool will see in production, so auto-generated `tool.yaml` claims are consistent across developer laptops, CI, and the server.

### 4.2 Reduce server latency

`observe.py` currently starts a Docker container for each observation. In the live MCP server path, that is a measurable delay. A host-level sandbox backend (srt or secimport) could cut observation latency dramatically.

### 4.3 Better event fidelity

eBPF / LSM-based sandboxes see events closer to the kernel than `strace` text parsing. Path resolution, network endpoints, and file-descriptor routing would be more reliable than our regex-based `_PATH_RE`, `_SIN_ADDR_RE`, and `route_fds()`.

---

## 5. Recommendations

### 5.1 Do not do a wholesale replacement

Keep `observe.py`'s contract (raw events → annotated events → reconciliation) but make the **trace backend pluggable**:

```text
┌─────────────┐     ┌─────────────────────┐     ┌─────────────────┐
│  tool.yaml  │────→│  measurement backend │────→│  classify /     │
│  claims     │     │  (strace | srt |     │     │  reconcile /    │
│  requires   │     │   secimport | ...)   │     │  report / gate  │
└─────────────┘     └─────────────────────┘     └─────────────────┘
```

### 5.2 Evaluation order

1. **`anthropics/sandbox-runtime`** — highest priority.
   - MCP-native, so it aligns with the live server architecture.
   - Violation store is a ready-made log-only event channel.
   - Can wrap tools via `srt <interpreter> <tool>`.

2. **`avilum/secimport`** — second priority.
   - Best language fit (all our tools are Python).
   - Supports host-level observation and block/record switching.
   - Risk: eBPF dependency may fail on macOS or locked-down CI runners.

3. **Landlock / seccomp wrappers** — third priority.
   - Good for long-term "minimal privilege" enforcement, but less valuable for observation because they focus on blocking, not attribution.

### 5.3 Definition of done for the first spike

Pick one tool (e.g. `tools/fx-rate`) and answer:

1. Can the sandbox run it on the host without Docker?
2. Does it emit events equivalent to our current `class`/`path`/`mode`/`ip`/`port` schema?
3. How different is the auto-generated `claims` block from the strace version?
4. What is the wall-clock time vs. `docker run --rm ... strace -f`?
5. Does it introduce new environment-specific noise?

Only after those answers are in should we decide whether to add a second backend.

---

## 6. Related work in attestation / trust

Beyond sandboxes, the "prove/trust the tool" layer has mature analogs worth tracking:

| Project | Focus | Why it matters |
|---|---|---|
| [kontext-security/attestable-mcp-server](https://github.com/kontext-security/attestable-mcp-server) | Hardware attestation for MCP servers | Proves the running server matches a known binary. Extends our provenance work toward hardware-backed trust. |
| [aflock-ai/aflock](https://github.com/aflock-ai/aflock) | Signed policy constraints for agents | Similar philosophy: declare policy, enforce/record at runtime. |

These sit orthogonal to the measurement-backend question but reinforce the architectural split: **trust the code** (provenance/attestation) is separate from **observe the behavior** (sandbox/strace).

---

## 7. Conclusion

The colleague was half right: the "record on trigger" mechanism is a commodity and we should not be proud of maintaining our own syscall classifier. But the conclusion that a sandbox can replace tool-trust is wrong, because sandboxes answer "allow/deny", not "declared vs. actual".

The correct integration is narrow: swap the measurement backend for a host-level, log-only sandbox, keep the claims/reconcile/gate layers, and treat container-drift elimination as the primary success metric.
