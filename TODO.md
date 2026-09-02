# TODO — tool-trust work list

> Sources: README roadmap, semgrep-inspired engineering decisions, AI-agent
> attack-vector lessons (Prompt Injection / Tool Misuse / Intent Breaking /
> Identity Spoofing / Code Attacks). Checkbox = done. **Bold** = newly planned.

## Near term (0–2 weeks · high value) — ordered by dependency

**Order rationale (2026-09-02):** contract governance BEFORE enforcement —
without operator approval, compiling tool self-testimony into a sandbox
policy amplifies the circular-trust we just killed; and sandbox feasibility
must be proven before anything is built on it.

- [ ] **Step 1 — CONTRACT GOVERNANCE (laws before locks)**:
      - claims gain `origin`: author-built | observed-suggested | operator-approved
      - `--generate-claims` downgraded: output is `observed-suggested` candidates,
        NOT law; needs operator review/approval to become effective
      - a confirm entry point (CLI) to review & approve candidate claims
      - independent of sandbox; destroys the self-testimony loop
- [ ] **Step 2 — SANDBOX FEASIBILITY SPIKE (≤1 day, parallel to Step 1)**:
      seatbelt/sandbox-exec driven to "wraps a real tool call" depth on macOS
      (long-running procs, network limiting, exit codes, log reading) —
      prove the tech gamble before building on it (sandbox-exec is deprecated-
      flagged by Apple; SIP/permissions risk)
- [ ] **Step 3 — LIVE RECONCILIATION (enforcement layer)**:
      build on Steps 1+2:
      - `attest/profile.py`: operator-approved claims → seatbelt profile
      - observer wraps real invocation; violations → deny + telemetry/audit
      - reuse attest/rules.py + reconcile.py for watch/dual-check paths
      - claim granularity: hosts/paths/args allowlists
      - closes conditional-evil + self-testimony via enforcement

- [x] Promote `toolhub` to global pi MCP registration (visible from any project, 4 servers)
- [x] Attestation pipeline / three-level claims / `requires` / gate / server-side filter
- [x] bench: 22 handwritten cases + 500 adversarial fuzz + Wilson CI (accuracy 1.000, CI ≥ 0.987)
- [x] **Tool provenance, minimal implementation** (SCA-style supply-chain trust;
      closes the "honestly-malicious tool" blind spot):
  - add `source` / `version` / `hash` to `tool.yaml`
  - version bump → cached attestation invalidates, re-observe required
  - gate verifies source+manifest hash, refuses tampering
- [ ] **Declarative rules for `attest/rules.py`** (semgrep "rules as code"):
  - extract syscall→class, open-flags→mode intent, hosts policy into YAML rules
    (with metadata / severity)
  - rules become auditable, extensible, externally contributable
- [ ] **rule-level positive/negative tests** in bench: every class rule carries its
      own benign/malicious cases (semgrep rule-testing culture); engine corpus
      becomes a rule contract

## Mid term (supply-chain trust layer · attack-vector mapped)

- [x] **CI/CD pipeline**: GitHub Actions on every push/PR — pytest + usability
      (server/gate smoke) + Docker observe e2e + 522-case bench metrics gate
      (≥0.95, artifact). CI done 2026-09-02; CD (plugin-store distribution) parked
      until provenance + versioning mature

- [ ] **First-connect human review** for unknown-source tools (browser / unknown-CA
      model) — Tool Misuse mitigation
- [ ] **semgrep SAST layer in register-tool onboarding**: `static_scan` section in
      report.json
  - hand-run a few times first to judge noise ratio before wiring into pipeline
  - fills the honest "we don't scan tool source" gap → SAST/DAST/SCA closed loop
- [ ] **Caller identity in the gate** (session/agent context) — Identity Spoofing
      mitigation
- [ ] **Replay real tool traces into bench** (synthetic-vs-real comparison; dogfood
      `_drop_launch_execve` / noise filtering)
- [ ] Fully manifest-driven registration: add a tool by editing `tool.yaml` only
- [ ] `toolhub` health scan: detect stale / failed attestation reports

## Long term (ecosystem)

- [ ] **tools registry**: shared `tool.yaml` + attestation reports (semgrep registry
      inspiration / SCA-style source trust)
- [ ] **Executable-plan accountability** (Intent Breaking candidate): declare plan
      steps → verify steps actually ran
- [ ] Multi-language runtime support (Node, Go) in base image
- [ ] Telemetry dashboard from `cache_tool` logs

---

### Priority logic (one line)

Of the five agent attack vectors: Tool Misuse (provenance + first-connect review)
and Identity Spoofing (gate identity) are engineering-solvable and come first;
Prompt Injection / Code Attacks are already defended by hard gates + the claims
inventory; Intent Breaking has no clean engineering solution yet and is parked
under long-term "executable-plan accountability".