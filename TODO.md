# TODO — tool-trust work list

> Sources: README roadmap, semgrep-inspired engineering decisions, AI-agent
> attack-vector lessons (Prompt Injection / Tool Misuse / Intent Breaking /
> Identity Spoofing / Code Attacks). Checkbox = done. **Bold** = newly planned.

## Near term (0–2 weeks · high value) — ordered by dependency

**Order rationale (2026-09-02):** contract governance BEFORE enforcement —
without operator approval, compiling tool self-testimony into a sandbox
policy amplifies the circular-trust we just killed; and sandbox feasibility
must be proven before anything is built on it.

- [x] **Step 1 — CONTRACT GOVERNANCE (laws before locks)** (done 2026-09-05):
      - claims `origin`: author-built | operator-approved; `--scan` proposes,
        `--onboard`/`--approve` legislate (human-in-the-loop); destroys
        self-testimony
- [x] **Step 2 — SANDBOX FEASIBILITY** (done 2026-09-03, via srt): srt drives
      real tool calls on macOS seatbelt + Linux bwrap; CI installs srt+bwrap
- [ ] **Step 3 — LIVE RECONCILIATION (enforcement layer)**:
      build on Steps 1+2:
      - ~~`attest/profile.py`~~ → **deleted 2026-09-03**: custom seatbelt layer dropped,
        enforcement delegated to **srt** (sandbox-runtime; seatbelt/bwrap)
      - [x] `attest/live.py`: approved contracts run via `srt -c`, violations parsed
        from `--debug` stderr; `gate.gated_invoke` routes operator-approved +
        `sandbox.srt_settings` tools into srt (deny srt-not-installed/srt-settings-missing)
      - [x] **violation → deny**: runtime breach flips decision to `violation-deny`
        with detail (live reconcile decision loop closed)
      - [x] nine enforced tools (all operator-approved; settings content locked via sha256)
      - [x] claim granularity: hosts (domains) + paths via srt-settings; enforce-time
        fs-deny parsed from EPERM (filesystem breach now visible as violation-deny, 2026-09-08)
      - [ ] optionally wrap the whole MCP server in srt (coarse-grained enforcement)
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
      (server/gate/enforce smoke) + 522-case bench metrics gate (≥0.95, artifact).
      The old Docker observe e2e job was removed 2026-09-03: discovery moved fully
      into srt (observe --scan); CI still installs srt so enforced runs are verified
      in CI. CD parked until provenance + versioning mature

- [ ] **First-connect human review** for unknown-source tools (browser / unknown-CA
      model) — Tool Misuse mitigation
- [ ] **semgrep SAST layer in register-tool onboarding**: `static_scan` section in
      report.json
  - hand-run a few times first to judge noise ratio before wiring into pipeline
  - fills the honest "we don't scan tool source" gap → SAST/DAST/SCA closed loop
- [x] **Caller identity in the gate** (2026-09-08): `gated_invoke(caller=...)` threads
      session identity into telemetry + results; MCP tools inject fastmcp Context
      (ctx.client_id) — Identity Spoofing mitigation
- [ ] **Replay real tool traces into bench** (synthetic-vs-real comparison; dogfood
      `_drop_launch_execve` / noise filtering)
- [ ] Fully manifest-driven registration: add a tool by editing `tool.yaml` only
- [x] `toolhub` health scan (2026-09-08): `observe.py --status` + `authorizer_status`
      surface `drifted ⚠` when contract/settings deviate (shared verify_snapshot with gate)

## Long term (ecosystem)

- [ ] **tools registry**: shared `tool.yaml` + attestation reports (semgrep registry
      inspiration / SCA-style source trust)
- [ ] **Executable-plan accountability** (Intent Breaking candidate): declare plan
      steps → verify steps actually ran
- [ ] Telemetry dashboard from `cache_tool` logs

---

### Priority logic (one line)

Of the five agent attack vectors: Tool Misuse (provenance + first-connect review)
and Identity Spoofing (gate identity) are engineering-solvable and come first;
Prompt Injection / Code Attacks are already defended by hard gates + the claims
inventory; Intent Breaking has no clean engineering solution yet and is parked
under long-term "executable-plan accountability".