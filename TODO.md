# TODO — tool-trust work list

> Sources: README roadmap, semgrep-inspired engineering decisions, AI-agent
> attack-vector lessons (Prompt Injection / Tool Misuse / Intent Breaking /
> Identity Spoofing / Code Attacks). Checkbox = done. **Bold** = newly planned.

## Near term (0–2 weeks · high value)

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

- [ ] **CI/CD pipeline**: GitHub Actions on every push/PR — run `uv run pytest` +
      `bench --json --fuzz 500` (metrics regression gate, thresholds from
      `tests/test_bench.py`); optional Docker observe smoke test (marked slow);
      commit summaries appended locally to `docs/CHANGELOG.md` (gitignored)

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