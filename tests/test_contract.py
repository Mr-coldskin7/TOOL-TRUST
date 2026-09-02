"""Contract governance regression tests (Step 1).

Invariants locked in:
  - auto-generated claims are observed-suggested CANDIDATES, never law
  - only operator-approved claims can enforce
  - approve() is the only way to become operator-approved
  - legacy manifests without origin behave as author-built (no enforce)
  - --generate-claims refuses to overwrite an approved contract
"""
import pathlib

import pytest

from attest import contract


def test_generated_claims_are_candidates_not_law():
    claims = contract.mark_generated({"allow": [], "deny": []})
    assert contract.origin_of(claims) == "observed-suggested"
    assert contract.can_enforce(claims) is False
    assert claims["approved_at"] is None


def test_only_approved_claims_can_enforce():
    c = contract.mark_generated({"allow": [], "deny": []})
    assert contract.can_enforce(c) is False
    contract.approve(c)
    assert contract.can_enforce(c) is True
    assert c["origin"] == "operator-approved"
    assert "approved_at" in c


def test_approve_is_idempotent():
    c = contract.mark_generated({"allow": [], "deny": []})
    contract.approve(c)
    first = c["approved_at"]
    contract.approve(c)
    assert c["approved_at"] == first


def test_legacy_missing_origin_is_author_built():
    assert contract.origin_of({}) == "author-built"
    assert contract.origin_of({"allow": []}) == "author-built"
    assert contract.can_enforce({"allow": []}) is False


def test_invalid_origin_falls_back_to_author_built():
    assert contract.origin_of({"origin": "not-a-real-origin"}) == "author-built"


def test_generate_refuses_to_overwrite_approved(tmp_path, monkeypatch):
    """CLI-level: --generate-claims on an approved tool must exit(2) without edits."""
    import yaml

    from observe import TOOLS_DIR, generate_claims

    tool = tmp_path / "provenance-demo"
    tool.mkdir()
    claims = {"origin": "operator-approved", "allowed_at": "t", "allow": [], "deny": []}
    m = {"name": "provenance-demo", "claims": claims, "command": "sh run.sh", "build": "true"}
    (tool / "tool.yaml").write_text(yaml.safe_dump(m))
    (tool / "run.sh").write_text("#!/bin/sh\necho hi\n")
    monkeypatch.setattr("observe.TOOLS_DIR", tmp_path)

    with pytest.raises(SystemExit) as e:
        generate_claims("provenance-demo", ["x"])
    assert e.value.code == 2
    # file untouched
    after = yaml.safe_load((tool / "tool.yaml").read_text())
    assert after["claims"]["origin"] == "operator-approved"