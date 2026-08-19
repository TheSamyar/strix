"""retest_findings: replay validated findings and report still-open vs fixed."""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.validation import tools as validation


@pytest.fixture(autouse=True)
def _clear_validations() -> None:
    validation._validations_storage.clear()


def _seed(vid: str, url: str, proof: str | None, *, validated: bool = True) -> None:
    validation._validations_storage[vid] = {
        "id": vid,
        "url": url,
        "method": "GET",
        "validated": validated,
        "proof_excerpt": proof,
    }


def test_still_open_when_signal_reproduces(monkeypatch: pytest.MonkeyPatch) -> None:
    _seed("v1", "https://x/doc/1", "secret-token")

    def _fake(
        method: str, url: str, headers: Any, body: Any, timeout: int, allow_redirects: bool
    ) -> dict[str, Any]:
        del method, url, headers, body, timeout, allow_redirects
        return {"success": True, "status_code": 200, "body": "here is secret-token still"}

    monkeypatch.setattr(validation, "_replay_impl", _fake)
    out = validation._retest_findings_impl(None, None)
    assert out["retested"] == 1
    assert out["still_open"] == 1
    assert out["results"][0]["status"] == "still_open"


def test_fixed_when_signal_gone(monkeypatch: pytest.MonkeyPatch) -> None:
    _seed("v1", "https://x/doc/1", "secret-token")

    def _fake(
        method: str, url: str, headers: Any, body: Any, timeout: int, allow_redirects: bool
    ) -> dict[str, Any]:
        del method, url, headers, body, timeout, allow_redirects
        return {"success": True, "status_code": 403, "body": "access denied"}

    monkeypatch.setattr(validation, "_replay_impl", _fake)
    out = validation._retest_findings_impl(None, None)
    assert out["fixed"] == 1
    assert out["results"][0]["status"] == "fixed"


def test_inconclusive_without_proof() -> None:
    _seed("v1", "https://x/doc/1", None)
    out = validation._retest_findings_impl(None, None)
    assert out["inconclusive"] == 1
    assert out["results"][0]["status"] == "inconclusive"


def test_unvalidated_findings_skipped() -> None:
    _seed("v1", "https://x/doc/1", "tok", validated=False)
    out = validation._retest_findings_impl(None, None)
    assert out["retested"] == 0


def test_credential_label_missing_errors() -> None:
    _seed("v1", "https://x/doc/1", "tok")
    out = validation._retest_findings_impl(None, "ghost-label")
    assert out["success"] is False
