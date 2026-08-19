"""ssrf_probe: deep SSRF via content signatures, with reflection-FP suppression."""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote

import pytest

from strix.tools.injection_fuzz import tools as inj
from strix.tools.ssrf_probe import tools as st


def _mock_fetching_server(monkeypatch: pytest.MonkeyPatch) -> None:
    """Server that actually fetches SSRF targets and returns their content."""

    def fake(method: str, url: str, headers: Any, body: Any, timeout: int, **_k: Any) -> dict[str, Any]:
        blob = unquote(url + (body or ""))
        if "metadata.google.internal" in blob:
            return {"success": True, "status_code": 200, "body": "numeric_project_id 8123 sshKeys"}
        if "169.254.169.254" in blob:
            return {"success": True, "status_code": 200, "body": "ami-id ami-1 AccessKeyId ASIA"}
        if "file:///etc/passwd" in blob:
            return {"success": True, "status_code": 200, "body": "root:x:0:0:root:/root:/bin/bash"}
        if "127.0.0.1" in blob:
            return {"success": True, "status_code": 200, "body": "internal dashboard " * 20}
        if "240.0.0.1" in blob:
            return {"success": True, "status_code": 502, "body": "bad gateway"}
        return {"success": True, "status_code": 200, "body": "normal app response"}

    monkeypatch.setattr(inj, "_replay_impl", fake)


def test_confirms_metadata_and_file_via_content(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_fetching_server(monkeypatch)
    out = st._ssrf_probe_impl("GET", "https://x/fetch", ["url"], None, None, "query", None, 12)
    confirmed = {f["target"] for f in out["findings"] if f["severity"] == "critical"}
    assert "aws-imds" in confirmed
    assert "file-etc-passwd" in confirmed
    assert out["possible_ssrf"] is True


def test_internal_host_is_unconfirmed_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_fetching_server(monkeypatch)
    out = st._ssrf_probe_impl("GET", "https://x/fetch", ["url"], None, None, "query", None, 12)
    internal = [f for f in out["findings"] if f["target"] == "loopback-v4"]
    assert internal and internal[0]["severity"] == "unconfirmed"


def test_reflection_is_not_falsely_confirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    # App that only echoes the requested URL back — must NOT confirm SSRF, even
    # though the echoed URL contains tokens like "iam/security-credentials".
    def echo(method: str, url: str, headers: Any, body: Any, timeout: int, **_k: Any) -> dict[str, Any]:
        return {"success": True, "status_code": 200, "body": "requested: " + unquote(url + (body or ""))}

    monkeypatch.setattr(inj, "_replay_impl", echo)
    out = st._ssrf_probe_impl("GET", "https://x/f", ["url"], None, None, "query", None, 12)
    assert out["finding_count"] == 0


def test_oast_blind_payload_emitted(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_fetching_server(monkeypatch)
    out = st._ssrf_probe_impl("GET", "https://x/f", ["url"], None, None, "query", "abc.oast.site", 12)
    blind = [f for f in out["findings"] if f["target"] == "blind-oast"]
    assert blind and "abc.oast.site" in blind[0]["payload"]


def test_empty_inputs_rejected() -> None:
    assert st._ssrf_probe_impl("GET", "", ["url"], None, None, "query", None, 12)["success"] is False
    assert st._ssrf_probe_impl("GET", "https://x", [], None, None, "query", None, 12)["success"] is False
