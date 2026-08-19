"""lfi_probe: deep path traversal / LFI via content signatures, FP-suppressed."""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.lfi_probe import tools as lt


def _vuln_reader(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(method: str, url: str, headers: Any, body: Any, timeout: int, **_k: Any) -> dict[str, Any]:
        blob = url + (body or "")
        if "passwd" in blob:  # any traversal/encoding reaching /etc/passwd
            return {"success": True, "status_code": 200, "body": "root:x:0:0:root:/root:/bin/bash"}
        if "win.ini" in blob:
            return {"success": True, "status_code": 200, "body": "[fonts]\n[extensions]"}
        return {"success": True, "status_code": 200, "body": "<html>index</html>"}

    monkeypatch.setattr(lt, "_replay_impl", fake)


def test_confirms_file_read(monkeypatch: pytest.MonkeyPatch) -> None:
    _vuln_reader(monkeypatch)
    out = lt._lfi_probe_impl("GET", "https://x/dl", ["file"], None, None, "query", 12)
    assert out["possible_lfi"] is True
    assert out["finding_count"] == 1  # stops at first confirmed encoding per param


def test_reflection_not_confirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    def echo(method: str, url: str, headers: Any, body: Any, timeout: int, **_k: Any) -> dict[str, Any]:
        return {"success": True, "status_code": 200, "body": "requested: " + url + (body or "")}

    monkeypatch.setattr(lt, "_replay_impl", echo)
    out = lt._lfi_probe_impl("GET", "https://x/dl", ["file"], None, None, "query", 12)
    assert out["finding_count"] == 0


def test_encodings_sent_verbatim(monkeypatch: pytest.MonkeyPatch) -> None:
    # The double-encoded payload must reach the server unchanged (not re-encoded).
    seen: list[str] = []

    def cap(method: str, url: str, headers: Any, body: Any, timeout: int, **_k: Any) -> dict[str, Any]:
        seen.append(url)
        return {"success": True, "status_code": 200, "body": "nothing"}

    monkeypatch.setattr(lt, "_replay_impl", cap)
    lt._lfi_probe_impl("GET", "https://x/dl", ["file"], None, None, "query", 12)
    assert any("%252e%252e%252f" in u for u in seen)


def test_empty_inputs_rejected() -> None:
    assert lt._lfi_probe_impl("GET", "", ["f"], None, None, "query", 12)["success"] is False
    assert lt._lfi_probe_impl("GET", "https://x", [], None, None, "query", 12)["success"] is False
