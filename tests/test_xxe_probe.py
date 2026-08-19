"""xxe_probe: XXE via content signatures, reflection-FP suppression, blind OOB."""

from __future__ import annotations

from typing import Any

import pytest

from strix.tools.xxe_probe import tools as xt


def _vuln_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    """Parser that resolves file:// entities and reflects the content."""

    def fake(method: str, url: str, headers: Any, body: Any, timeout: int, **_k: Any) -> dict[str, Any]:
        b = body or ""
        if "file:///etc/passwd" in b:
            return {"success": True, "status_code": 200, "body": "<r>root:x:0:0:root:/root:/bin/bash</r>"}
        return {"success": True, "status_code": 200, "body": "<r></r>"}

    monkeypatch.setattr(xt, "_replay_impl", fake)


def test_confirms_file_read_via_content(monkeypatch: pytest.MonkeyPatch) -> None:
    _vuln_parser(monkeypatch)
    out = xt._xxe_probe_impl("https://x/soap", "POST", None, None, "application/xml", None, 15)
    assert out["possible_xxe"] is True
    assert any(f["target"] == "xxe-file-passwd" for f in out["findings"])


def test_reflection_not_falsely_confirmed(monkeypatch: pytest.MonkeyPatch) -> None:
    # App echoes the raw request (incl. the file:// system URL) but never parses
    # the entity — must NOT be confirmed.
    def echo(method: str, url: str, headers: Any, body: Any, timeout: int, **_k: Any) -> dict[str, Any]:
        return {"success": True, "status_code": 200, "body": "you sent: " + (body or "")}

    monkeypatch.setattr(xt, "_replay_impl", echo)
    out = xt._xxe_probe_impl("https://x/soap", "POST", None, None, "application/xml", None, 15)
    assert out["finding_count"] == 0


def test_template_marker_and_blind_oob(monkeypatch: pytest.MonkeyPatch) -> None:
    _vuln_parser(monkeypatch)
    tmpl = '<?xml version="1.0"?><data><name>XXEINJECT</name></data>'
    out = xt._xxe_probe_impl("https://x/", "POST", tmpl, None, "application/xml", "h.oast", 15)
    blind = [f for f in out["findings"] if f["target"] == "blind-oob"]
    assert blind and "h.oast" in blind[0]["system_url"]


def test_doc_inserts_doctype_after_declaration() -> None:
    tmpl = '<?xml version="1.0"?><data>XXEINJECT</data>'
    doc = xt._doc("file:///etc/passwd", tmpl)
    assert doc.startswith('<?xml version="1.0"?><!DOCTYPE')
    assert "&xxe;" in doc and "XXEINJECT" not in doc


def test_empty_url_rejected() -> None:
    assert xt._xxe_probe_impl("", "POST", None, None, "application/xml", None, 15)["success"] is False
