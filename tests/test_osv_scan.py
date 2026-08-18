"""osv_scan: lockfile parsing + OSV response mapping with mocked requests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import requests

from strix.tools.osv_scan import tools as osv


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


_PACKAGE_LOCK = json.dumps(
    {
        "name": "demo",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.11"},
            "node_modules/left-pad": {"version": "1.3.0"},
        },
    }
)


def test_parse_package_lock() -> None:
    pkgs = osv._parse_package_lock(_PACKAGE_LOCK)
    names = {(p["name"], p["version"], p["ecosystem"]) for p in pkgs}
    assert ("lodash", "4.17.11", "npm") in names
    assert ("left-pad", "1.3.0", "npm") in names
    assert all(p["name"] != "demo" for p in pkgs)  # root project skipped


def test_maps_osv_response_to_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "package-lock.json").write_text(_PACKAGE_LOCK, encoding="utf-8")

    class _Resp:
        def __init__(self, payload: dict[str, Any]) -> None:
            self._payload = payload

        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, Any]:
            return self._payload

    def fake_post(_url: str, **_: Any) -> _Resp:
        # lodash vulnerable, left-pad clean (order matches input queries)
        return _Resp({"results": [{"vulns": [{"id": "GHSA-xxxx"}]}, {}]})

    def fake_get(_url: str, **_: Any) -> _Resp:
        return _Resp(
            {
                "summary": "Prototype pollution in lodash",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
            }
        )

    monkeypatch.setattr(osv.requests, "post", fake_post)
    monkeypatch.setattr(osv.requests, "get", fake_get)

    result = osv._scan_impl(str(tmp_path), None)
    assert result["success"] is True
    assert result["packages_checked"] == 2
    assert result["vulnerable_count"] == 1
    vuln = result["vulnerable_packages"][0]
    assert vuln["package"] == "lodash"
    assert vuln["vuln_ids"] == ["GHSA-xxxx"]
    assert "Prototype pollution" in vuln["summary"]
    assert vuln["severity"].startswith("CVSS")


def test_network_error_is_structured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "package-lock.json").write_text(_PACKAGE_LOCK, encoding="utf-8")

    def boom(*_: Any, **__: Any) -> None:
        raise requests.ConnectionError("unreachable")

    monkeypatch.setattr(osv.requests, "post", boom)

    result = osv._scan_impl(str(tmp_path), None)
    assert result["success"] is False
    assert "OSV API request failed" in result["error"]


def test_no_lockfiles_message(tmp_path: Path) -> None:
    result = osv._scan_impl(str(tmp_path), None)
    assert result["success"] is True
    assert result["vulnerable_count"] == 0
    assert "No supported lockfiles" in result["message"]
