"""npm_audit tool: parse severity counts, handle missing npm binary."""

from __future__ import annotations

import json
import subprocess
from typing import TYPE_CHECKING, Any

from strix.tools.npm_audit.tools import _audit_impl


if TYPE_CHECKING:
    import pytest


_SAMPLE_NEW_SCHEMA = json.dumps(
    {
        "vulnerabilities": {
            "lodash": {
                "severity": "high",
                "range": "<4.17.21",
                "fixAvailable": True,
                "via": [{"title": "Prototype Pollution in lodash"}],
            },
            "minimist": {
                "severity": "critical",
                "range": "<1.2.6",
                "fixAvailable": {"name": "minimist", "version": "1.2.6"},
                "via": [{"title": "Prototype Pollution in minimist"}],
            },
            "debug": {
                "severity": "low",
                "range": "2.0.0 - 3.0.0",
                "fixAvailable": False,
                "via": ["ms"],
            },
        }
    }
)

_SAMPLE_LEGACY_SCHEMA = json.dumps(
    {
        "advisories": {
            "1065": {
                "module_name": "handlebars",
                "severity": "moderate",
                "title": "Prototype Pollution",
                "vulnerable_versions": "<4.5.3",
                "patched_versions": ">=4.5.3",
            }
        }
    }
)


def _fake_run(stdout: str) -> Any:
    def _run(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        # npm audit exits 1 when vulns exist — parsing must ignore returncode.
        return subprocess.CompletedProcess(args=["npm"], returncode=1, stdout=stdout, stderr="")

    return _run


def test_missing_npm_returns_structured_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("strix.tools.npm_audit.tools.shutil.which", lambda _: None)
    result = _audit_impl(".", production_only=False)
    assert result["success"] is False
    assert result["hint"] == "install Node/npm"


def test_parses_new_schema_severity_counts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("strix.tools.npm_audit.tools.shutil.which", lambda _: "/usr/bin/npm")
    monkeypatch.setattr(
        "strix.tools.npm_audit.tools.subprocess.run", _fake_run(_SAMPLE_NEW_SCHEMA)
    )
    result = _audit_impl(".", production_only=False)
    assert result["success"] is True
    assert result["schema"] == "new"
    assert result["total"] == 3
    assert result["severity_counts"] == {
        "critical": 1,
        "high": 1,
        "moderate": 0,
        "low": 1,
        "info": 0,
    }
    # Sorted most-severe first.
    assert result["advisories"][0]["package"] == "minimist"
    assert result["advisories"][0]["fix_available"] is True
    assert result["advisories"][-1]["fix_available"] is False


def test_parses_legacy_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("strix.tools.npm_audit.tools.shutil.which", lambda _: "/usr/bin/npm")
    monkeypatch.setattr(
        "strix.tools.npm_audit.tools.subprocess.run", _fake_run(_SAMPLE_LEGACY_SCHEMA)
    )
    result = _audit_impl(".", production_only=False)
    assert result["success"] is True
    assert result["schema"] == "legacy"
    assert result["severity_counts"]["moderate"] == 1
    assert result["advisories"][0]["package"] == "handlebars"
