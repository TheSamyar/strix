"""cve_lookup: NVD CVE parsing, OSV package parsing, and missing-arg error."""

from __future__ import annotations

from typing import Any

from strix.tools.cve_lookup.tools import _cve_lookup_impl


class _FakeResp:
    def __init__(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def json(self) -> dict[str, Any]:
        return self._payload


_NVD_SAMPLE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2023-11-07T03:39:39.203",
                "descriptions": [{"lang": "en", "value": "Log4Shell JNDI RCE."}],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
                "weaknesses": [
                    {"description": [{"lang": "en", "value": "CWE-502"}]}
                ],
                "references": [{"url": "https://logging.apache.org/log4j/"}],
            }
        }
    ]
}

_OSV_SAMPLE = {
    "vulns": [
        {
            "id": "GHSA-jfh8-c2jp-5v3q",
            "aliases": ["CVE-2021-44228"],
            "summary": "Remote code execution in Log4j",
            "affected": [
                {
                    "package": {"name": "org.apache.logging.log4j:log4j-core"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0"}]}],
                    "versions": ["2.14.1"],
                }
            ],
        }
    ]
}


def test_cve_parses_cvss(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "strix.tools.cve_lookup.tools.requests.get",
        lambda *_a, **_k: _FakeResp(_NVD_SAMPLE),
    )
    result = _cve_lookup_impl("cve-2021-44228", None, None)
    assert result["success"] is True
    assert result["cve"] == "CVE-2021-44228"
    assert result["cvss"]["score"] == 10.0
    assert result["cvss"]["severity"] == "CRITICAL"
    assert result["cvss"]["vector"].startswith("CVSS:3.1/")
    assert "CWE-502" in result["cwe"]


def test_package_parses_advisories(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "strix.tools.cve_lookup.tools.requests.post",
        lambda *_a, **_k: _FakeResp(_OSV_SAMPLE),
    )
    result = _cve_lookup_impl(None, "log4j-core", "Maven")
    assert result["success"] is True
    assert result["advisory_count"] == 1
    assert result["advisories"][0]["id"] == "GHSA-jfh8-c2jp-5v3q"
    assert "CVE-2021-44228" in result["advisories"][0]["aliases"]


def test_no_params_returns_error() -> None:
    result = _cve_lookup_impl(None, None, None)
    assert result["success"] is False
    assert "error" in result
