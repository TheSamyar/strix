from __future__ import annotations

import pytest

from strix.audit import jobs_for_mode


def test_quick_has_four_jobs() -> None:
    jobs = jobs_for_mode("quick")
    assert [j.id for j in jobs] == ["recon", "auth", "injection", "access"]
    assert jobs[0].skills == ("asset_discovery",)
    assert jobs[2].skills == ("sql_injection", "xss", "rce")


def test_standard_extends_quick() -> None:
    ids = [j.id for j in jobs_for_mode("standard")]
    assert ids == ["recon", "auth", "injection", "access", "ssrf_files", "secrets_deps"]


def test_deep_extends_standard() -> None:
    ids = [j.id for j in jobs_for_mode("deep")]
    assert ids[-2:] == ["logic", "deser_ssti"]
    assert len(ids) == 8


def test_unknown_mode_raises() -> None:
    with pytest.raises(ValueError, match="scan-mode"):
        jobs_for_mode("turbo")
