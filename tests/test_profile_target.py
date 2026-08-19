"""profile_target.recommended_probes is a pure function of the fingerprint."""

from __future__ import annotations

from strix.tools.profile_target.tools import _recommended_probes


_ALWAYS = (
    "security_headers_probe",
    "header_leak",
    "frontend_secret_scan",
    "cors_probe",
)


def test_graphql_in_api_recommends_graphql_abuse() -> None:
    probes = _recommended_probes({"api": ["graphql"]})
    assert "graphql_abuse" in probes


def test_jwt_in_auth_recommends_jwt_audit() -> None:
    probes = _recommended_probes({"auth": ["jwt"]})
    assert "jwt_audit" in probes


def test_empty_profile_still_includes_always_on_header_probes() -> None:
    probes = _recommended_probes({})
    for name in _ALWAYS:
        assert name in probes


def test_recommendations_are_deduped() -> None:
    probes = _recommended_probes({"auth": ["jwt"], "baas": ["supabase"]})
    assert probes.count("jwt_audit") == 1


def test_oauth_supabase_firebase_and_endpoints() -> None:
    probes = _recommended_probes(
        {
            "auth": ["oauth"],
            "baas": ["supabase", "firebase"],
            "endpoints": ["/api/users"],
        }
    )
    assert "oauth_probe" in probes
    assert "backend_rules_probe" in probes
    assert "storage_probe" in probes
    assert "injection_fuzz" in probes
    assert "param_discover" in probes


def test_wordpress_adds_nothing_without_a_cms_tool() -> None:
    probes = _recommended_probes({"cms": "wordpress", "evidence": {"cms:wordpress": ["body"]}})
    assert not any("wordpress" in p or "wp_" in p for p in probes)
