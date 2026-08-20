"""plan_tests: baseline always covers the high-impact classes; AI targets get prompt-injection."""

from __future__ import annotations

from strix.tools.plan_tests.tools import _BASELINE, _build_plan


def _areas(plan: list[dict[str, object]]) -> str:
    return " | ".join(str(p["area"]).lower() for p in plan)


def test_baseline_covers_injection_xss_and_access_control() -> None:
    areas = _areas(list(_BASELINE))
    for needed in ("injection", "xss", "mass assignment", "open redirect", "access control"):
        assert needed in areas, needed


def test_ai_target_plans_prompt_injection() -> None:
    plan = _build_plan({"ai": ["llm"], "framework": "nextjs"})
    areas = _areas(plan)
    assert "prompt injection" in areas
    # non-AI target does not get it
    assert "prompt injection" not in _areas(_build_plan({"framework": "nextjs"}))


def test_graphql_and_jwt_signals_still_layer_on() -> None:
    plan = _build_plan({"api": ["graphql"], "auth": ["jwt"]})
    areas = _areas(plan)
    assert "graphql" in areas
    assert "jwt" in areas
