"""Turn a target profile into a tailored test plan + seeded todos.

``profile_target`` says what the target IS; this says what to TEST and with
which tools/skills, so the agent stops blindly running every class top-down.
Always-on items (access control, secrets, CORS, info disclosure) plus
stack-specific items (Supabase RLS, GraphQL introspection, JWT, WordPress, …).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.todo.tools import seed_todos


PLAN_MARKER = "[plan]"

# Always test these regardless of stack.
_BASELINE: tuple[dict[str, Any], ...] = (
    {
        "area": "Access control (IDOR/BOLA/BFLA)",
        "why": "The #1 bug in generated CRUD; object refs rarely scoped to the caller.",
        "tools": ["authz_probe"],
        "skills": ["idor", "broken_function_level_authorization"],
        "priority": "high",
    },
    {
        "area": "Client-leaked secrets",
        "why": "Vibe apps bake keys into shipped JS bundles.",
        "tools": ["frontend_secret_scan"],
        "skills": ["cryptographic_failures"],
        "priority": "high",
    },
    {
        "area": "Info disclosure (.env / debug / stack traces)",
        "why": "Scaffolds ship debug on and framework error pages.",
        "tools": ["run_scanner"],
        "skills": ["information_disclosure"],
        "priority": "medium",
    },
    {
        "area": "Permissive CORS",
        "why": "Reflected Origin + credentials is a common generated default.",
        "tools": ["cors_probe"],
        "skills": [],
        "priority": "medium",
    },
    {
        "area": "Missing rate limiting",
        "why": "Login/OTP/reset ship unthrottled.",
        "tools": ["rate_limit_probe"],
        "skills": [],
        "priority": "medium",
    },
    {
        "area": "Blind SSRF on URL/webhook params",
        "why": "URL-handling features almost always lack an allowlist.",
        "tools": ["oast_get_domain", "oast_poll"],
        "skills": ["ssrf"],
        "priority": "medium",
    },
    {
        "area": "Injection (SQLi / NoSQLi / command / SSTI)",
        "why": "Any param that reaches a query/shell/template; the highest-impact class.",
        "tools": ["injection_fuzz", "deep_fuzz"],
        "skills": ["sql_injection", "nosql_injection", "ssti"],
        "priority": "high",
    },
    {
        "area": "XSS (reflected / stored / DOM)",
        "why": "User input echoed into HTML/JS; stored variants pivot to account takeover.",
        "tools": ["stored_probe"],
        "skills": ["xss"],
        "priority": "high",
    },
    {
        "area": "Mass assignment / over-posting",
        "why": "Create/update endpoints accept fields the UI never sends (role/is_admin).",
        "tools": ["mass_assignment_probe"],
        "skills": ["mass_assignment"],
        "priority": "high",
    },
    {
        "area": "Open redirect",
        "why": "redirect/next/return_to params without an allowlist enable phishing/token theft.",
        "tools": ["redirect_probe"],
        "skills": ["open_redirect"],
        "priority": "medium",
    },
    {
        "area": "Business-logic abuse",
        "why": "Quantity/price/state-machine flaws no scanner catches; reason about the workflow.",
        "tools": [],
        "skills": ["business_logic", "race_conditions"],
        "priority": "medium",
    },
)

# profile signal -> extra recommendation.
_BAAS_RULES: dict[str, dict[str, Any]] = {
    "supabase": {
        "area": "Broken Supabase RLS",
        "why": "~60% of AI Supabase apps ship broken Row Level Security.",
        "tools": ["backend_rules_probe"],
        "skills": ["supabase", "data_leakage"],
        "priority": "high",
    },
    "firebase": {
        "area": "Open Firebase rules",
        "why": "Public Realtime DB rules leak the whole tree at /<path>.json.",
        "tools": ["backend_rules_probe"],
        "skills": ["firebase"],
        "priority": "high",
    },
}
_API_RULES: dict[str, dict[str, Any]] = {
    "graphql": {
        "area": "GraphQL introspection + abuse",
        "why": "Introspection left on hands over the schema for every other attack.",
        "tools": ["graphql_introspection"],
        "skills": ["graphql"],
        "priority": "high",
    },
    "rest": {
        "area": "API Security Top 10 pass",
        "why": "REST APIs fail per-object/per-function authz.",
        "tools": [],
        "skills": ["api_security_top10"],
        "priority": "medium",
    },
}
_AUTH_RULES: dict[str, dict[str, Any]] = {
    "jwt": {
        "area": "JWT misconfiguration",
        "why": "Generated JWTs skip verification / use weak secrets.",
        "tools": ["jwt_audit"],
        "skills": ["authentication_jwt"],
        "priority": "high",
    },
    "oauth": {
        "area": "OAuth flow flaws",
        "why": "redirect_uri, state/CSRF, PKCE downgrade.",
        "tools": [],
        "skills": ["oauth"],
        "priority": "medium",
    },
    "session_cookie": {
        "area": "CSRF / session handling",
        "why": "Cookie auth without CSRF protection or secure flags.",
        "tools": [],
        "skills": ["csrf"],
        "priority": "medium",
    },
}
# profile signal -> AI/LLM-specific recommendation.
_AI_RULES: dict[str, dict[str, Any]] = {
    "llm": {
        "area": "Prompt injection + LLM abuse",
        "why": "Direct/indirect prompt injection, tool/function abuse, and MCP tool poisoning.",
        "tools": ["prompt_injection_probe", "mcp_tool_poisoning_audit"],
        "skills": ["llm_prompt_injection", "ai_ml_security"],
        "priority": "high",
    },
}
# framework -> skill pack that exists in the repo.
_FRAMEWORK_SKILL = {
    "nextjs": "nextjs",
    "django": "django",
    "fastapi": "fastapi",
    "nestjs": "nestjs",
}


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)] if value else []


def _build_plan(profile: dict[str, Any]) -> list[dict[str, Any]]:
    plan: list[dict[str, Any]] = list(_BASELINE)
    plan.extend(_BAAS_RULES[b] for b in _as_list(profile.get("baas")) if b in _BAAS_RULES)
    plan.extend(_API_RULES[a] for a in _as_list(profile.get("api")) if a in _API_RULES)
    plan.extend(_AUTH_RULES[a] for a in _as_list(profile.get("auth")) if a in _AUTH_RULES)
    plan.extend(_AI_RULES[a] for a in _as_list(profile.get("ai")) if a in _AI_RULES)
    framework = profile.get("framework")
    if isinstance(framework, str) and framework in _FRAMEWORK_SKILL:
        plan.append(
            {
                "area": f"{framework} framework-specific tests",
                "why": f"Test {framework}-specific exposure (routes, debug, source maps).",
                "tools": [],
                "skills": [_FRAMEWORK_SKILL[framework]],
                "priority": "medium",
            }
        )
    if profile.get("cms") == "wordpress":
        plan.append(
            {
                "area": "WordPress scan",
                "why": "Plugin/theme CVEs and user enumeration.",
                "tools": ["run_scanner (wpscan)"],
                "skills": [],
                "priority": "medium",
            }
        )
    if _as_list(profile.get("cdn_waf")):
        plan.append(
            {
                "area": "Web cache deception / poisoning",
                "why": "A CDN in front raises cache-key confusion risk.",
                "tools": ["http_replay"],
                "skills": [],
                "priority": "low",
            }
        )
    return plan


def _plan_tests_impl(profile: dict[str, Any], agent_id: str, seed: bool) -> dict[str, Any]:
    if not isinstance(profile, dict) or not profile:
        return {"success": False, "error": "profile must be the dict returned by profile_target"}
    plan = _build_plan(profile)
    seeded = 0
    if seed:
        todos = [
            {
                "title": (
                    f"{PLAN_MARKER} {rec['area']} — "
                    f"tools: {', '.join(rec['tools']) or 'manual'}"
                ),
                "description": f"{rec['why']} Load skills: {', '.join(rec['skills']) or 'none'}.",
            }
            for rec in plan
        ]
        seeded = seed_todos(agent_id, todos)
    return {
        "success": True,
        "target": profile.get("final_url") or profile.get("url"),
        "recommendation_count": len(plan),
        "seeded_todos": seeded,
        "supabase_ready": bool(profile.get("supabase_url") and profile.get("supabase_anon_key")),
        "plan": plan,
    }


@function_tool(timeout=30, strict_mode=False)
async def plan_tests(
    ctx: RunContextWrapper,
    profile: dict[str, Any],
    seed: bool = True,
) -> str:
    """Turn a ``profile_target`` result into a tailored test plan and seed todos.

    Maps the detected stack to the vuln classes, skills, and probe tools that
    matter for THIS target (baseline access-control/secrets/CORS/info-disclosure
    plus stack-specific items — Supabase RLS, GraphQL, JWT, WordPress, …), and
    (by default) seeds a ``[plan]`` todo per item so nothing gets skipped. If the
    profile carried a Supabase URL + anon key, ``supabase_ready`` flags that
    ``backend_rules_probe`` can run immediately.

    Returns JSON with ``plan`` (area/why/tools/skills/priority), ``seeded_todos``,
    and ``supabase_ready``.

    Args:
        profile: The JSON object returned by ``profile_target``.
        seed: Seed a ``[plan]`` todo per recommendation (default True).
    """
    agent_id = "mcp"
    if isinstance(ctx.context, dict):
        agent_id = str(ctx.context.get("agent_id") or "mcp")
    return json.dumps(
        await asyncio.to_thread(_plan_tests_impl, profile, agent_id, seed),
        ensure_ascii=False,
        default=str,
    )
