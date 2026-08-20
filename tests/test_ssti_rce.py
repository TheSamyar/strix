"""Unit checks for the SSTI fingerprint + RCE payload logic (no network)."""

from __future__ import annotations

from strix.tools.ssti_rce.tools import (
    _ALL_ENGINES,
    _DELAY_THRESHOLD_MS,
    _PRODUCT,
    _delayed,
    _place,
    candidates_from_body,
    disambiguate,
    rce_payloads,
)


def test_candidates_narrowing() -> None:
    cands = candidates_from_body(f"result is {_PRODUCT} ok")
    assert {"jinja2", "twig", "freemarker"} <= set(cands)
    assert candidates_from_body("no product here") == []


def test_disambiguate_jinja_string_repeat() -> None:
    assert disambiguate("out: zzzzzzzzzzzzzz done") == "jinja2"
    assert disambiguate("out: 49") is None


def test_every_engine_has_command_payload() -> None:
    for eng in _ALL_ENGINES:
        pays = rce_payloads(eng, "sleep 8")
        assert pays
        assert all("sleep" in p for p in pays)
    assert "os.popen('sleep 8')" in rce_payloads("jinja2", "sleep 8")[0]


def test_payload_carries_raw_command() -> None:
    inj = rce_payloads("jinja2", "id;whoami")[0]
    assert "id;whoami" in inj


def test_time_delay_oracle() -> None:
    assert _delayed(120.0, 120.0 + _DELAY_THRESHOLD_MS + 1)
    assert not _delayed(120.0, 300.0)


def test_injection_placement() -> None:
    url, _, _ = _place("http://t/p?a=1", "q", "query", "PAY", {}, None)
    assert "q=PAY" in url
    assert "a=1" in url
    _, _, body = _place("http://t/p", "q", "body", "PAY", {}, "x={PAYLOAD}")
    assert body == "x=PAY"
