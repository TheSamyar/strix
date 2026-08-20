"""Unit checks for the blind-SQLi inference core against a fake oracle (no network)."""

from __future__ import annotations

from strix.tools.sqli_dump.tools import (
    _mssql,
    _mysql,
    _place,
    _postgres,
    _sqlite,
    extract_string,
)


def test_extraction_recovers_known_bounded() -> None:
    known = "R0w-Value_42"
    calls = {"n": 0}

    def fake_len_gt(n: int) -> bool:
        calls["n"] += 1
        return len(known) > n

    def fake_char_gt(pos: int, val: int) -> bool:
        calls["n"] += 1
        return ord(known[pos - 1]) > val

    got = extract_string(fake_len_gt, fake_char_gt, 64)
    assert got == known
    per_char = 7  # binary search over 0..127
    assert calls["n"] <= (len(known) + 1) * (per_char + 1) + 10


def test_extraction_edge_cases() -> None:
    assert extract_string(lambda n: n < 0, lambda _p, _v: False, 64) == ""
    one = extract_string(lambda n: n < 1, lambda _p, v: ord("A") > v, 64)
    assert one == "A"


def test_dialect_fragments() -> None:
    my_time = _mysql().time_cond
    pg_time = _postgres().time_cond
    ms_time = _mssql().time_cond
    assert my_time and "SLEEP(" in my_time("1=1", 5)
    assert pg_time and "pg_sleep(" in pg_time("1=1", 5)
    assert ms_time and "WAITFOR DELAY" in ms_time("1=1", 5)
    assert _sqlite().time_cond is None
    assert "UNICODE(SUBSTR(" in _sqlite().substr("x", 1)
    assert "ASCII(SUBSTRING(" in _mysql().substr("x", 1)
    assert "information_schema.tables" in _mysql().tables_expr(0)
    assert "sqlite_master" in _sqlite().tables_expr(0)


def test_payload_placement() -> None:
    url, _ = _place("http://t/i?id=1{PAYLOAD}", None, " AND 1=1")
    assert url == "http://t/i?id=1 AND 1=1"
    url2, _ = _place("http://t/i?id=1", None, " AND 1=1")
    assert "AND" in url2
