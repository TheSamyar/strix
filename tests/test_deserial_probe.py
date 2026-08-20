"""Unit checks for the deserialization fingerprint + payload logic (no network)."""

from __future__ import annotations

import base64
import os
import pickle

from strix.tools.deserial_probe.tools import _gen_node, _PickleRCE, _place, fingerprint


def test_fingerprint_formats() -> None:
    assert fingerprint("rO0ABXNy") == ["java"]
    assert "node" in fingerprint('{"a":"_$$ND_FUNC$$_function(){}()"}')
    assert fingerprint('O:8:"stdClass":0:{}') == ["php"]
    assert fingerprint(base64.b64encode(pickle.dumps({1: 2})).decode()) == ["python"]
    assert fingerprint("") == []


def test_node_gadget_runs_command() -> None:
    node = _gen_node("id")
    assert b"child_process" in node
    assert b"'id'" in node


def test_pickle_gadget_reduces_to_os_system() -> None:
    reduced = _PickleRCE("echo hi").__reduce__()
    assert reduced[0] is os.system
    assert reduced[1] == ("echo hi",)


def test_injection_placement() -> None:
    _, headers, _ = _place("cookie", "sess", "PAY", "http://t/", {}, None)
    assert headers["Cookie"] == "sess=PAY"
    url, _, _ = _place("query", "d", "PAY", "http://t/x?a=1", {}, None)
    assert url.endswith("a=1&d=PAY")
