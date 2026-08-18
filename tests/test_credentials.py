"""Per-run credential store: label/value round-trip, 0o600, re-hydrate, delete."""

from __future__ import annotations

import json
import stat
from typing import TYPE_CHECKING

from strix.tools.credentials.tools import (
    _delete_credential_impl,
    _get_credential_impl,
    _list_credentials_impl,
    _store_credential_impl,
    hydrate_credentials_from_disk,
)


if TYPE_CHECKING:
    from pathlib import Path


def test_store_list_get_mode_rehydrate_delete(tmp_path: Path) -> None:
    hydrate_credentials_from_disk(tmp_path)

    assert _store_credential_impl("admin", "hunter2", note="role=admin")["success"] is True

    # list shows label + note, never the value.
    listed = _list_credentials_impl()
    (entry,) = listed["credentials"]
    assert entry["label"] == "admin"
    assert entry["note"] == "role=admin"
    assert "value" not in entry
    assert "hunter2" not in json.dumps(listed)

    # get returns the value.
    assert _get_credential_impl("admin")["value"] == "hunter2"

    # file is 0o600.
    cred_file = tmp_path / "credentials.json"
    assert cred_file.is_file()
    assert stat.S_IMODE(cred_file.stat().st_mode) == 0o600

    # survives a re-hydrate (fresh process reading the same run dir).
    hydrate_credentials_from_disk(tmp_path)
    assert _get_credential_impl("admin")["value"] == "hunter2"

    # delete works.
    assert _delete_credential_impl("admin")["success"] is True
    assert _get_credential_impl("admin")["success"] is False


def test_upsert_on_label(tmp_path: Path) -> None:
    hydrate_credentials_from_disk(tmp_path)
    _store_credential_impl("u", "v1")
    _store_credential_impl("u", "v2")
    assert _list_credentials_impl()["total_count"] == 1
    assert _get_credential_impl("u")["value"] == "v2"
