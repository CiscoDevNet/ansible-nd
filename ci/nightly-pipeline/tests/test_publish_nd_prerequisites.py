import base64
import io
import json
import pathlib
import sys
import urllib.error

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

import publish_nd_prerequisites as release
from publish_nd_prerequisites import ConsulKV, KVRecord, ReleaseError, _manifest_keys, snapshot_keys


class FakeConsul:
    def __init__(self, records):
        self.records = {
            key: KVRecord(key, value, revision, True)
            for key, (revision, value) in records.items()
        }
        self.put_order = []

    def read(self, key, allow_absent=False):
        if key in self.records:
            return self.records[key]
        if allow_absent:
            return KVRecord(key, None, 0, False)
        raise ReleaseError(f"missing Consul value: {key}")


def test_snapshot_decodes_bytes_and_records_revision(tmp_path):
    client = FakeConsul({"ansible-nd/nd_manage_acl.yaml": (41, b"---\\n- hosts: nd\\n")})
    records = snapshot_keys(client, ["ansible-nd/nd_manage_acl.yaml"], tmp_path)
    record = records["ansible-nd/nd_manage_acl.yaml"]
    assert record.modify_index == 41
    assert record.value == b"---\\n- hosts: nd\\n"
    assert (tmp_path / "ansible-nd" / "nd_manage_acl.yaml").read_bytes() == record.value
    assert (tmp_path.stat().st_mode & 0o777) == 0o700
    assert ((tmp_path / "ansible-nd" / "nd_manage_acl.yaml").stat().st_mode & 0o777) == 0o600


def test_snapshot_rejects_empty_or_missing_key(tmp_path):
    client = FakeConsul({"ansible-nd/empty.yaml": (9, b"")})
    with pytest.raises(ReleaseError, match="empty"):
        snapshot_keys(client, ["ansible-nd/empty.yaml"], tmp_path)
    with pytest.raises(ReleaseError, match="missing"):
        snapshot_keys(client, ["ansible-nd/missing.yaml"], tmp_path)


def test_publication_snapshot_records_absent_new_key_without_creating_it(tmp_path):
    client = FakeConsul({})
    records = snapshot_keys(client, ["ansible-nd/nd_prerequisite_wrapper.yaml"], tmp_path, allow_absent=True)
    assert records["ansible-nd/nd_prerequisite_wrapper.yaml"] == KVRecord(
        key="ansible-nd/nd_prerequisite_wrapper.yaml", value=None,
        modify_index=0, exists=False,
    )
    assert client.put_order == []


def test_snapshot_rejects_unsafe_output_path(tmp_path):
    client = FakeConsul({"ansible-nd/nd_manage_acl.yaml": (41, b"x")})
    output = tmp_path / "snapshot"
    output.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(ReleaseError, match="symlink"):
        snapshot_keys(client, ["ansible-nd/nd_manage_acl.yaml"], output)


class FakeResponse(io.StringIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_consul_read_decodes_base64_and_handles_missing(monkeypatch):
    payload = [{"Key": "ansible-nd/nd_manage_acl.yaml", "Value": base64.b64encode(b"body").decode(), "ModifyIndex": 41}]
    monkeypatch.setattr(release.urllib.request, "urlopen", lambda *args, **kwargs: FakeResponse(json.dumps(payload)))
    assert ConsulKV("http://consul").read("ansible-nd/nd_manage_acl.yaml") == KVRecord(
        "ansible-nd/nd_manage_acl.yaml", b"body", 41, True
    )
    def missing(*args, **kwargs):
        raise urllib.error.HTTPError("http://consul", 404, "missing", {}, None)
    monkeypatch.setattr(release.urllib.request, "urlopen", missing)
    assert ConsulKV("http://consul").read("ansible-nd/new.yaml", allow_absent=True).exists is False
    with pytest.raises(ReleaseError, match="HTTP 404"):
        ConsulKV("http://consul").read("ansible-nd/new.yaml")


def test_snapshot_uses_restrictive_create_mode(monkeypatch, tmp_path):
    observed = []
    original_open = release.os.open
    def guarded_open(path, flags, mode=0o777):
        observed.append((flags, mode))
        return original_open(path, flags, mode)
    monkeypatch.setattr(release.os, "open", guarded_open)
    snapshot_keys(FakeConsul({"ansible-nd/nd_manage_acl.yaml": (41, b"body")}), ["ansible-nd/nd_manage_acl.yaml"], tmp_path)
    assert any(mode == 0o600 for _, mode in observed)


def test_manifest_rejects_inventory_and_output_keys(tmp_path):
    manifest = tmp_path / "keys.json"
    manifest.write_text(json.dumps(["inventory.yaml", "test_output.yml"]))
    with pytest.raises(ReleaseError, match="not an allowed release source"):
        _manifest_keys(manifest, "ansible-nd")


def test_manifest_rejects_non_release_prefix(tmp_path):
    manifest = tmp_path / "keys.json"
    manifest.write_text(json.dumps(["nd_manage_acl.yaml"]))
    with pytest.raises(ReleaseError, match="unsupported Consul prefix"):
        _manifest_keys(manifest, "secrets")
