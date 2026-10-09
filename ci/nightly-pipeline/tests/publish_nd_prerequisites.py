#!/usr/bin/env python3
from __future__ import annotations

"""Snapshot prerequisite release sources without exposing their content."""

import argparse
import base64
import dataclasses
import hashlib
import json
import os
import pathlib
import urllib.error
import urllib.parse
import urllib.request


@dataclasses.dataclass(frozen=True)
class KVRecord:
    key: str
    value: bytes | None
    modify_index: int
    exists: bool = True


class ReleaseError(RuntimeError):
    pass


ALLOWED_RELEASE_SOURCE_NAMES = frozenset({
    "nd_manage_acl.yaml", "nd_manage_prefix_list.yaml", "nd_manage_route_map.yaml", "nd_manage_vrfs.yaml", "nd_manage_networks.yaml", "nd_manage_policy.yaml", "nd_manage_policy_group.yaml", "nd_manage_switches.yaml", "nd_manage_vpc_pair.yaml", "nd_interface_vpc_access.yaml", "nd_interface_vpc_trunk_host.yaml", "nd_manage_vrf_lite.yaml", "nd_manage_l3out.yaml", "nd_manage_resource_manager.yaml", "nd_manage_fabric_ibgp_vxlan.yaml", "nd_manage_fabric_ebgp_vxlan.yaml", "nd_manage_fabric_ai_ibgp_vxlan.yaml", "nd_manage_fabric_ai_ebgp_vxlan.yaml", "nd_manage_fabric_external.yaml", "run_integration_module.yaml", "reset_fabric.yaml", "nd_prerequisite_profiles.yaml", "nd_prerequisite_wrapper.yaml", "nd_prerequisite_capture.yaml", "nd_prerequisite_reconcile.yaml", "nd_prerequisite_wait.yaml", "nd_prerequisite_verify.yaml", "nd_prerequisite_restore.yaml", "validate_nd_prerequisites.py", "publish_nd_prerequisites.py", "nd_prerequisite_release_manifest.json",
})


class ConsulKV:
    def __init__(self, address: str, timeout: int = 30):
        self.address = address.rstrip("/")
        self.timeout = timeout

    def read(self, key: str, allow_absent: bool = False) -> KVRecord:
        url = f"{self.address}/v1/kv/{urllib.parse.quote(key, safe='/')}"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and allow_absent:
                return KVRecord(key, None, 0, False)
            raise ReleaseError(f"Consul read failed for {key}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            raise ReleaseError(f"Consul read failed for {key}") from exc
        if not isinstance(payload, list) or len(payload) != 1 or payload[0].get("Value") is None:
            raise ReleaseError(f"missing Consul value: {key}")
        try:
            value = base64.b64decode(payload[0]["Value"], validate=True)
            revision = int(payload[0]["ModifyIndex"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ReleaseError(f"invalid Consul response for {key}") from exc
        if not value:
            raise ReleaseError(f"empty Consul value: {key}")
        return KVRecord(key, value, revision, True)


def _safe_key_path(root: pathlib.Path, key: str) -> pathlib.Path:
    relative = pathlib.PurePosixPath(key)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ReleaseError(f"unsafe Consul key: {key}")
    return root.joinpath(*relative.parts)


def _secure_directory(path: pathlib.Path, *, create: bool) -> None:
    if path.is_symlink():
        raise ReleaseError(f"snapshot destination is a symlink: {path}")
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ReleaseError(f"snapshot destination is not a directory: {path}")
    path.chmod(0o700)


def _write_restricted(path: pathlib.Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise ReleaseError(f"cannot safely create snapshot file: {path}") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(value)


def snapshot_keys(client, keys, output_dir, allow_absent=False):
    output_dir = pathlib.Path(output_dir)
    _secure_directory(output_dir, create=True)
    records = {}
    for key in keys:
        record = client.read(key, allow_absent=allow_absent)
        if record.exists:
            if not record.value:
                raise ReleaseError(f"empty Consul value: {key}")
            path = _safe_key_path(output_dir, key)
            if path.exists() or path.is_symlink():
                raise ReleaseError(f"snapshot path already exists or is a symlink: {path}")
            _secure_directory(path.parent, create=True)
            _write_restricted(path, record.value)
        records[key] = record
    return records


def _manifest_keys(path: pathlib.Path, prefix: str) -> list[str]:
    if prefix.rstrip("/") != "ansible-nd":
        raise ReleaseError("unsupported Consul prefix")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"cannot read key manifest: {path}") from exc
    entries = payload.get("files", payload.get("keys", payload)) if isinstance(payload, dict) else payload
    if not isinstance(entries, list):
        raise ReleaseError("key manifest must contain a list")
    keys = []
    for entry in entries:
        key = entry.get("key") if isinstance(entry, dict) else entry
        if not isinstance(key, str) or not key:
            raise ReleaseError("key manifest contains an invalid key")
        key = key.lstrip("/")
        if not key.startswith(prefix.rstrip("/") + "/"):
            key = prefix.rstrip("/") + "/" + key
        _safe_key_path(pathlib.Path("."), key)
        relative = pathlib.PurePosixPath(key).relative_to(prefix.rstrip("/"))
        if len(relative.parts) != 1 or relative.name not in ALLOWED_RELEASE_SOURCE_NAMES:
            raise ReleaseError(f"key is not an allowed release source: {key}")
        keys.append(key)
    if len(keys) != len(set(keys)):
        raise ReleaseError("key manifest contains duplicate keys")
    return keys


def _record_metadata(records):
    return {
        key: {
            "exists": record.exists,
            "modify_index": record.modify_index,
            **({"sha256": hashlib.sha256(record.value).hexdigest(), "bytes": len(record.value)} if record.exists else {}),
        }
        for key, record in sorted(records.items())
    }


def snapshot_command(args):
    output = pathlib.Path(args.output)
    if output.exists() or output.is_symlink():
        raise ReleaseError(f"snapshot output already exists or is a symlink: {output}")
    keys = _manifest_keys(pathlib.Path(args.keys_file), args.prefix)
    records = snapshot_keys(ConsulKV(args.address), keys, output, allow_absent=args.allow_absent)
    metadata = output / "records.json"
    _write_restricted(metadata, (json.dumps(_record_metadata(records), indent=2, sort_keys=True) + "\n").encode("utf-8"))


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    snapshot = subparsers.add_parser("snapshot", help="write restricted Consul before-images")
    snapshot.add_argument("--address", required=True)
    snapshot.add_argument("--prefix", default="ansible-nd")
    snapshot.add_argument("--keys-file", required=True)
    snapshot.add_argument("--output", required=True)
    snapshot.add_argument("--allow-absent", action="store_true")
    snapshot.set_defaults(handler=snapshot_command)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.handler(args)
    except ReleaseError as exc:
        raise SystemExit(f"error: {exc}") from exc


if __name__ == "__main__":
    main()
