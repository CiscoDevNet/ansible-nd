# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Bind staged Network effects to the exact native, default-expanded request."""

from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import hashlib
import json

from ansible.module_utils.common.validation import check_type_bool, check_type_int, check_type_str


@lru_cache(maxsize=1)
def _network_spec():
    # Share the native argument contract without importing the module entry point
    # or depending on a second catalog of Network defaults.
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import network_parent_argument_spec

    return network_parent_argument_spec()


def _normalize_value(value, spec):
    """Apply only native, unambiguous scalar conversions and nested defaults."""
    kind = spec.get("type")
    if kind == "dict" and isinstance(value, dict):
        options = spec.get("options")
        return _normalize_options(value, options) if options else deepcopy(value)
    if kind == "list" and isinstance(value, list):
        element_spec = {"type": spec.get("elements"), "options": spec.get("options")}
        return [_normalize_value(item, element_spec) for item in value]
    converter = {"bool": check_type_bool, "int": check_type_int, "str": check_type_str}.get(kind)
    if converter is not None and isinstance(value, (str, bool, int, float)):
        try:
            return converter(value)
        except (TypeError, ValueError):
            pass
    # Invalid or future shapes remain distinguishable. Validation belongs to the
    # module; computing a digest must not silently discard unknown intent.
    return deepcopy(value)


def _normalize_options(value, options):
    result = {key: deepcopy(item) for key, item in value.items() if key not in options}
    for key, spec in options.items():
        item = value.get(key)
        if item is None:
            item = spec.get("default")
        if item is not None:
            result[key] = _normalize_value(item, spec)
    return result


def network_staging_request_digest(fabric, state, config, config_actions=None):
    """Return a deterministic SHA256 binding raw and Ansible-expanded requests.

    Known omitted/None options resolve to their native defaults or disappear.
    List order, explicit false/zero, unknown fields and explicit action contents
    are retained. No request data or shared argument specification is mutated.
    """
    payload = {
        "fabric_name": _normalize_value(fabric, {"type": "str"}),
        "state": _normalize_value(state, {"type": "str"}),
        "config": _normalize_value([] if config is None else config, {"type": "list", "elements": "dict", "options": _network_spec()}),
        "config_actions": {} if config_actions is None else deepcopy(config_actions),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
