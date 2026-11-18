# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Compose writable attachment intent from the task's existing inventory."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


def instance_values(value: dict[str, Any] | None, model: type, *, keep_unknown: bool = False) -> dict[str, Any]:
    """Canonicalize known writable aliases without injecting request defaults."""
    aliases = {name: field.alias or name for name, field in model.model_fields.items()}
    writable = set(aliases.values())
    return {aliases.get(key, key): item for key, item in (value or {}).items() if keep_unknown or aliases.get(key, key) in writable}


def effective_attachment(
    current: dict[str, Any] | None,
    desired: dict[str, Any],
    *,
    state: str,
    model: type,
    managed_options: set[str],
    option_defaults: dict[str, Any] | None = None,
    interfaces: bool = False,
) -> dict[str, Any]:
    """Merge omissions or reset managed properties without replaying operational fields."""
    result = deepcopy(desired)
    saved = current or {}
    existing_options = instance_values(saved.get("instanceValues"), model)
    requested_options = instance_values(result.get("instanceValues"), model, keep_unknown=True)
    reset = state != "merged" or "instanceValues" in result and not requested_options
    if reset:
        options = {key: value for key, value in existing_options.items() if key not in managed_options}
        options.update({key: value for key, value in (option_defaults or {}).items() if key in existing_options or key in requested_options})
    else:
        options = existing_options
    options = {**options, **requested_options}
    if options or "instanceValues" in result or existing_options and reset:
        result["instanceValues"] = deepcopy(options)
    if not result.get("_clearVlanId") and "vlanId" not in result and saved.get("vlanId") is not None:
        result["vlanId"] = saved["vlanId"]
    if "extraConfig" not in result:
        if state == "merged" and saved.get("extraConfig"):
            result["extraConfig"] = saved["extraConfig"]
        elif saved.get("extraConfig") and state != "merged":
            result["extraConfig"] = ""
    if interfaces and "interfaces" not in result:
        if state == "merged" and saved.get("interfaces") is not None:
            result["interfaces"] = deepcopy(saved["interfaces"])
        elif current is not None and state != "merged":
            result["interfaces"] = []
    return result


def instance_values_match(current: dict[str, Any] | None, desired: dict[str, Any] | None, model: type, defaults: dict[str, Any] | None = None) -> bool:
    """Compare complete writable options, equating omitted and cleared collections."""
    for name, field in model.model_fields.items():
        alias = field.alias or name
        if name != alias and name in (desired or {}) and alias in desired and desired[name] != desired[alias]:
            return False
    want = instance_values(desired, model, keep_unknown=True)
    have = instance_values(current, model)
    have.update({key: value for key, value in (current or {}).items() if key in want and key not in have})
    for key, value in (defaults or {}).items():
        if key in have or key in want:
            have.setdefault(key, value)
            want.setdefault(key, value)

    def normalized(values):
        return {key: sorted(value) if isinstance(value, list) else value for key, value in values.items() if value not in (None, "", [], {})}

    return normalized(have) == normalized(want)
