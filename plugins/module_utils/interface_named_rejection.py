# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# SPDX-License-Identifier: GPL-3.0-or-later

"""Exact synchronous negative evidence, distinct from generic failed status."""


def named_sync_rejections(response, targets):
    """Return named negative receipts only for complete unambiguous HTTP 207.

    Failure classification alone is not negative evidence: omitted, malformed,
    duplicate and unknown results can also be classified as failed. A receipt
    requires every requested target to have one result with an explicit
    recognized terminal status. A bare name binds only when the mutation
    request contains exactly one switch. No transport is performed.
    Pair-qualified vPC responses retain ordinary recovery instead of inferring
    ownership from an extra serial in the result name.
    """
    if not isinstance(response, dict) or response.get("RETURN_CODE") != 207:
        return {}
    method = getattr(response.get("METHOD"), "value", response.get("METHOD"))
    if str(method).upper() != "POST":
        return {}
    requested = {}
    for serial, name in targets:
        if not isinstance(serial, str) or not serial or not isinstance(name, str) or not name:
            return {}
        key = serial.casefold(), name.casefold()
        if key in requested:
            return {}
        requested[key] = serial, name
    data = response.get("DATA")
    rows = data.get("results") if isinstance(data, dict) else None
    if not requested or not isinstance(rows, list) or len(rows) != len(requested):
        return {}
    seen, rejected = set(), {}
    switch_ids = {key[0] for key in requested}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str) or not isinstance(row.get("status"), str):
            return {}
        name = row["name"].strip()
        if "~" not in name and ":" not in name:
            if len(switch_ids) != 1:
                return {}
            key = next(iter(switch_ids)), name.casefold()
        else:
            if "~" in name and ":" in name:
                return {}
            parts = name.split("~" if "~" in name else ":")
            if len(parts) != 2 or any(not part or part != part.strip() for part in parts):
                return {}
            key = tuple(part.casefold() for part in parts)
        if key not in requested or key in seen:
            return {}
        serial, interface_name = requested[key]
        if "switchId" in row and (not isinstance(row["switchId"], str) or row["switchId"].casefold() != serial.casefold()):
            return {}
        if "interfaceName" in row and (not isinstance(row["interfaceName"], str) or row["interfaceName"].casefold() != interface_name.casefold()):
            return {}
        status = row["status"].strip().casefold()
        if status not in {"success", "failed", "failure", "error"}:
            return {}
        seen.add(key)
        if status != "success":
            rejected[(serial, interface_name)] = {
                "version": 1,
                "source": "native_named_sync_rejection_v1",
                "action": "create",
                "switch_id": serial,
                "interface_name": interface_name,
                "http_status": 207,
                "response_status": status,
            }
    return rejected if seen == set(requested) else {}
