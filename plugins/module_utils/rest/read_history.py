# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Opt-in retention of consumed successful native GET observations.

Only historical bodies are compacted. Full current response, request/result
metadata, failures and standalone diagnostics keep their existing behavior.
"""

from __future__ import annotations

from urllib.parse import urlsplit


def _same_json_value(left: object, right: object) -> bool:
    """Compare known JSON aliases without bool/int or int/float coercion."""
    # Exact controller/receipt types are part of the validation contract.
    # pylint: disable=unidiomatic-typecheck
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return (
            left.keys() == right.keys() and all(type(key) is str for key in left) and all(_same_json_value(value, right[key]) for key, value in left.items())
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(_same_json_value(a, b) for a, b in zip(left, right))
    return type(left) in {str, bool, int, float, type(None)} and left == right


def _resource_path(value: object) -> str | None:
    """Preserve exact resource/query while accepting HttpApi absolute URLs."""
    if not isinstance(value, str) or "#" in value or any(ord(char) <= 32 or ord(char) == 127 for char in value):
        return None
    try:
        parsed = urlsplit(value)
        if parsed.fragment or parsed.username is not None or parsed.password is not None:
            return None
        if parsed.scheme:
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                return None
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                return None
        elif parsed.netloc or not value.startswith("/"):
            return None
    except ValueError:
        return None
    return parsed.path + ("?" + parsed.query if "?" in value else "")


def compact_consumed_get_response(response: dict, *, path: str) -> dict:
    """Drop only consumed GET200 DATA and its exact known body alias.

    Matching the relative resource of an absolute HttpApi response affects
    retention only, not controller authorization or redirect acceptance. The
    authenticated transport remains responsible for its destination. Unknown
    wrappers retain all bodies, even when the caller classified them success.
    """
    # Exact controller/receipt types are part of the validation contract.
    # pylint: disable=unidiomatic-typecheck
    actual, requested = _resource_path(response.get("REQUEST_PATH")), _resource_path(path)
    if (
        str(response.get("METHOD") or "").upper() not in {"GET", "HTTPVERBENUM.GET"}
        or type(response.get("RETURN_CODE")) is not int
        or response["RETURN_CODE"] != 200
        or actual is None
        or requested is None
        or actual != requested
        or "DATA" not in response
        or "error" in response
        or "body" in response
        and not _same_json_value(response["body"], response["DATA"])
    ):
        return response
    return {key: value for key, value in response.items() if key not in {"DATA", "body"}}
