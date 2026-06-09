# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

import logging
from copy import deepcopy
from typing import Any, Dict, List, Union


def sanitize_dict(dict_to_sanitize, keys=None, values=None, recursive=True, remove_none_values=True):
    if keys is None:
        keys = []
    if values is None:
        values = []

    result = deepcopy(dict_to_sanitize)
    for k, v in dict_to_sanitize.items():
        if k in keys:
            del result[k]
        elif v in values or (v is None and remove_none_values):
            del result[k]
        elif isinstance(v, dict) and recursive:
            result[k] = sanitize_dict(v, keys, values)
        elif isinstance(v, list) and recursive:
            for index, item in enumerate(v):
                if isinstance(item, dict):
                    result[k][index] = sanitize_dict(item, keys, values)
    return result


def issubset(subset: Any, superset: Any) -> bool:
    """Check if subset is contained in superset."""
    if type(subset) is not type(superset):
        return False

    if not isinstance(subset, dict):
        if isinstance(subset, list):
            if len(subset) != len(superset):
                return False

            remaining = list(superset)
            for item in subset:
                for index, candidate in enumerate(remaining):
                    if issubset(item, candidate) and issubset(candidate, item):
                        del remaining[index]
                        break
                else:
                    return False
            return True
        return subset == superset

    for key, value in subset.items():
        if value is None:
            continue

        if key not in superset:
            return False

        if not issubset(value, superset[key]):
            return False

    return True


def remove_unwanted_keys(data: Dict, unwanted_keys: List[Union[str, List[str]]]) -> Dict:
    """Remove unwanted keys from dict (supports nested paths)."""
    data = deepcopy(data)

    for key in unwanted_keys:
        if isinstance(key, str):
            if key in data:
                del data[key]

        elif isinstance(key, list) and len(key) > 0:
            try:
                parent = data
                for k in key[:-1]:
                    if isinstance(parent, dict) and k in parent:
                        parent = parent[k]
                    else:
                        break
                else:
                    if isinstance(parent, dict) and key[-1] in parent:
                        del parent[key[-1]]
            except (KeyError, TypeError, IndexError):
                pass

    return data


# =========================================================================
# Exceptions
# =========================================================================


class SwitchOperationError(Exception):
    """Raised when a switch operation fails."""


# =========================================================================
# API Response Validation
# =========================================================================


class ApiDataChecker:
    """Detect controller-embedded errors in API response DATA payloads.

    The Nexus Dashboard API signals certain errors by embedding an error
    object inside ``DATA`` as ``{"code": <N>, "message": "<reason>"}`` even
    when the transport-level result is marked successful.  Any payload dict
    that contains a ``"code"`` key is treated as an error; the absence of
    ``"code"`` means the payload is a genuine data body.
    """

    @staticmethod
    def check(
        data: Any,
        context: str,
        log: logging.Logger,
        fail_callback=None,
    ) -> None:
        """Fail or raise if the response DATA contains an embedded error code.

        Args:
            data: Value returned by ``nd.request()`` or extracted from
                  ``response_current["DATA"]``.
            context: Human-readable description of the operation.
            log: Logger instance.
            fail_callback: Optional callable (e.g. ``module.fail_json``) that
                           accepts a ``msg`` keyword argument.  When provided
                           it is called on error instead of raising
                           ``SwitchOperationError``.
        """
        log.debug(f"ApiDataChecker.check: Checking response for context: {context}")
        log.debug(f"ApiDataChecker.check: data type={type(data)}, has 'error'={'error' in data if isinstance(data, dict) else 'N/A'}")

        # Check for error object in response (some APIs return this structure)
        if isinstance(data, dict) and "error" in data:
            error_obj = data.get("error", {})
            log.debug(f"ApiDataChecker.check: Found error object: {error_obj}")
            if isinstance(error_obj, dict) and "code" in error_obj:
                # Extract message from nested structure
                error_msg = error_obj.get("message", "Unknown error")
                if isinstance(error_msg, dict):
                    error_msg = error_msg.get("message") or error_msg.get("status") or str(error_msg)
                msg = f"{context} failed \u2014 controller returned error: " f"{error_msg} (code={error_obj['code']})"
                log.error(msg)
                if fail_callback is not None:
                    log.debug(f"ApiDataChecker.check: Calling fail_callback with msg: {msg}")
                    fail_callback(msg=msg)
                    return  # Should not reach here
                else:
                    raise SwitchOperationError(msg)

        # Check for code in data payload (embedded error pattern)
        if isinstance(data, dict) and "code" in data:
            error_msg = data.get("message", "Unknown error")
            msg = f"{context} failed \u2014 controller returned error: " f"{error_msg} (code={data['code']})"
            log.error(msg)
            if fail_callback is not None:
                log.debug(f"ApiDataChecker.check: Calling fail_callback with msg: {msg}")
                fail_callback(msg=msg)
                return  # Should not reach here
            else:
                raise SwitchOperationError(msg)

        log.debug("ApiDataChecker.check: No errors detected in response")
