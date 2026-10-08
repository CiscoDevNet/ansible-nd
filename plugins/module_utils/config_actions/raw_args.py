# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Helpers for reading raw Ansible module arguments before defaults are injected.
"""

from __future__ import annotations

import json
from typing import Any


def get_raw_module_args() -> dict[str, Any]:
    """
    # Summary

    Return raw user-provided module arguments from Ansible's serialized argument payload.

    ## Raises

    None
    """
    try:
        from ansible.module_utils import basic as ansible_basic

        raw_payload = getattr(ansible_basic, "_ANSIBLE_ARGS", None)
        if raw_payload is None:
            return {}
        if isinstance(raw_payload, (bytes, bytearray)):
            decoded = raw_payload.decode("utf-8")
        elif isinstance(raw_payload, str):
            decoded = raw_payload
        else:
            return {}

        parsed = json.loads(decoded)
        module_args = parsed.get("ANSIBLE_MODULE_ARGS")
        return module_args if isinstance(module_args, dict) else {}
    except Exception:
        return {}
