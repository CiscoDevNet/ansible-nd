# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Conservative ND 4.3.1 mixed-policy create eligibility.

The ``interfaceActions/modify`` endpoint can upsert malformed absent names
that the ordinary create endpoint rejects. Only known, model-derived NX-OS
logical identities may use it. Unqualified inputs retain the established
family create path and its server-side validation.
"""

from __future__ import annotations

import re
from typing import Any


def _number(name: str, pattern: str, minimum: int, maximum: int) -> int | None:
    match = re.fullmatch(pattern, name, flags=re.IGNORECASE)
    if match is None:
        return None
    value = int(match.group(1))
    return value if minimum <= value <= maximum and match.group(1) == str(value) else None


def bulk_create_parent(payload: dict[str, Any]) -> str | None:
    """Return the required routed parent for a qualified subinterface."""
    name = payload.get("interfaceName")
    if not isinstance(name, str):
        return None
    if "." not in name:
        return None
    parent, _suffix = name.rsplit(".", 1)
    return parent


def bulk_create_identity_qualified(payload: dict[str, Any]) -> bool:
    """Admit only conservative, wire-canonical logical identity/policy pairs."""
    name = payload.get("interfaceName")
    interface_type = payload.get("interfaceType")
    config = payload.get("configData")
    if not isinstance(name, str) or not isinstance(config, dict):
        return False
    os_data = config.get("networkOS")
    if not isinstance(os_data, dict) or os_data.get("networkOSType") != "nx-os":
        return False
    policy = os_data.get("policy")
    if not isinstance(policy, dict):
        return False
    policy_type = policy.get("policyType")
    if interface_type == "portChannel" and policy_type in {"accessPoHost", "l3Po", "trunkPoHost"}:
        ports = policy.get("ports", [])
        return _number(name, r"port-channel(\d+)", 1, 4096) is not None and isinstance(ports, list) and not ports
    if interface_type == "vpc" and policy_type in {"accessVpcHost", "trunkVpcHost"}:
        number = _number(name, r"vpc(\d+)", 1, 4096)
        return (
            number is not None
            and policy.get("peer1PortChannelId") == number
            and policy.get("peer2PortChannelId") == number
            and isinstance(policy.get("peerSwitchId"), str)
            and bool(policy["peerSwitchId"])
            and all(isinstance(policy.get(field, []), list) and not policy.get(field, []) for field in ("peer1MemberPorts", "peer2MemberPorts"))
        )
    if interface_type == "loopback" and policy_type == "loopback":
        return _number(name, r"loopback(\d+)", 0, 1023) is not None and bool(policy.get("ip"))
    if interface_type == "svi" and policy_type == "svi":
        return _number(name, r"vlan(\d+)", 1, 4094) is not None
    if interface_type == "subInterface" and policy_type in {"subinterface", "monitorSubinterface"}:
        parent = bulk_create_parent(payload)
        if parent is None:
            return False
        valid_parent = _number(parent, r"port-channel(\d+)", 1, 4096) is not None or bool(re.fullmatch(r"Ethernet\d+(?:/\d+)+", parent, flags=re.IGNORECASE))
        suffix = name.rsplit(".", 1)[1]
        sub_id = _number(suffix, r"(\d+)", 1, 4094)
        if not valid_parent or sub_id is None:
            return False
        if policy_type == "subinterface":
            return policy.get("vlanId") == sub_id and bool(policy.get("ip")) and isinstance(policy.get("prefix"), int)
        return True
    return False
