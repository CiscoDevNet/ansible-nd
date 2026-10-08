# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Release-aware validation for user-supplied fabric DHCP and gateway addresses."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    DhcpProtocolVersionEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_bgp_validation import (
    parse_controller_version,
)

DHCP_GATEWAY_FIELDS = ("dhcp_start_address", "dhcp_end_address", "management_gateway")
DHCP_SCOPE_FIELDS = frozenset({"dhcp_start_address", "dhcp_end_address"})


class ManageFabricDhcpValidationMixin:
    """Gate IPv6 scalar input without rejecting IPv6 controller responses."""

    rest_send: Any

    def preflight(self, model_instances: Sequence[NDBaseModel]) -> None:
        """Require a compatible release and explicit DHCPv6 for IPv6 scopes.

        ND 4.3.1 relaxed the three scalar address schemas.  IPv6 local DHCP
        additionally requires a V6 controller installation.  No documented
        read-only capability flag exists, so the API remains authoritative
        for that installation-specific condition.
        """
        ipv6_fields_by_fabric: dict[str, list[str]] = {}
        local_dhcp_without_dhcpv6: list[str] = []

        for item in model_instances:
            management = getattr(item, "management", None)
            if management is None:
                continue
            name = str(item.get_identifier_value())
            for field in DHCP_GATEWAY_FIELDS:
                if field not in management.model_fields_set:
                    continue
                value = getattr(management, field, None)
                if value is None or ipaddress.ip_address(value).version != 6:
                    continue
                ipv6_fields_by_fabric.setdefault(name, []).append(field)
                uses_local_dhcp = field in DHCP_SCOPE_FIELDS or (field == "management_gateway" and management.local_dhcp_server)
                if uses_local_dhcp and management.dhcp_protocol_version != DhcpProtocolVersionEnum.DHCPV6:
                    local_dhcp_without_dhcpv6.append(f"{name} ({field})")

        if ipv6_fields_by_fabric:
            raw_version = self.rest_send.controller_version
            version = parse_controller_version(raw_version)
            if version is None or version < (4, 3, 1):
                reported = raw_version or "unknown"
                affected = ", ".join(f"{name} ({', '.join(fields)})" for name, fields in ipv6_fields_by_fabric.items())
                raise RuntimeError(
                    "IPv6 management DHCP/gateway addresses require ND 4.3.1 or later; "
                    "IPv6 local DHCP also requires a V6 controller installation. "
                    f"Controller version is {reported!r} for fabric(s): {affected}"
                )

        if local_dhcp_without_dhcpv6:
            raise RuntimeError(
                "IPv6 management addresses using local DHCP require "
                "management.dhcp_protocol_version=dhcpv6 in the same config entry for fabric(s): " + ", ".join(local_dhcp_without_dhcpv6)
            )

        super().preflight(model_instances)
