# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Standalone NX-OS dot1qTunnelPoHost interface orchestration."""

from __future__ import annotations

from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_dot1q_tunnel_host_interface import (
    PortChannelDot1qTunnelHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_base import PortChannelBaseOrchestrator


class PortChannelDot1qTunnelHostInterfaceOrchestrator(PortChannelBaseOrchestrator):
    """Manage dot1qTunnelPoHost through the established staged interface lifecycle."""

    model_class: ClassVar[type[NDBaseModel]] = PortChannelDot1qTunnelHostInterfaceModel
    interface_type: ClassVar[str] = "portChannel"
    interface_mode: ClassVar[str] = "dot1qTunnel"

    def _switches_to_query(self) -> dict[str, str]:
        """Gather this family's parents from every switch without requiring config."""
        if self.rest_send.params.get("state") == "gathered":
            return self.fabric_context.switch_map
        return super()._switches_to_query()

    def _managed_policy_types(self) -> set[str]:
        """Manage the parent policy, never an Ethernet or generated vPC member."""
        return {"dot1qTunnelPoHost"}
