# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Network dependency checks."""

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_network import (
    BaseNetworkStrategy,
)


class NetworkDependencyChecker:
    """
    Placeholder for network-specific destructive-operation dependencies.

    VRFs must be checked for attached networks before deletion. Networks do not
    have an equivalent child-resource relationship in the Manage schema; switch
    attachments are handled explicitly by NetworkAttachmentManager before delete.
    """

    def __init__(self, coordinator: Any):
        self.coordinator = coordinator

    def ensure_no_networks(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str],
    ) -> None:
        """No-op dependency guard retained for state-machine symmetry."""

    def current_networks_for_networks(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str],
    ) -> list[dict[str, Any]]:
        """Return no dependent resources."""
        return []

    def query_networks_for_networks(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str],
        use_filter: bool,
    ) -> list[dict[str, Any]]:
        """Return no dependent resources."""
        return []
