# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
VRF dependency checks that must pass before destructive VRF operations.
"""

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_networks import (
    EpManageFabricsNetworksGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics_networks import (
    EpOneManageFabricsNetworksGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_vrf import (
    BaseVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_config_utils import (
    vrf_name_filter,
)


class VrfDependencyChecker:
    """
    Checks ND resources that can block VRF deletion.

    The coordinator owns REST construction and module failure handling; this
    class owns only dependency-specific queries and interpretation.
    """

    def __init__(self, coordinator: Any):
        self.coordinator = coordinator

    @staticmethod
    def _networks_get_endpoint_cls(strategy: BaseVrfStrategy) -> type:
        if strategy.is_multicluster and strategy.is_parent:
            return EpOneManageFabricsNetworksGet
        return EpManageFabricsNetworksGet

    def ensure_no_networks(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str],
    ) -> None:
        """Fail before VRF deletion when networks still reference the VRFs."""
        if not vrf_names:
            return

        networks = self.coordinator._current_networks_for_vrfs(module_args, strategy, vrf_names)
        if not networks:
            return

        networks_by_vrf: dict[str, list[str]] = {}
        for network in networks:
            vrf_name = network.get("vrfName") or network.get("vrf_name")
            network_name = network.get("networkName") or network.get("network_name") or network.get("displayName") or "<unknown>"
            if vrf_name:
                networks_by_vrf.setdefault(vrf_name, []).append(network_name)

        if networks_by_vrf:
            self.coordinator.module.fail_json(
                msg=(
                    "Cannot delete VRF(s) because network(s) still reference them "
                    f"on fabric '{strategy.fabric_name}': {networks_by_vrf}. "
                    "Remove the associated networks before deleting the VRF."
                )
            )

    def current_networks_for_vrfs(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str],
    ) -> list[dict[str, Any]]:
        """Gather networks referencing the requested VRFs."""
        vrf_name_set = set(vrf_names)
        try:
            networks = self.coordinator._query_networks_for_vrfs(module_args, strategy, vrf_names, use_filter=True)
        except Exception:
            networks = self.coordinator._query_networks_for_vrfs(module_args, strategy, vrf_names, use_filter=False)
        return [network for network in networks if (network.get("vrfName") or network.get("vrf_name")) in vrf_name_set]

    def query_networks_for_vrfs(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str],
        use_filter: bool,
    ) -> list[dict[str, Any]]:
        """Query the networks endpoint, optionally scoped by VRF filter."""
        orchestrator, _results = self.coordinator._new_vrf_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(self._networks_get_endpoint_cls(strategy))
        if hasattr(endpoint, "endpoint_params"):
            endpoint.endpoint_params.max = 10000
            if use_filter:
                endpoint.endpoint_params.filter = vrf_name_filter(vrf_names)

        data = orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            not_found_ok=True,
            operation_type=OperationType.QUERY,
        )
        if isinstance(data, dict):
            return data.get("networks") or data.get("items") or []
        if isinstance(data, list):
            return data
        return []
