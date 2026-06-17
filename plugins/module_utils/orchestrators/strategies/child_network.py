# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import (
    NetworkChildConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import (
    network_base_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import (
    StandaloneNetworkStrategy,
)


class ChildNetworkStrategy(StandaloneNetworkStrategy):
    """
    Unified strategy for Multisite (MSD) and Multicluster (MFD) child fabrics.

    Inherits all endpoint classes from StandaloneNetworkStrategy — child fabrics
    use the same API surface.  The only difference for Multicluster is that
    cluster_name must be injected into each endpoint's query parameters.
    """

    def __init__(
        self,
        fabric_name: str,
        fabric_data: dict[str, Any] | None = None,
        cluster_name: str | None = None,
        **kwargs,
    ):
        super().__init__(fabric_name=fabric_name, fabric_data=fabric_data, **kwargs)
        # Prefer explicit cluster_name (coordinator fast-path), fall back to fabric_data.
        self._cluster_name: str | None = cluster_name or ((fabric_data or {}).get("clusterName"))

    # ── Fabric type identity ────────────────────────────────────────

    @property
    def fabric_type(self) -> str:
        return "multicluster_child" if self.is_multicluster else "multisite_child"

    @property
    def is_child(self) -> bool:
        return True

    @property
    def is_multicluster(self) -> bool:
        return bool(self._cluster_name)

    @property
    def is_multisite(self) -> bool:
        return not self.is_multicluster

    @property
    def cluster_name(self) -> str | None:
        """The cluster name, or None for Multisite child fabrics."""
        return self._cluster_name

    # ── Config model ───────────────────────────────────────────────

    @property
    def config_model_cls(self) -> type:
        return NetworkChildConfigModel

    # ── Argument spec ──────────────────────────────────────────────

    def get_argument_spec(self) -> dict[str, Any]:
        """Child fabrics do not expose child_fabric_config."""
        return network_base_argument_spec()

    # ── Cluster name guard ─────────────────────────────────────────

    def _require_cluster_name(self) -> str:
        """Return cluster_name or raise ValueError if absent."""
        if not self._cluster_name:
            raise ValueError(
                f"ChildNetworkStrategy for fabric '{self.fabric_name}' requires a "
                "cluster_name for Multicluster operations, but none was found. "
                "Ensure the member fabric data returned by ND includes 'clusterName'."
            )
        return self._cluster_name

    # ── Endpoint configuration hook ────────────────────────────────

    def configure_endpoint(self, ep) -> None:
        """
        Inject cluster_name into the endpoint's query parameters for
        Multicluster child fabrics.  No-op for Multisite child fabrics.
        """
        if self.is_multicluster:
            ep.endpoint_params.cluster_name = self._require_cluster_name()
