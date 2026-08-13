# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import (
    VrfChildConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_argument_specs import (
    vrf_base_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import (
    StandaloneVrfStrategy,
)


class ChildVrfStrategy(StandaloneVrfStrategy):
    """
    Unified strategy for Multisite (MSD) and Multicluster (MFD) child fabrics.

    Inherits all endpoint classes from StandaloneVrfStrategy — child fabrics
    use the same fabric-scoped API surface.  Multicluster child identity is
    retained as metadata, but fabric operations are routed by fabric name.
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
        return VrfChildConfigModel

    # ── Argument spec ──────────────────────────────────────────────

    def get_argument_spec(self) -> dict[str, Any]:
        """Child fabrics do not expose child_fabric_config."""
        return vrf_base_argument_spec()

    # ── Endpoint configuration hook ────────────────────────────────

    def configure_endpoint(self, ep) -> None:
        """
        Inject clusterName for Multicluster child fabrics.

        Remote MCFG child fabric-scoped APIs require the association cluster
        name in the URI when authenticated against the MCFG login domain.
        """
        if self.is_multicluster and hasattr(ep, "endpoint_params") and hasattr(ep.endpoint_params, "cluster_name"):
            ep.endpoint_params.cluster_name = self.cluster_name
