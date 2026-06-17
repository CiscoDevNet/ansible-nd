# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import (
    NetworkConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import (
    network_base_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_network import (
    BaseNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_networks import (
    EpManageFabricsNetworksGet,
    EpManageFabricsNetworksPost,
    EpManageFabricsNetworksNetworkNamePut,
    EpManageFabricsNetworksNetworkNameDelete,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_network_actions import (
    EpManageFabricsNetworkActionsDeployPost,
    EpManageFabricsNetworkActionsRemovePost,
)


class StandaloneNetworkStrategy(BaseNetworkStrategy):
    """
    Strategy for standalone (non-Multisite / non-Multicluster) fabrics.

    Uses the standard /api/v1/manage/fabrics/{fabricName}/networks endpoints.
    No child fabric orchestration.
    """

    @property
    def fabric_type(self) -> str:
        return "standalone"

    @property
    def config_model_cls(self) -> type:
        return NetworkConfigModel

    def get_argument_spec(self) -> dict[str, Any]:
        """Standalone fabrics use the base Network argument spec (no child_fabric_config)."""
        return network_base_argument_spec()

    # ── Endpoint classes ──────────────────────────────────────────

    def networks_get_cls(self) -> type:
        return EpManageFabricsNetworksGet

    def networks_post_cls(self) -> type:
        return EpManageFabricsNetworksPost

    def network_put_cls(self) -> type:
        return EpManageFabricsNetworksNetworkNamePut

    def network_delete_cls(self) -> type:
        return EpManageFabricsNetworksNetworkNameDelete

    def network_actions_deploy_post_cls(self) -> type:
        return EpManageFabricsNetworkActionsDeployPost

    def network_actions_remove_post_cls(self) -> type:
        return EpManageFabricsNetworkActionsRemovePost

    # ── Query params ──────────────────────────────────────────────

    def build_query_all_params(self, **kwargs) -> dict[str, Any] | None:
        return {"fabricName": self.fabric_name}
