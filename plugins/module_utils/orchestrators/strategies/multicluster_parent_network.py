# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_network import (
    MultisiteParentNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics_networks import (
    EpOneManageFabricsNetworkActionsDeployPost,
    EpOneManageFabricsNetworkActionsRemovePost,
    EpOneManageFabricsNetworksGet,
    EpOneManageFabricsNetworksNetworkNameDelete,
    EpOneManageFabricsNetworksNetworkNamePut,
    EpOneManageFabricsNetworksPost,
)


class MulticlusterParentNetworkStrategy(MultisiteParentNetworkStrategy):
    """
    Strategy for Multicluster Parent (MFD) fabrics.

    Reuses the Multisite parent workflow contract, including child task
    construction and parent/child result aggregation, while routing parent
    Network operations through the OneManage manage endpoint surface.
    """

    @property
    def fabric_type(self) -> str:
        return "multicluster_parent"

    @property
    def is_multicluster(self) -> bool:
        return True

    @property
    def is_multisite(self) -> bool:
        return False

    def networks_get_cls(self) -> type:
        return EpOneManageFabricsNetworksGet

    def networks_post_cls(self) -> type:
        return EpOneManageFabricsNetworksPost

    def network_put_cls(self) -> type:
        return EpOneManageFabricsNetworksNetworkNamePut

    def network_delete_cls(self) -> type:
        return EpOneManageFabricsNetworksNetworkNameDelete

    def network_actions_deploy_post_cls(self) -> type:
        return EpOneManageFabricsNetworkActionsDeployPost

    def network_actions_remove_post_cls(self) -> type:
        return EpOneManageFabricsNetworkActionsRemovePost

    def configure_endpoint(self, ep) -> None:
        super().configure_endpoint(ep)
        if hasattr(ep, "proxy_path"):
            # ``onemanageProxyPath`` is used only for MCFG fabric association
            # discovery. Resource endpoints under /oneManage/manage are reached
            # directly through the OneManage server root.
            ep.proxy_path = ""
