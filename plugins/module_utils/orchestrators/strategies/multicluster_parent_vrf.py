# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_vrf import (
    MultisiteParentVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.vrfs import (
    EpOneManageFabricsVrfActionsDeployPost,
    EpOneManageFabricsVrfsGet,
    EpOneManageFabricsVrfsBulkDelete,
    EpOneManageFabricsVrfsPost,
    EpOneManageFabricsVrfsVrfNameDelete,
    EpOneManageFabricsVrfsVrfNamePut,
)


class MulticlusterParentVrfStrategy(MultisiteParentVrfStrategy):
    """
    Strategy for Multicluster Parent (MFD) fabrics.

    Identical to MultisiteParentVrfStrategy except fabric_type and
    is_multicluster / is_multisite identity flags.
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

    def vrfs_get_cls(self) -> type:
        return EpOneManageFabricsVrfsGet

    def vrfs_post_cls(self) -> type:
        return EpOneManageFabricsVrfsPost

    def vrf_put_cls(self) -> type:
        return EpOneManageFabricsVrfsVrfNamePut

    def vrf_delete_cls(self) -> type:
        return EpOneManageFabricsVrfsVrfNameDelete

    def vrf_actions_deploy_post_cls(self) -> type:
        return EpOneManageFabricsVrfActionsDeployPost

    def vrf_actions_remove_post_cls(self) -> type:
        return EpOneManageFabricsVrfsBulkDelete

    def configure_endpoint(self, ep) -> None:
        super().configure_endpoint(ep)
        if hasattr(ep, "proxy_path"):
            ep.proxy_path = self.fabric_data.get("onemanageProxyPath", "")
