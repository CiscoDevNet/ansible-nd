# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Strategy for multi cluster ("One Manage") link operations.

Same URL surface as the single cluster strategy; differs only in the identity
field set (includes cluster names) and the query param shape (srcClusterName /
dstClusterName instead of clusterName).
"""

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.one_manage.link_actions import LinkActionsRemovePost
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.one_manage.links import LinkPut, LinksGet, LinksPost
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_link import BaseLinkStrategy


class OneManageLinkStrategy(BaseLinkStrategy):
    """Multi cluster scope; 8 field identity including cluster names."""

    @property
    def links_get_cls(self) -> type[NDEndpointBaseModel]:
        return LinksGet

    @property
    def links_post_cls(self) -> type[NDEndpointBaseModel]:
        return LinksPost

    @property
    def link_put_cls(self) -> type[NDEndpointBaseModel]:
        return LinkPut

    @property
    def link_actions_remove_post_cls(self) -> type[NDEndpointBaseModel]:
        return LinkActionsRemovePost

    @property
    def identifier_fields(self) -> list[str]:
        return [
            "src_cluster_name",
            "dst_cluster_name",
            "src_fabric_name",
            "dst_fabric_name",
            "src_switch_name",
            "dst_switch_name",
            "src_interface_name",
            "dst_interface_name",
        ]

    def configure_read(self, endpoint: Any, **kwargs: Any) -> None:
        """Populate GET /manage/links query params (fabricName required; cluster filters optional)."""
        params = endpoint.endpoint_params
        params.fabric_name = self.fabric_name
        if kwargs.get("src_cluster_name"):
            params.src_cluster_name = kwargs["src_cluster_name"]
        if kwargs.get("dst_cluster_name"):
            params.dst_cluster_name = kwargs["dst_cluster_name"]

    def configure_mutation(self, endpoint: Any) -> None:
        """Populate ticketId query param for create/update/delete (cluster identity is in the payload)."""
        if self.ticket_id:
            endpoint.endpoint_params.ticket_id = self.ticket_id
