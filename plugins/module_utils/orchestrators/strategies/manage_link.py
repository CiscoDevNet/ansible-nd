# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Strategy for single cluster (NDFC) link operations.

API surface lives under /api/v1/manage/links (same base URL as multi cluster).
Single vs. multi cluster is expressed via query params and identity field
count, not the URL path.
"""

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.link_actions import LinkActionsRemovePost
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.links import LinkPut, LinksGet, LinksPost
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_link import BaseLinkStrategy


class ManageLinkStrategy(BaseLinkStrategy):
    """Single cluster (NDFC) scope; 6 field identity, no cluster names."""

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
            "src_fabric_name",
            "dst_fabric_name",
            "src_switch_name",
            "dst_switch_name",
            "src_interface_name",
            "dst_interface_name",
        ]

    def configure_read(self, endpoint: Any, **kwargs: Any) -> None:
        """Populate GET /manage/links query params (fabricName required; others optional)."""
        params = endpoint.endpoint_params
        params.fabric_name = self.fabric_name
        if self.cluster_name:
            params.cluster_name = self.cluster_name
        if self.ticket_id:
            params.ticket_id = self.ticket_id
        if kwargs.get("switch_id"):
            params.switch_id = kwargs["switch_id"]

    def configure_mutation(self, endpoint: Any) -> None:
        """Populate clusterName / ticketId query params for create/update/delete."""
        params = endpoint.endpoint_params
        if self.cluster_name:
            params.cluster_name = self.cluster_name
        if self.ticket_id:
            params.ticket_id = self.ticket_id
