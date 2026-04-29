# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Strategy for single cluster (NDFC) link operations.

API surface lives under /api/v1/manage/links (same base URL as multi cluster).
Single vs. multi cluster is expressed via query params and identity field
count, not the URL path.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.link_actions import LinkActionsRemovePost
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.links import LinkPut, LinksGet, LinksPost
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_link import BaseLinkStrategy


class ManageLinkStrategy(BaseLinkStrategy):
    """Single cluster (NDFC) scope; 6 field identity, no cluster names."""

    @property
    def links_get_cls(self):
        return LinksGet

    @property
    def links_post_cls(self):
        return LinksPost

    @property
    def link_put_cls(self):
        return LinkPut

    @property
    def link_actions_remove_post_cls(self):
        return LinkActionsRemovePost

    @property
    def identifier_fields(self):
        return [
            "src_fabric_name",
            "dst_fabric_name",
            "src_switch_name",
            "dst_switch_name",
            "src_interface_name",
            "dst_interface_name",
        ]

    def build_query_all_params(self, **kwargs):
        """Build GET /manage/links query params (fabricName required; others optional)."""
        params = {"fabricName": self.fabric_name}
        if self.cluster_name:
            params["clusterName"] = self.cluster_name
        if self.ticket_id:
            params["ticketId"] = self.ticket_id
        if kwargs.get("switch_id"):
            params["switchId"] = kwargs["switch_id"]
        return params

    def build_query_one_params(self, model_instance, **kwargs):
        """No dedicated single get endpoint; reuse GET all params and filter client side."""
        return self.build_query_all_params(**kwargs)
