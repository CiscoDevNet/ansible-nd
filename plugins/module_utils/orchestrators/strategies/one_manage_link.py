# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Strategy for multi cluster ("One Manage") link operations.

Same URL surface as the single cluster strategy; differs only in the identity
field set (includes cluster names) and the query param shape (srcClusterName /
dstClusterName instead of clusterName).
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.one_manage.link_actions import LinkActionsRemovePost
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.one_manage.links import LinkPut, LinksGet, LinksPost
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_link import BaseLinkStrategy


class OneManageLinkStrategy(BaseLinkStrategy):
    """Multi cluster scope; 8 field identity including cluster names."""

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
            "src_cluster_name",
            "dst_cluster_name",
            "src_fabric_name",
            "dst_fabric_name",
            "src_switch_name",
            "dst_switch_name",
            "src_interface_name",
            "dst_interface_name",
        ]

    def build_query_all_params(self, **kwargs):
        """Build GET /manage/links query params (fabricName required; cluster filters optional)."""
        params = {"fabricName": self.fabric_name}
        if kwargs.get("src_cluster_name"):
            params["srcClusterName"] = kwargs["src_cluster_name"]
        if kwargs.get("dst_cluster_name"):
            params["dstClusterName"] = kwargs["dst_cluster_name"]
        return params

    def build_query_one_params(self, model_instance, **kwargs):
        """Prefilter by cluster names on the instance for a narrower GET."""
        params = {"fabricName": self.fabric_name}
        if getattr(model_instance, "src_cluster_name", None):
            params["srcClusterName"] = model_instance.src_cluster_name
        if getattr(model_instance, "dst_cluster_name", None):
            params["dstClusterName"] = model_instance.dst_cluster_name
        return params
