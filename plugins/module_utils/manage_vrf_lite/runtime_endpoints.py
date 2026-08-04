# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_config_save import (
    EpFabricConfigSavePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrf_actions import (
    EpManageFabricsVrfActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
    EpManageFabricsVrfsGet,
)


class VrfLiteEndpoints:
    """Resolve the mixed Manage and legacy top-down paths used by VRF Lite workflows.

    VRF inventory, deployment, and config actions delegate to the canonical
    Manage-API endpoint models. VRF Lite attachment details and writes still
    require the controller's legacy top-down contract because equivalent Manage plural
    paths are not exposed, so those paths are built here.
    """

    _LAN_FABRIC_API = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest"
    _TOP_DOWN_API = "{0}/top-down".format(_LAN_FABRIC_API)

    @staticmethod
    def _top_down_fabric_path(fabric_name: str, *segments: str) -> str:
        suffix = "/".join(("fabrics", quote(fabric_name, safe=""), *segments))
        return "{0}/{1}".format(VrfLiteEndpoints._TOP_DOWN_API, suffix)

    @staticmethod
    def vrfs(fabric_name: str) -> str:
        return EpManageFabricsVrfsGet(fabric_name=fabric_name).path

    @staticmethod
    def vrf_attachments_query(fabric_name: str, vrf_names_csv: str) -> str:
        return "{0}?vrf-names={1}".format(
            VrfLiteEndpoints._top_down_fabric_path(fabric_name, "vrfs", "attachments"),
            quote(vrf_names_csv, safe=","),
        )

    @staticmethod
    def vrf_attachments_post(fabric_name: str) -> str:
        return VrfLiteEndpoints._top_down_fabric_path(fabric_name, "vrfs", "attachments")

    @staticmethod
    def vrf_deployments(fabric_name: str) -> str:
        return EpManageFabricsVrfActionsDeployPost(fabric_name=fabric_name).path

    @staticmethod
    def vrf_switch(fabric_name: str, vrf_names_csv: str, serial_numbers_csv: str) -> str:
        # Both query params are plural: ``vrf-names`` and ``serial-numbers`` each
        # accept a comma-separated list, so a single request can enrich several
        # switches across several VRFs at once. Commas are kept ``safe`` for both
        # so the list separators survive URL-encoding.
        return "{0}?vrf-names={1}&serial-numbers={2}".format(
            VrfLiteEndpoints._top_down_fabric_path(fabric_name, "vrfs", "switches"),
            quote(vrf_names_csv, safe=","),
            quote(serial_numbers_csv, safe=","),
        )

    @staticmethod
    def reserve_id(fabric_name: str) -> str:
        # The legacy resource-manager endpoint is global rather than fabric-scoped.
        del fabric_name
        return "{0}/resource-manager/reserve-id".format(VrfLiteEndpoints._LAN_FABRIC_API)

    @staticmethod
    def config_save(fabric_name: str) -> str:
        return EpFabricConfigSavePost(fabric_name=fabric_name).path
