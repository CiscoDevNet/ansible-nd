# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switches import (
    EpManageSwitchesListGet,
)


class VrfLiteEndpoints:
    """Resolve the mixed Manage and NDFC paths used by VRF Lite workflows.

    VRF inventory, deployment, and config actions use the current Manage API.
    VRF Lite attachment details and writes still require the NDFC top-down
    contract because the equivalent Manage plural paths are not exposed.
    """

    _LAN_FABRIC_API = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest"
    _TOP_DOWN_API = "{0}/top-down".format(_LAN_FABRIC_API)

    @staticmethod
    def _fabric_path(fabric_name: str, *segments: str) -> str:
        return BasePath.path("fabrics", quote(fabric_name, safe=""), *segments)

    @staticmethod
    def _top_down_fabric_path(fabric_name: str, *segments: str) -> str:
        suffix = "/".join(("fabrics", quote(fabric_name, safe=""), *segments))
        return "{0}/{1}".format(VrfLiteEndpoints._TOP_DOWN_API, suffix)

    @staticmethod
    def vrfs(fabric_name: str) -> str:
        return VrfLiteEndpoints._fabric_path(fabric_name, "vrfs")

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
        return VrfLiteEndpoints._fabric_path(fabric_name, "vrfActions", "deploy")

    @staticmethod
    def vrf_switch(fabric_name: str, vrf_name: str, serial_number: str) -> str:
        return "{0}?vrf-names={1}&serial-numbers={2}".format(
            VrfLiteEndpoints._top_down_fabric_path(fabric_name, "vrfs", "switches"),
            quote(vrf_name, safe=""),
            quote(serial_number, safe=","),
        )

    @staticmethod
    def reserve_id(fabric_name: str) -> str:
        # The legacy resource-manager endpoint is global rather than fabric-scoped.
        del fabric_name
        return "{0}/resource-manager/reserve-id".format(VrfLiteEndpoints._LAN_FABRIC_API)

    @staticmethod
    def fabric_switches(fabric_name: str) -> str:
        return EpManageSwitchesListGet(fabric_name=fabric_name).path

    @staticmethod
    def config_save(fabric_name: str) -> str:
        return VrfLiteEndpoints._fabric_path(fabric_name, "actions", "configSave")

    @staticmethod
    def config_deploy(fabric_name: str) -> str:
        return "{0}?forceShowRun=true".format(VrfLiteEndpoints._fabric_path(fabric_name, "actions", "deploy"))
