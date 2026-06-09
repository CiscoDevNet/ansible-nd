# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switches import (
    EpManageSwitchesListGet,
)


class VrfLiteEndpoints:
    """Runtime endpoint resolver for VRF Lite-specific Manage API paths."""

    @staticmethod
    def _fabric_path(fabric_name: str, *segments: str) -> str:
        return BasePath.path("fabrics", quote(fabric_name, safe=""), *segments)

    @staticmethod
    def vrfs(fabric_name: str) -> str:
        return VrfLiteEndpoints._fabric_path(fabric_name, "vrfs")

    @staticmethod
    def vrf_attachments_query(fabric_name: str) -> str:
        return VrfLiteEndpoints._fabric_path(fabric_name, "vrfAttachments", "query")

    @staticmethod
    def vrf_attachments_post(fabric_name: str) -> str:
        return VrfLiteEndpoints._fabric_path(fabric_name, "vrfAttachments")

    @staticmethod
    def vrf_deployments(fabric_name: str) -> str:
        return VrfLiteEndpoints._fabric_path(fabric_name, "vrfs", "deployments")

    @staticmethod
    def vrf_switch(fabric_name: str, vrf_name: str, serial_number: str) -> str:
        return "{0}?vrf-names={1}&serial-numbers={2}".format(
            VrfLiteEndpoints._fabric_path(fabric_name, "vrfs", "switches"),
            quote(vrf_name, safe=""),
            quote(serial_number, safe=""),
        )

    @staticmethod
    def reserve_id(fabric_name: str) -> str:
        return VrfLiteEndpoints._fabric_path(fabric_name, "resource-manager", "reserve-id")

    @staticmethod
    def fabric_switches(fabric_name: str) -> str:
        return EpManageSwitchesListGet(fabric_name=fabric_name).path

    @staticmethod
    def config_save(fabric_name: str) -> str:
        return VrfLiteEndpoints._fabric_path(fabric_name, "actions", "configSave")

    @staticmethod
    def config_deploy(fabric_name: str) -> str:
        return "{0}?forceShowRun=true".format(VrfLiteEndpoints._fabric_path(fabric_name, "actions", "deploy"))
