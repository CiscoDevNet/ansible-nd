# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_config_save import (
    EpFabricConfigSavePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_deploy import (
    EpFabricDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import (
    EpFabricSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
    EpFabricVrfsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs_attachments import (
    EpFabricVrfsAttachmentsGet,
    EpFabricVrfsAttachmentsPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs_deployments import (
    EpFabricVrfsDeploymentsPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs_switches import (
    EpFabricVrfsSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_resource_manager_reserve_id import (
    EpResourceManagerReserveIdPost,
)


class VrfLiteEndpoints:
    """Runtime endpoint resolver backed by endpoint model classes."""

    @staticmethod
    def vrfs(fabric_name: str) -> str:
        return EpFabricVrfsGet(fabric_name=fabric_name).path

    @staticmethod
    def vrf_attachments_query(fabric_name: str, vrf_names_csv: str) -> str:
        return EpFabricVrfsAttachmentsGet(fabric_name=fabric_name, vrf_names=vrf_names_csv).path

    @staticmethod
    def vrf_attachments_post(fabric_name: str) -> str:
        return EpFabricVrfsAttachmentsPost(fabric_name=fabric_name).path

    @staticmethod
    def vrf_deployments(fabric_name: str) -> str:
        return EpFabricVrfsDeploymentsPost(fabric_name=fabric_name).path

    @staticmethod
    def vrf_switch(fabric_name: str, vrf_name: str, serial_number: str) -> str:
        return EpFabricVrfsSwitchesGet(
            fabric_name=fabric_name,
            vrf_names=vrf_name,
            serial_numbers=serial_number,
        ).path

    @staticmethod
    def reserve_id() -> str:
        return EpResourceManagerReserveIdPost().path

    @staticmethod
    def fabric_switches(fabric_name: str) -> str:
        return EpFabricSwitchesGet(fabric_name=fabric_name).path

    @staticmethod
    def config_save(fabric_name: str) -> str:
        return EpFabricConfigSavePost(fabric_name=fabric_name).path

    @staticmethod
    def config_deploy(fabric_name: str) -> str:
        return EpFabricDeployPost(fabric_name=fabric_name, force_show_run=True).path
