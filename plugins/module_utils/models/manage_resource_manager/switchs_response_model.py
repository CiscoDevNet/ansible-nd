# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
GetAllSwitchesResponse - Response model for list-all-switches endpoint.

COMPOSITE model: contains List[SwitchRecord].

Endpoint: GET /fabrics/{fabricName}/switches?max=<n>
"""

from __future__ import annotations

from typing import Any, ClassVar, List, Optional

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field


class SwitchAdditionalDataMeta(NDNestedModel):
    """Nested ``meta`` object inside ``additionalData``."""

    identifiers: ClassVar[List[str]] = []

    switch_db_id: Optional[int] = Field(
        default=None,
        alias="switchDbId",
        description="Internal database ID of the switch",
    )
    switch_uuid: Optional[str] = Field(
        default=None,
        alias="switchUuid",
        description="Internal UUID of the switch",
    )


class SwitchAdditionalData(NDNestedModel):
    """``additionalData`` object embedded in each switch record."""

    identifiers: ClassVar[List[str]] = []

    config_sync_status: Optional[str] = Field(
        default=None,
        alias="configSyncStatus",
        description="Configuration synchronisation status",
    )
    discovered_system_mode: Optional[str] = Field(
        default=None,
        alias="discoveredSystemMode",
        description="Discovered system mode",
    )
    discovery_status: Optional[str] = Field(
        default=None,
        alias="discoveryStatus",
        description="Current discovery status",
    )
    domain_name: Optional[str] = Field(
        default=None,
        alias="domainName",
        description="Domain name of the switch",
    )
    hypershield_connectivity_status: Optional[str] = Field(
        default=None,
        alias="hypershieldConnectivityStatus",
        description="HyperShield connectivity status",
    )
    hypershield_tenant: Optional[str] = Field(
        default=None,
        alias="hypershieldTenant",
        description="HyperShield tenant identifier",
    )
    intended_system_mode: Optional[str] = Field(
        default=None,
        alias="intendedSystemMode",
        description="Intended system mode",
    )
    meta: Optional[SwitchAdditionalDataMeta] = Field(
        default=None,
        description="Internal metadata (switchDbId, switchUuid)",
    )
    platform_type: Optional[str] = Field(
        default=None,
        alias="platformType",
        description="Platform type, e.g. nx-os",
    )
    remote_credential_store: Optional[str] = Field(
        default=None,
        alias="remoteCredentialStore",
        description="Remote credential store type",
    )
    scalable_unit: Optional[str] = Field(
        default=None,
        alias="scalableUnit",
        description="Scalable unit identifier",
    )
    smart_switch: Optional[bool] = Field(
        default=None,
        alias="smartSwitch",
        description="Whether the switch is a smart switch",
    )
    source_interface_name: Optional[str] = Field(
        default=None,
        alias="sourceInterfaceName",
        description="Source interface name, e.g. mgmt0",
    )
    source_vrf_name: Optional[str] = Field(
        default=None,
        alias="sourceVrfName",
        description="Source VRF name, e.g. management",
    )
    system_mode: Optional[str] = Field(
        default=None,
        alias="systemMode",
        description="Current system mode",
    )
    usage: Optional[str] = Field(
        default=None,
        description="Usage classification, e.g. others",
    )
    username: Optional[str] = Field(
        default=None,
        description="Username for switch access",
    )
    vendor: Optional[str] = Field(
        default=None,
        description="Vendor name, e.g. Cisco",
    )


class SwitchRecord(NDNestedModel):
    """A single switch record as returned by GET /fabrics/{fabricName}/switches."""

    identifiers: ClassVar[List[str]] = []

    additional_data: Optional[SwitchAdditionalData] = Field(
        default=None,
        alias="additionalData",
        description="Extended switch metadata",
    )
    advisory_level: Optional[str] = Field(
        default=None,
        alias="advisoryLevel",
        description="Advisory level for the switch",
    )
    alert_suspend: Optional[str] = Field(
        default=None,
        alias="alertSuspend",
        description="Alert suspend status",
    )
    anomaly_level: Optional[str] = Field(
        default=None,
        alias="anomalyLevel",
        description="Anomaly level for the switch",
    )
    fabric_management_ip: Optional[str] = Field(
        default=None,
        alias="fabricManagementIp",
        description="Management IP address of the switch in the fabric",
    )
    fabric_name: Optional[str] = Field(
        default=None,
        alias="fabricName",
        description="Name of the fabric the switch belongs to",
    )
    fabric_type: Optional[str] = Field(
        default=None,
        alias="fabricType",
        description="Type of the fabric, e.g. vxlanIbgp",
    )
    hostname: Optional[str] = Field(
        default=None,
        description="Hostname of the switch",
    )
    model: Optional[str] = Field(
        default=None,
        description="Hardware model identifier, e.g. N9K-C9300v",
    )
    serial_number: Optional[str] = Field(
        default=None,
        alias="serialNumber",
        description="Serial number of the switch",
    )
    software_version: Optional[str] = Field(
        default=None,
        alias="softwareVersion",
        description="NX-OS software version running on the switch",
    )
    switch_id: Optional[str] = Field(
        default=None,
        alias="switchId",
        description="Unique switch identifier (typically the serial number)",
    )
    switch_role: Optional[str] = Field(
        default=None,
        alias="switchRole",
        description="Role of the switch in the fabric, e.g. leaf, spine",
    )
    system_up_time: Optional[str] = Field(
        default=None,
        alias="systemUpTime",
        description="System uptime string",
    )
    vpc_configured: Optional[bool] = Field(
        default=None,
        alias="vpcConfigured",
        description="Whether vPC is configured on this switch",
    )


class SwitchesMetaCounts(NDNestedModel):
    """Counts object inside the response ``meta`` block."""

    identifiers: ClassVar[List[str]] = []

    remaining: Optional[int] = Field(
        default=None,
        description="Number of remaining switches not returned in this page",
    )
    total: Optional[int] = Field(
        default=None,
        description="Total number of switches in the fabric",
    )


class SwitchesMeta(NDNestedModel):
    """``meta`` block in the GET switches response."""

    identifiers: ClassVar[List[str]] = []

    counts: Optional[SwitchesMetaCounts] = Field(
        default=None,
        description="Pagination counts",
    )


class GetAllSwitchesResponse(NDBaseModel):
    """
    Response body for GET /api/v1/manage/fabrics/{fabricName}/switches.

    Composite: contains List[SwitchRecord].
    """

    identifiers: ClassVar[List[str]] = []

    meta: Optional[SwitchesMeta] = Field(
        default=None,
        description="Response metadata including pagination counts",
    )
    switches: List[SwitchRecord] = Field(
        default_factory=list,
        description="List of switch records in the fabric",
    )

    @classmethod
    def from_response(cls, response: Any) -> "GetAllSwitchesResponse":
        """Create an instance from a raw API response.

        Accepts the raw value returned by ``nd.request()`` for the GET switches
        endpoint.  A dict with a ``switches`` key is validated directly; a bare
        list is wrapped automatically.
        """
        if isinstance(response, list):
            return cls.model_validate({"switches": response})
        if isinstance(response, dict):
            return cls.model_validate(response)
        return cls(switches=[])


__all__ = [
    "GetAllSwitchesResponse",
    "SwitchRecord",
    "SwitchesMeta",
    "SwitchesMetaCounts",
    "SwitchAdditionalData",
    "SwitchAdditionalDataMeta",
]
