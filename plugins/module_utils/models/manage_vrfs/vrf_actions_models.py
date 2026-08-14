# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""VRF action models (API request/response representations for VRF actions).

Based on OpenAPI schema for Nexus Dashboard Manage APIs v1.1.332.

Covers:
- POST /fabrics/{fabricName}/vrfActions/deploy
- POST /fabrics/{fabricName}/vrfActions/export
- POST /fabrics/{fabricName}/vrfActions/preview
- POST /fabrics/{fabricName}/vrfActions/remove
- POST /fabrics/{fabricName}/vrfActions/stretch
"""

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.enums import (
    ConfigurationStatus,
    OperationStatus,
    VrfAttachmentSwitchRole,
)

# =============================================================================
# Shared nested models
# =============================================================================


class MultiStatusBaseModel(NDNestedModel):
    """
    Common status fields returned in multi-operation 207 responses.

    Based on: components/schemas/schemas-multiStatusBase
    """

    identifiers: ClassVar[list[str]] = []
    vrf_name: str | None = Field(
        default=None,
        alias="vrfName",
        max_length=94,
        description="Name of the VRF this status entry describes",
    )
    status: OperationStatus | None = Field(
        default=None,
        description="Outcome of the operation for this VRF",
    )
    message: str | None = Field(
        default=None,
        description="Error message in case of operation failure",
    )


class VrfOrNetworkPreviewModel(NDNestedModel):
    """
    VRF or Network preview information for a single switch attachment.

    Based on: components/schemas/vrfOrNetworkPreview
    """

    identifiers: ClassVar[list[str]] = []
    fabric_name: str | None = Field(
        default=None,
        alias="fabricName",
        description="Name of the fabric that the switch belongs to",
    )
    switch_id: str | None = Field(
        default=None,
        alias="switchId",
        description="Serial number of the switch",
    )
    switch_ip: str | None = Field(
        default=None,
        alias="switchIp",
        description="IPv4 address of the switch",
    )
    switch_name: str | None = Field(
        default=None,
        alias="switchName",
        description="Name of the switch",
    )
    switch_role: VrfAttachmentSwitchRole | None = Field(
        default=None,
        alias="switchRole",
        description="Role of the switch in the fabric",
    )
    status: ConfigurationStatus | None = Field(
        default=None,
        description="Pending configuration status",
    )
    pending_configs: list[str] | None = Field(
        default=None,
        alias="pendingConfigs",
        description=("List of pending configuration commands for the switch"),
    )


class VrfAttachmentPreviewModel(NDNestedModel):
    """
    Per-VRF preview of pending configuration changes on a switch.

    Based on: components/schemas/attachmentPreview
    (allOf: vrfOrNetworkPreview + vrfName)
    """

    identifiers: ClassVar[list[str]] = []
    fabric_name: str | None = Field(
        default=None,
        alias="fabricName",
        description="Name of the fabric that the switch belongs to",
    )
    switch_id: str | None = Field(
        default=None,
        alias="switchId",
        description="Serial number of the switch",
    )
    switch_ip: str | None = Field(
        default=None,
        alias="switchIp",
        description="IPv4 address of the switch",
    )
    switch_name: str | None = Field(
        default=None,
        alias="switchName",
        description="Name of the switch",
    )
    switch_role: VrfAttachmentSwitchRole | None = Field(
        default=None,
        alias="switchRole",
        description="Role of the switch in the fabric",
    )
    status: ConfigurationStatus | None = Field(
        default=None,
        description="Pending configuration status",
    )
    pending_configs: list[str] | None = Field(
        default=None,
        alias="pendingConfigs",
        description=("List of pending configuration commands for the switch"),
    )
    vrf_name: str = Field(
        default=...,
        alias="vrfName",
        max_length=94,
        description="Name of the VRF",
    )


class VrfStretchItemModel(NDNestedModel):
    """
    VRF name / stretch-target pair for stretch operations.

    Based on: components/schemas/vrfStretchItem
    """

    identifiers: ClassVar[list[str]] = []
    vrf_name: str = Field(
        default=...,
        alias="vrfName",
        max_length=94,
        description="Name of the VRF to stretch",
    )
    stretch: str = Field(
        default=...,
        description=("Stretch target. Use 'allBgwList' to stretch to all border " "gateways, or 'none' to remove stretching."),
    )


class VrfStretchStatusModel(NDNestedModel):
    """
    Status of a single VRF in a stretch 207 response.

    Based on: components/schemas/vrfStretchStatus
    (allOf: schemas-multiStatusBase + stretch)
    """

    identifiers: ClassVar[list[str]] = []
    vrf_name: str | None = Field(
        default=None,
        alias="vrfName",
        max_length=94,
        description="Name of the VRF",
    )
    status: OperationStatus | None = Field(
        default=None,
        description="Outcome of the stretch operation for this VRF",
    )
    message: str | None = Field(
        default=None,
        description="Error message in case of operation failure",
    )
    stretch: str | None = Field(
        default=None,
        description="Stretch target value applied to this VRF",
    )


# =============================================================================
# Request models
# =============================================================================


class VrfDeployRequestModel(NDBaseModel):
    """
    Request body for deploying or previewing VRF configurations.

    Based on: components/schemas/deployVrfsRequest
    Path: POST /fabrics/{fabricName}/vrfActions/deploy
          POST /fabrics/{fabricName}/vrfActions/preview
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    vrf_names: list[str] = Field(
        default=...,
        alias="vrfNames",
        min_length=1,
        description="Names of VRFs to deploy",
    )
    switch_fabric_names: list[str] | None = Field(
        default=None,
        alias="switchFabricNames",
        description=("Names of the switch fabrics to which deployment should be " "limited. Leave unset to deploy to all fabrics."),
    )
    switch_ids: list[str] | None = Field(
        default=None,
        alias="switchIds",
        description=("Serial numbers of the switches to which deployment should " "be limited. Leave unset to deploy to all switches."),
    )


class VrfExportRequestModel(NDBaseModel):
    """
    Request body for exporting VRF definitions as CSV.

    Based on: components/schemas/exportVrfs
    Path: POST /fabrics/{fabricName}/vrfActions/export
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    vrf_names: list[str] | None = Field(
        default=None,
        alias="vrfNames",
        description=("Names of the VRFs to export. If null or empty, all VRFs " "in the fabric are exported."),
    )


class VrfRemoveRequestModel(NDBaseModel):
    """
    Request body for removing one or more VRFs.

    Based on: POST /fabrics/{fabricName}/vrfActions/remove request body
    Schema: ``{ vrfNames: string[] }``
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    vrf_names: list[str] = Field(
        default=...,
        alias="vrfNames",
        min_length=1,
        description="Names of the VRFs to remove",
    )


class VrfStretchRequestModel(NDBaseModel):
    """
    Request body for stretching VRFs to border gateways.

    Based on: components/schemas/vrfStretchPayload
    Path: POST /fabrics/{fabricName}/vrfActions/stretch
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    attachments: list[VrfStretchItemModel] | None = Field(
        default=None,
        description="List of VRF name and stretch-target pairs",
    )


# =============================================================================
# Response models
# =============================================================================


class VrfRemoveResponseModel(NDBaseModel):
    """
    Response body for a bulk VRF remove operation.

    Based on: POST /fabrics/{fabricName}/vrfActions/remove response
    Schema: ``{ results: schemas-multiStatusBase[] }``
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    results: list[MultiStatusBaseModel] | None = Field(
        default=None,
        description=("Status of each VRF removal. Will contain only the entries " "with failure status."),
    )


class VrfStretch207ResponseModel(NDBaseModel):
    """
    207 multi-status response for a VRF stretch operation.

    Based on: components/schemas/vrfStretch207Status
    Path: POST /fabrics/{fabricName}/vrfActions/stretch response
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    results: list[VrfStretchStatusModel] | None = Field(
        default=None,
        description="Status of each VRF stretch request",
    )


class VrfPreviewResponseModel(NDBaseModel):
    """
    Response body for a VRF configuration preview.

    Based on: components/schemas/previewPendingVrfChanges
    Path: POST /fabrics/{fabricName}/vrfActions/preview response
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    attachments: list[VrfAttachmentPreviewModel] | None = Field(
        default=None,
        description=("List of pending configuration changes per VRF per switch"),
    )


__all__ = [
    "MultiStatusBaseModel",
    "VrfAttachmentPreviewModel",
    "VrfDeployRequestModel",
    "VrfExportRequestModel",
    "VrfOrNetworkPreviewModel",
    "VrfPreviewResponseModel",
    "VrfRemoveRequestModel",
    "VrfRemoveResponseModel",
    "VrfStretch207ResponseModel",
    "VrfStretchItemModel",
    "VrfStretchRequestModel",
    "VrfStretchStatusModel",
]
