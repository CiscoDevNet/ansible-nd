# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Request and response models for the ND Manage Interface Groups API."""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.config_models import (
    InterfaceGroupConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.enums import (
    InterfaceGroupOperationStatus,
    InterfaceGroupType,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.validators import (
    InterfaceGroupValidators,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)


class InterfaceGroupsCreateRequestModel(NDBaseModel):
    """Request body for POST ``/fabrics/{fabricName}/interfaceGroups``."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    interface_groups: list[InterfaceGroupConfigModel] = Field(alias="interfaceGroups", min_length=1)

    def to_payload(self, **kwargs) -> dict[str, Any]:
        """Serialize create entries with required empty associations and live wire aliases."""
        payload = super().to_payload(**kwargs)
        payload["interfaceGroups"] = [InterfaceGroupValidators.to_wire_group(item, include_empty_associations=True) for item in payload["interfaceGroups"]]
        return payload


class InterfaceGroupsRemoveRequestModel(NDBaseModel):
    """Request body for POST ``/fabrics/{fabricName}/interfaceGroups/actions/remove``."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    interface_group_names: list[str] = Field(alias="interfaceGroupNames", min_length=1)

    @field_validator("interface_group_names", mode="before")
    @classmethod
    def normalize_interface_group_names(cls, value):
        """Strip, de-duplicate, and sort interface group names."""
        return InterfaceGroupValidators.normalize_unique_strings(value)


class InterfaceGroupCreateResultModel(NDNestedModel):
    """One per-item result from the Interface Groups bulk-create HTTP 207 response."""

    type: InterfaceGroupType | None = Field(default=None)
    status: InterfaceGroupOperationStatus | None = Field(default=None)
    message: str | None = Field(default=None)

    @model_validator(mode="before")
    @classmethod
    def normalize_live_ethernet_type(cls, data):
        """Accept the generic Ethernet type returned by current ND create calls."""
        if isinstance(data, dict) and data.get("type") == "ethernet":
            normalized = dict(data)
            normalized["type"] = InterfaceGroupType.ETHERNET_WITH_POLICY.value
            return normalized
        return data


class InterfaceGroupDeleteResultModel(NDNestedModel):
    """One per-item result from an Interface Groups delete HTTP 207 response."""

    interface_group_name: str | None = Field(default=None, alias="interfaceGroupName")
    status: InterfaceGroupOperationStatus | None = Field(default=None)
    message: str | None = Field(default=None)


class InterfaceGroupsCreateResponseModel(NDBaseModel):
    """HTTP 207 response body for bulk Interface Group creation."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    interface_groups: list[InterfaceGroupCreateResultModel] = Field(default_factory=list, alias="interfaceGroups")

    @property
    def failures(self) -> list[InterfaceGroupCreateResultModel]:
        """Return failed per-item results; HTTP 207 alone is not success."""
        return [item for item in self.interface_groups if item.status != InterfaceGroupOperationStatus.SUCCESS.value]


class InterfaceGroupsDeleteResponseModel(NDBaseModel):
    """HTTP 207 response body for bulk Interface Group deletion."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    interface_groups: list[InterfaceGroupDeleteResultModel] = Field(default_factory=list, alias="interfaceGroups")

    @property
    def failures(self) -> list[InterfaceGroupDeleteResultModel]:
        """Return failed per-item results; HTTP 207 alone is not success."""
        return [item for item in self.interface_groups if item.status != InterfaceGroupOperationStatus.SUCCESS.value]


class InterfaceGroupsListResponseModel(NDBaseModel):
    """Response body for GET ``/fabrics/{fabricName}/interfaceGroups``."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    interface_group_details: list[InterfaceGroupConfigModel] = Field(default_factory=list, alias="interfaceGroupDetails")
    meta: dict[str, Any] | None = Field(default=None)

    @model_validator(mode="before")
    @classmethod
    def normalize_list_response_shape(cls, data):
        """Accept the standard list wrapper and supported type-specific wrappers."""
        if not isinstance(data, dict) or "interfaceGroupDetails" in data or "interface_group_details" in data:
            return data
        example_keys = (
            "anyInterfaceGroup",
            "ethernetCustomInterfaceGroup",
            "ethernetWithPolicyInterfaceGroup",
            "ethernetWithoutPolicyInterfaceGroup",
            # Retain compatibility with the documented misspelled response wrapper.
            "ethernetWithoutPolicyInyterfaceGroup",
            "portChannelInterfaceGroup",
            "vpcInterfaceGroup",
        )
        groups: list[Any] = []
        for key in example_keys:
            value = data.get(key)
            if isinstance(value, list):
                groups.extend(value)
        if not groups:
            return data
        normalized = dict(data)
        normalized["interfaceGroupDetails"] = groups
        return normalized
