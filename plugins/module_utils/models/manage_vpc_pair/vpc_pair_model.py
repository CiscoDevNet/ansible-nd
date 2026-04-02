# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Any, ClassVar, Dict, List, Literal, Optional, Set, Union

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import (
    NDBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import (
    VpcFieldNames,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vpc_pair.vpc_pair_base import (
    SwitchPairKeyMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vpc_pair.vpc_pair_common import (
    normalize_vpc_pair_aliases,
    serialize_vpc_pair_details,
    validate_distinct_switches,
    validate_non_empty_switch_id,
)

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vpc_pair.vpc_pair_models import (
    VpcPairDetailsDefault,
    VpcPairDetailsCustom,
)


class VpcPairModel(SwitchPairKeyMixin, NDBaseModel):
    """
    Pydantic model for nd_manage_vpc_pair input.

    Uses a composite identifier `(switch_id, peer_switch_id)` and module-oriented
    defaults/validation behavior.
    """

    identifiers: ClassVar[List[str]] = ["switch_id", "peer_switch_id"]
    identifier_strategy: ClassVar[Literal["composite"]] = "composite"
    exclude_from_diff: ClassVar[Set[str]] = set()

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        validate_by_alias=True,
        validate_by_name=True,
        extra="ignore",
    )

    switch_id: str = Field(
        alias=VpcFieldNames.SWITCH_ID,
        description="Peer-1 switch serial number or management IP address",
        min_length=3,
        max_length=64,
    )
    peer_switch_id: str = Field(
        alias=VpcFieldNames.PEER_SWITCH_ID,
        description="Peer-2 switch serial number or management IP address",
        min_length=3,
        max_length=64,
    )
    use_virtual_peer_link: bool = Field(
        default=False,
        alias=VpcFieldNames.USE_VIRTUAL_PEER_LINK,
        description="Virtual peer link enabled",
    )
    vpc_pair_details: Optional[Union[VpcPairDetailsDefault, VpcPairDetailsCustom]] = Field(
        default=None,
        discriminator="type",
        alias=VpcFieldNames.VPC_PAIR_DETAILS,
        description="VPC pair configuration details (default or custom template)",
    )

    @field_validator("switch_id", "peer_switch_id")
    @classmethod
    def validate_switch_id_format(cls, v: str) -> str:
        """
        Validate switch ID is not empty or whitespace.

        Args:
            v: Raw switch ID string

        Returns:
            Stripped switch ID string.

        Raises:
            ValueError: If switch ID is empty or whitespace-only
        """
        return validate_non_empty_switch_id(v)

    @model_validator(mode="after")
    def validate_different_switches(self) -> "VpcPairModel":
        """
        Validate that switch_id and peer_switch_id are not the same.

        Returns:
            Self if validation passes.

        Raises:
            ValueError: If both switch IDs are identical
        """
        validate_distinct_switches(
            self.switch_id, self.peer_switch_id, "switch_id", "peer_switch_id"
        )
        return self

    def to_payload(self) -> Dict[str, Any]:
        """
        Serialize model to camelCase API payload dict.

        Returns:
            Dict with alias (camelCase) keys, excluding None values.
        """
        return self.model_dump(by_alias=True, exclude_none=True)

    def to_diff_dict(self) -> Dict[str, Any]:
        """
        Serialize model for diff comparison, excluding configured fields.

        Returns:
            Dict with alias keys, excluding None and exclude_from_diff fields.
        """
        return self.model_dump(
            by_alias=True,
            exclude_none=True,
            exclude=set(self.exclude_from_diff),
        )

    def get_identifier_value(self):
        """
        Return the unique identifier for this vPC pair.

        Returns:
            Tuple of sorted (switch_id, peer_switch_id) for order-independent matching.
        """
        return tuple(sorted([self.switch_id, self.peer_switch_id]))

    def to_config(self, **kwargs) -> Dict[str, Any]:
        """
        Serialize model to snake_case Ansible config dict.

        Args:
            **kwargs: Additional kwargs passed to model_dump

        Returns:
            Dict with Python-name keys, excluding None values.
        """
        return self.model_dump(by_alias=False, exclude_none=True, **kwargs)

    @classmethod
    def from_config(cls, ansible_config: Dict[str, Any]) -> "VpcPairModel":
        """
        Construct VpcPairModel from playbook config dict.

        Accepts both snake_case module input and API camelCase aliases.

        Args:
            ansible_config: Dict from playbook config item

        Returns:
            Validated VpcPairModel instance.
        """
        data = normalize_vpc_pair_aliases(ansible_config)
        return cls.model_validate(data, by_alias=True, by_name=True)

    def merge(self, other_model: "VpcPairModel") -> "VpcPairModel":
        """
        Merge non-None values from another model into this instance.

        Args:
            other_model: VpcPairModel whose non-None fields overwrite this model

        Returns:
            Self with merged values.

        Raises:
            TypeError: If other_model is not the same type
        """
        if not isinstance(other_model, type(self)):
            raise TypeError(
                "VpcPairModel.merge requires both models to be the same type"
            )

        merged_data = self.model_dump(by_alias=False, exclude_none=False)
        incoming_data = other_model.model_dump(by_alias=False, exclude_none=False)
        for field, value in incoming_data.items():
            if value is None:
                continue
            merged_data[field] = value

        # Validate once after the full merge so reversed pair updates do not
        # fail on transient assignment states with validate_assignment=True.
        return type(self).model_validate(merged_data, by_name=True, by_alias=True)

    @classmethod
    def from_response(cls, response: Dict[str, Any]) -> "VpcPairModel":
        """
        Construct VpcPairModel from an API response dict.

        Args:
            response: Dict from ND API response

        Returns:
            Validated VpcPairModel instance.
        """
        data = {
            VpcFieldNames.SWITCH_ID: response.get(VpcFieldNames.SWITCH_ID),
            VpcFieldNames.PEER_SWITCH_ID: response.get(VpcFieldNames.PEER_SWITCH_ID),
            VpcFieldNames.USE_VIRTUAL_PEER_LINK: response.get(
                VpcFieldNames.USE_VIRTUAL_PEER_LINK, False
            ),
            VpcFieldNames.VPC_PAIR_DETAILS: response.get(VpcFieldNames.VPC_PAIR_DETAILS),
        }
        return cls.model_validate(data)

    @classmethod
    def get_argument_spec(cls) -> Dict[str, Any]:
        """
        Return Ansible argument_spec for nd_manage_vpc_pair.

        Backward-compatible wrapper around the dedicated playbook config model.
        """
        return VpcPairPlaybookConfigModel.get_argument_spec()


class VpcPairPlaybookItemModel(BaseModel):
    """
    One item under playbook `config` for nd_manage_vpc_pair.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        validate_by_alias=True,
        validate_by_name=True,
        extra="ignore",
    )

    peer1_switch_id: str = Field(
        alias="switch_id",
        description="Peer-1 switch serial number or management IP address",
        min_length=3,
        max_length=64,
    )
    peer2_switch_id: str = Field(
        alias="peer_switch_id",
        description="Peer-2 switch serial number or management IP address",
        min_length=3,
        max_length=64,
    )
    use_virtual_peer_link: bool = Field(
        default=False,
        description="Virtual peer link enabled",
    )
    vpc_pair_details: Optional[Union[VpcPairDetailsDefault, VpcPairDetailsCustom]] = Field(
        default=None,
        discriminator="type",
        alias=VpcFieldNames.VPC_PAIR_DETAILS,
        description="VPC pair configuration details (default or custom template)",
    )

    @field_validator("peer1_switch_id", "peer2_switch_id")
    @classmethod
    def validate_switch_id_format(cls, v: str) -> str:
        """
        Validate switch ID is not empty or whitespace.

        Args:
            v: Raw switch ID string

        Returns:
            Stripped switch ID string.

        Raises:
            ValueError: If switch ID is empty or whitespace-only
        """
        return validate_non_empty_switch_id(v)

    @model_validator(mode="after")
    def validate_different_switches(self) -> "VpcPairPlaybookItemModel":
        """
        Validate that peer1_switch_id and peer2_switch_id are not the same.

        Returns:
            Self if validation passes.

        Raises:
            ValueError: If both switch IDs are identical
        """
        validate_distinct_switches(
            self.peer1_switch_id,
            self.peer2_switch_id,
            "peer1_switch_id",
            "peer2_switch_id",
        )
        return self

    def to_runtime_config(self) -> Dict[str, Any]:
        """
        Normalize playbook keys into runtime keys consumed by state machine code.

        Returns:
            Dict with both snake_case and camelCase keys for switch IDs,
            use_virtual_peer_link, and vpc_pair_details.
        """
        switch_id = self.peer1_switch_id
        peer_switch_id = self.peer2_switch_id
        use_virtual_peer_link = self.use_virtual_peer_link
        serialized_details = serialize_vpc_pair_details(self.vpc_pair_details)
        return {
            "switch_id": switch_id,
            "peer_switch_id": peer_switch_id,
            "use_virtual_peer_link": use_virtual_peer_link,
            "vpc_pair_details": serialized_details,
            VpcFieldNames.SWITCH_ID: switch_id,
            VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
            VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_virtual_peer_link,
            VpcFieldNames.VPC_PAIR_DETAILS: serialized_details,
        }


class VpcPairPlaybookConfigModel(BaseModel):
    """
    Top-level playbook configuration model for nd_manage_vpc_pair.
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
        validate_by_alias=True,
        validate_by_name=True,
        extra="ignore",
    )

    state: Literal["merged", "replaced", "deleted", "overridden", "gathered"] = Field(
        default="merged",
        description="Desired state for vPC pair configuration",
    )
    fabric_name: str = Field(description="Fabric name")
    deploy: bool = Field(default=True, description="Deploy after configuration changes")
    force: bool = Field(
        default=False,
        description="Force deletion without pre-deletion safety checks",
    )
    api_timeout: int = Field(
        default=30,
        description="API request timeout in seconds for write operations",
    )
    query_timeout: int = Field(
        default=10,
        description="API request timeout in seconds for query/recommendation operations",
    )
    refresh_after_apply: bool = Field(
        default=True,
        description="Refresh final after-state with a post-apply query",
    )
    refresh_after_timeout: Optional[int] = Field(
        default=None,
        description="Optional timeout for post-apply refresh query",
    )
    suppress_verification: bool = Field(
        default=False,
        description="Skip final after-state refresh query",
    )
    config: Optional[List[VpcPairPlaybookItemModel]] = Field(
        default=None,
        description="List of vPC pair configurations",
    )

    @classmethod
    def get_argument_spec(cls) -> Dict[str, Any]:
        """
        Return Ansible argument_spec for nd_manage_vpc_pair.
        """
        return dict(
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "deleted", "overridden", "gathered"],
            ),
            fabric_name=dict(type="str", required=True),
            deploy=dict(type="bool", default=True),
            force=dict(
                type="bool",
                default=False,
                description=(
                    "Force deletion without pre-deletion validation "
                    "(bypasses safety checks)"
                ),
            ),
            api_timeout=dict(
                type="int",
                default=30,
                description=(
                    "API request timeout in seconds for primary operations"
                ),
            ),
            query_timeout=dict(
                type="int",
                default=10,
                description=(
                    "API request timeout in seconds for query/recommendation "
                    "operations"
                ),
            ),
            refresh_after_apply=dict(
                type="bool",
                default=True,
                description=(
                    "Refresh final after-state by querying controller "
                    "after write operations"
                ),
            ),
            refresh_after_timeout=dict(
                type="int",
                required=False,
                description=(
                    "Optional timeout in seconds for post-apply after-state "
                    "refresh query"
                ),
            ),
            suppress_verification=dict(
                type="bool",
                default=False,
                description=(
                    "Skip post-apply controller query for after-state "
                    "verification (alias for refresh_after_apply=false)."
                ),
            ),
            config=dict(
                type="list",
                elements="dict",
                options=dict(
                    peer1_switch_id=dict(
                        type="str", required=True, aliases=["switch_id"]
                    ),
                    peer2_switch_id=dict(
                        type="str", required=True, aliases=["peer_switch_id"]
                    ),
                    use_virtual_peer_link=dict(type="bool", default=False),
                    vpc_pair_details=dict(type="dict"),
                ),
            ),
        )
