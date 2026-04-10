# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import List, Dict, Any, Optional, ClassVar, Literal, Set

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel


class ManageTorModel(NDBaseModel):
    """
    Access/ToR switch association configuration for Nexus Dashboard.

    Identifier: composite (fabric_name, access_or_tor_switch_id, aggregation_or_leaf_switch_id)

    Serialization notes:
        - fabric_name is excluded from API payload (path parameter only).
        - Port channel and VPC ID fields are nested under "resources" in
          payload mode but remain flat in config mode.
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[Optional[List[str]]] = [
        "fabric_name",
        "access_or_tor_switch_id",
        "aggregation_or_leaf_switch_id",
    ]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "composite"

    # --- Serialization Configuration ---

    # fabric_name is a path parameter; hostname fields are read-only from API responses
    payload_exclude_fields: ClassVar[Set[str]] = {
        "fabric_name",
        "access_or_tor_switch_name",
        "access_or_tor_peer_switch_name",
    }
    exclude_from_diff: ClassVar[Set[str]] = {
        "access_or_tor_switch_name",
        "access_or_tor_peer_switch_name",
    }

    # In payload mode, nest these fields under "resources"
    payload_nested_fields: ClassVar[Dict[str, List[str]]] = {
        "resources": [
            "access_or_tor_port_channel_id",
            "aggregation_or_leaf_port_channel_id",
            "access_or_tor_peer_port_channel_id",
            "access_or_tor_vpc_id",
            "aggregation_or_leaf_peer_port_channel_id",
            "aggregation_or_leaf_vpc_id",
        ],
    }

    # --- Fields ---

    # Path parameter / scope
    fabric_name: str = Field(alias="fabricName")

    # Required switch identifiers
    access_or_tor_switch_id: str = Field(alias="accessOrTorSwitchId")
    aggregation_or_leaf_switch_id: str = Field(alias="aggregationOrLeafSwitchId")

    # Optional VPC peer switch identifiers
    access_or_tor_peer_switch_id: Optional[str] = Field(default=None, alias="accessOrTorPeerSwitchId")
    aggregation_or_leaf_peer_switch_id: Optional[str] = Field(default=None, alias="aggregationOrLeafPeerSwitchId")

    # Read-only hostname fields (returned by API, never sent in payloads)
    access_or_tor_switch_name: Optional[str] = Field(default=None, alias="accessOrTorSwitchName")
    access_or_tor_peer_switch_name: Optional[str] = Field(default=None, alias="accessOrTorPeerSwitchName")

    # Resource fields (nested under "resources" in API payload)
    access_or_tor_port_channel_id: Optional[int] = Field(default=None, alias="accessOrTorPortChannelId")
    aggregation_or_leaf_port_channel_id: Optional[int] = Field(default=None, alias="aggregationOrLeafPortChannelId")
    access_or_tor_peer_port_channel_id: Optional[int] = Field(default=None, alias="accessOrTorPeerPortChannelId")
    access_or_tor_vpc_id: Optional[int] = Field(default=None, alias="accessOrTorVpcId")
    aggregation_or_leaf_peer_port_channel_id: Optional[int] = Field(default=None, alias="aggregationOrLeafPeerPortChannelId")
    aggregation_or_leaf_vpc_id: Optional[int] = Field(default=None, alias="aggregationOrLeafVpcId")

    # --- Validators (Deserialization) ---

    @model_validator(mode="before")
    @classmethod
    def flatten_resources(cls, data: Any) -> Any:
        """
        Flatten nested resources from API response into top-level fields.
        This is the inverse of the payload_nested_fields nesting.
        """
        if not isinstance(data, dict):
            return data

        resources = data.pop("resources", None)
        if isinstance(resources, dict):
            for key, val in resources.items():
                data.setdefault(key, val)

        return data

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> Dict:
        return dict(
            fabric_name=dict(type="str", required=True),
            config=dict(
                type="list",
                elements="dict",
                options=dict(
                    access_or_tor_switch_id=dict(type="str"),
                    aggregation_or_leaf_switch_id=dict(type="str", required=True),
                    access_or_tor_peer_switch_id=dict(type="str"),
                    aggregation_or_leaf_peer_switch_id=dict(type="str"),
                    access_or_tor_port_channel_id=dict(type="int"),
                    aggregation_or_leaf_port_channel_id=dict(type="int"),
                    access_or_tor_peer_port_channel_id=dict(type="int"),
                    access_or_tor_vpc_id=dict(type="int"),
                    aggregation_or_leaf_peer_port_channel_id=dict(type="int"),
                    aggregation_or_leaf_vpc_id=dict(type="int"),
                ),
            ),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "deleted", "gathered"],
            ),
            # gathered also requires config to provide aggregation_or_leaf_switch_id
            # for the ND API query parameter (enforced via required_if in the module).
        )
