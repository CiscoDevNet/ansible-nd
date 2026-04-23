# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import ClassVar, Dict, List, Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel


class AclModel(NDBaseModel):
    """
    Access Control List (ACL) configuration for Nexus Dashboard.

    Identifier: composite (fabric_name, name)

    Serialization notes:
        - fabric_name is excluded from API payload (path parameter only).
        - Entries are handled as plain dicts in the orchestrator due to
          their complex value-mapping requirements (port actions, etc.).
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[Optional[List[str]]] = ["fabric_name", "name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "composite"

    # --- Serialization Configuration ---

    payload_exclude_fields: ClassVar[set] = {"fabric_name"}

    # --- Fields ---

    fabric_name: str = Field(alias="fabricName")
    name: str = Field(alias="name")
    ip_version: Optional[str] = Field(default=None, alias="type")
    description: Optional[str] = Field(default=None, alias="description")

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> Dict:
        entry_spec = dict(
            sequence_number=dict(type="int", required=True),
            action=dict(type="str", required=True, choices=["permit", "deny", "remark"]),
            remark_comment=dict(type="str"),
            protocol=dict(
                type="str",
                choices=["ip", "ipv6", "tcp", "udp", "icmp", "igmp", "eigrp", "ospf", "pim", "ahp", "gre", "nos", "esp", "custom"],
            ),
            custom_protocol=dict(type="int"),
            src=dict(type="str"),
            dst=dict(type="str"),
            src_port_action=dict(
                type="str",
                default="none",
                choices=["none", "equal_to", "greater_than", "less_than", "not_equal_to", "port_range"],
            ),
            src_port=dict(type="int"),
            src_port_range_start=dict(type="int"),
            src_port_range_end=dict(type="int"),
            dst_port_action=dict(
                type="str",
                default="none",
                choices=["none", "equal_to", "greater_than", "less_than", "not_equal_to", "port_range"],
            ),
            dst_port=dict(type="int"),
            dst_port_range_start=dict(type="int"),
            dst_port_range_end=dict(type="int"),
            icmp_option=dict(type="str"),
            tcp_option=dict(type="str"),
        )

        acl_spec = dict(
            name=dict(type="str", required=True),
            type=dict(type="str", choices=["ipv4", "ipv6"]),
            description=dict(type="str"),
            entries=dict(type="list", elements="dict", default=[], options=entry_spec),
        )

        return dict(
            fabric=dict(type="str", required=True),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "deleted", "gathered"],
            ),
            config=dict(type="list", elements="dict", default=[], options=acl_spec),
        )
