# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import List, Dict, Any, Optional, ClassVar, Literal, Set
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    ConfigDict,
)
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.argument_spec import config_actions_spec
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import FABRIC_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel


class FabricGroupMemberModel(NDBaseModel):
    """
    Fabric group member configuration for Nexus Dashboard.

    Represents a single member fabric within a fabric group.

    Identifier: name (single)

    API details:
        - Members are added via POST /fabrics/{fabricName}/actions/addMembers
        - Members are removed via POST /fabrics/{fabricName}/actions/removeMembers
        - Members are queried via GET /fabrics/{fabricName}/members
        - The parent fabric group name is a module-level parameter, not part of
          the member model itself.
    """

    model_config = ConfigDict(populate_by_name=True)

    # --- Identifier Configuration ---

    identifiers: ClassVar[Optional[List[str]]] = ["member_name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # --- Serialization Configuration ---

    # fabric_type is read-only (returned by GET, not settable and absent from the argument spec),
    # so it must not make an already-present member look "changed" during the merged diff.
    exclude_from_diff: ClassVar[Set[str]] = {"fabric_type"}
    payload_exclude_fields: ClassVar[Set[str]] = {"fabric_type"}

    # ``cluster_name`` feeds the composite MCFG identity, so a templated value resolving to
    # "" would otherwise key the member as ``("", name)`` and never match what ND stores.
    empty_string_means_unset: ClassVar[bool] = True

    # --- Fields ---

    member_name: str = Field(alias="name")
    fabric_type: Optional[str] = Field(default=None, alias="type")
    # Identifies the cluster hosting the member. Required for a multi-cluster fabric group,
    # where OneManage addresses a member as (clusterName, name) and rejects a member without
    # it; absent for a plain fabric group, whose Manage responses never carry it. The
    # orchestrator enforces that split once the surface is resolved, because a clusterName
    # sent to Manage is accepted and silently dropped, which would desynchronise the identity
    # below from what ND actually stores.
    cluster_name: Optional[str] = Field(default=None, alias="clusterName")

    # --- Identifier ---

    def get_identifier_value(self):
        """
        Identify a member by name for a fabric group, and by (cluster_name, name) for a
        multi-cluster fabric group so members with the same fabric name in different clusters
        remain distinct.
        """
        if self.cluster_name:
            return (self.cluster_name, self.member_name)
        return self.member_name

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> Dict[str, Any]:
        return dict(
            fabric_name=dict(type="str", required=True),
            config=dict(
                type="list",
                elements="dict",
                required=True,
                options=dict(
                    member_name=dict(type="str", required=True),
                    cluster_name=dict(type="str", required=False),
                ),
            ),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "deleted", "gathered"],
            ),
            **config_actions_spec(FABRIC_CONFIG_ACTIONS),
        )
