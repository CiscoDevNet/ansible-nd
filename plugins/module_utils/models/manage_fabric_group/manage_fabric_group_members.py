# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import List, Dict, Any, Optional, ClassVar, Literal, Set
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    ConfigDict,
)
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

    identifiers: ClassVar[Optional[List[str]]] = ["name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # --- Serialization Configuration ---

    exclude_from_diff: ClassVar[Set[str]] = set()
    payload_exclude_fields: ClassVar[Set[str]] = {"fabric_type"}

    # --- Fields ---

    name: str = Field(alias="name")
    fabric_type: Optional[str] = Field(default=None, alias="type")

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
                    name=dict(type="str", required=True),
                ),
            ),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "deleted", "gathered"],
            ),
        )
