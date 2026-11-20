# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import List, Dict, Optional, ClassVar, Literal
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel


class InfraTenantDomainModel(NDBaseModel):
    """
    Tenant Domain configuration for Nexus Dashboard Multi Tenancy.

    Identifier: name (single)

    API endpoints:
        - GET    /api/v1/infra/tenantDomains
        - GET    /api/v1/infra/tenantDomains/{tenantDomainName}
        - POST   /api/v1/infra/tenantDomains
        - PUT    /api/v1/infra/tenantDomains/{tenantDomainName}
        - DELETE /api/v1/infra/tenantDomains/{tenantDomainName}
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[Optional[List[str]]] = ["name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # --- Serialization Configuration ---

    exclude_from_diff: ClassVar[set] = set()

    # --- Fields ---

    name: str = Field(alias="name")
    tenant_names: Optional[List[str]] = Field(default=None, alias="tenantNames")
    description: Optional[str] = Field(default=None, alias="description")

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> Dict:
        return dict(
            config=dict(
                type="list",
                elements="dict",
                required=True,
                options=dict(
                    name=dict(type="str", required=True),
                    tenant_names=dict(type="list", elements="str"),
                    description=dict(type="str"),
                ),
            ),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "overridden", "deleted"],
            ),
        )
