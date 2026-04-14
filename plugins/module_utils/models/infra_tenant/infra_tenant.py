# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Any, List, Dict, Optional, ClassVar, Literal, Set
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_serializer,
    field_validator,
    FieldSerializationInfo,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


class InfraTenantFabricAssociationModel(NDNestedModel):
    """
    Fabric association for a tenant.

    Canonical form (config):
        {"fabric_name": "fab1", "allowed_vlans": ["10-20"], "local_name": "loc1", "tenant_prefix": "pfx"}
    API payload form (manage API):
        {"fabricName": "fab1", "tenantName": "t1", "allowedVlans": ["10-20"], "localName": "loc1", "tenantPrefix": "pfx"}
    """

    fabric_name: str = Field(alias="fabricName")
    allowed_vlans: Optional[List[str]] = Field(default=None, alias="allowedVlans")
    local_name: Optional[str] = Field(default=None, alias="localName")
    tenant_prefix: Optional[str] = Field(default=None, alias="tenantPrefix")


class InfraTenantModel(NDBaseModel):
    """
    Tenant configuration for Nexus Dashboard Multi Tenancy.

    Identifier: name (single)

    API endpoints (tenant CRUD — infra API):
        - GET    /api/v1/infra/tenants
        - GET    /api/v1/infra/tenants/{tenantName}
        - POST   /api/v1/infra/tenants
        - PUT    /api/v1/infra/tenants/{tenantName}
        - DELETE /api/v1/infra/tenants/{tenantName}

    API endpoints (fabric associations — manage API):
        - GET  /api/v1/manage/tenantFabricAssociations
        - POST /api/v1/manage/tenantFabricAssociations

    Serialization notes:
        - ``fabric_associations`` is excluded from the infra API payload
          (handled by ``payload_exclude_fields``). The orchestrator sends
          association data to the manage API separately.
        - In config mode, ``fabric_associations`` appears as a flat list
          of dicts with snake_case keys.
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[Optional[List[str]]] = ["name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # --- Serialization Configuration ---

    exclude_from_diff: ClassVar[set] = set()
    payload_exclude_fields: ClassVar[Set[str]] = {"fabric_associations"}

    # --- Fields ---

    name: str = Field(alias="name")
    description: Optional[str] = Field(default=None, alias="description")
    fabric_associations: Optional[List[InfraTenantFabricAssociationModel]] = Field(
        default=None, alias="fabricAssociations"
    )

    # --- Serializers ---

    @field_serializer("fabric_associations")
    def serialize_fabric_associations(
        self,
        value: Optional[List[InfraTenantFabricAssociationModel]],
        info: FieldSerializationInfo,
    ) -> Any:
        if not value:
            return None

        mode = (info.context or {}).get("mode", "payload")

        if mode == "config":
            return [
                assoc.model_dump(by_alias=False, exclude_none=True)
                for assoc in value
            ]

        # Payload mode — not used directly (excluded via payload_exclude_fields),
        # but provided for completeness.
        return [
            assoc.model_dump(by_alias=True, exclude_none=True)
            for assoc in value
        ]

    # --- Validators ---

    @field_validator("fabric_associations", mode="before")
    @classmethod
    def normalize_fabric_associations(cls, value: Any) -> Optional[List[Dict]]:
        """
        Accept fabric_associations in either format:
            - List of dicts (Ansible config or merged orchestrator data)
            - None
        """
        if value is None:
            return None
        if isinstance(value, list):
            return value
        return value

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
                    description=dict(type="str"),
                    fabric_associations=dict(
                        type="list",
                        elements="dict",
                        options=dict(
                            fabric_name=dict(type="str", required=True),
                            allowed_vlans=dict(type="list", elements="str"),
                            local_name=dict(type="str"),
                            tenant_prefix=dict(type="str"),
                        ),
                    ),
                ),
            ),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "overridden", "deleted"],
            ),
        )
