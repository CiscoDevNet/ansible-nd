# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import List, Dict, Any, Optional, ClassVar, Literal
from ansible_collections.cisco.nd.plugins.module_utils.pydantic_compat import (
    Field,
    SecretStr,
    model_serializer,
    field_serializer,
    field_validator,
    model_validator,
    FieldSerializationInfo,
    SerializationInfo,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.constants import NDConstantMapping


USER_ROLES_MAPPING = NDConstantMapping(
    {
        "fabric_admin": "fabric-admin",
        "observer": "observer",
        "super_admin": "super-admin",
        "support_engineer": "support-engineer",
        "approver": "approver",
        "designer": "designer",
    }
)


class LocalUserSecurityDomainModel(NDNestedModel):
    """
    Security domain with assigned roles for a local user.

    Canonical form (config): {"name": "all", "roles": ["observer", "support_engineer"]}
    API payload form:        {"all": {"roles": ["observer", "support-engineer"]}}
    """

    name: str = Field(alias="name")
    roles: Optional[List[str]] = Field(default=None, alias="roles")

    @model_serializer()
    def serialize(self, info: SerializationInfo) -> Any:
        mode = (info.context or {}).get("mode", "payload")

        if mode == "config":
            result = {"name": self.name}
            if self.roles is not None:
                result["roles"] = list(self.roles)
            return result

        # Payload mode: nested dict with API role names
        api_roles = [USER_ROLES_MAPPING.get_dict().get(role, role) for role in (self.roles or [])]
        return {self.name: {"roles": api_roles}}


class LocalUserModel(NDBaseModel):
    """
    Local user configuration for Nexus Dashboard.

    Identifier: login_id (single)

    Serialization notes:
        - In payload mode, `reuse_limitation` and `time_interval_limitation`
          are nested under `passwordPolicy` (handled by base class via
          `payload_nested_fields`).
        - In config mode, they remain as flat top-level fields.
        - `security_domains` serializes as a nested dict in payload mode
          and a flat list of dicts in config mode.
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[Optional[List[str]]] = ["login_id"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # --- Serialization Configuration ---

    exclude_from_diff: ClassVar[set] = {"user_password"}
    unwanted_keys: ClassVar[List] = [
        ["passwordPolicy", "passwordChangeTime"],
        ["userID"],
    ]

    # In payload mode, nest these fields under "passwordPolicy"
    payload_nested_fields: ClassVar[Dict[str, List[str]]] = {
        "passwordPolicy": ["reuse_limitation", "time_interval_limitation"],
    }

    # --- Fields ---

    login_id: str = Field(alias="loginID")
    email: Optional[str] = Field(default=None, alias="email")
    first_name: Optional[str] = Field(default=None, alias="firstName")
    last_name: Optional[str] = Field(default=None, alias="lastName")
    user_password: Optional[SecretStr] = Field(default=None, alias="password")
    reuse_limitation: Optional[int] = Field(default=None, alias="reuseLimitation")
    time_interval_limitation: Optional[int] = Field(default=None, alias="timeIntervalLimitation")
    security_domains: Optional[List[LocalUserSecurityDomainModel]] = Field(default=None, alias="rbac")
    remote_id_claim: Optional[str] = Field(default=None, alias="remoteIDClaim")
    remote_user_authorization: Optional[bool] = Field(default=None, alias="xLaunch")

    # --- Serializers ---

    @field_serializer("user_password")
    def serialize_password(self, value: Optional[SecretStr]) -> Optional[str]:
        return value.get_secret_value() if value else None

    @field_serializer("security_domains")
    def serialize_security_domains(
        self,
        value: Optional[List[LocalUserSecurityDomainModel]],
        info: FieldSerializationInfo,
    ) -> Any:
        if not value:
            return None

        mode = (info.context or {}).get("mode", "payload")

        if mode == "config":
            return [domain.model_dump(context=info.context) for domain in value]

        # Payload mode: merge all domain dicts into {"domains": {...}}
        domains_dict = {}
        for domain in value:
            domains_dict.update(domain.model_dump(context=info.context))
        return {"domains": domains_dict}

    # --- Validators (Deserialization) ---

    @model_validator(mode="before")
    @classmethod
    def flatten_password_policy(cls, data: Any) -> Any:
        """
        Flatten nested passwordPolicy from API response into top-level fields.
        This is the inverse of the payload_nested_fields nesting.
        """
        if not isinstance(data, dict):
            return data

        policy = data.pop("passwordPolicy", None)
        if isinstance(policy, dict):
            if "reuseLimitation" in policy:
                data.setdefault("reuseLimitation", policy["reuseLimitation"])
            if "timeIntervalLimitation" in policy:
                data.setdefault("timeIntervalLimitation", policy["timeIntervalLimitation"])

        return data

    @field_validator("security_domains", mode="before")
    @classmethod
    def normalize_security_domains(cls, value: Any) -> Optional[List[Dict]]:
        """
        Accept security_domains in either format:
            - List of dicts (Ansible config): [{"name": "all", "roles": [...]}]
            - Nested dict (API response):     {"domains": {"all": {"roles": [...]}}}
        Always normalizes to the list-of-dicts form for model storage.
        """
        if value is None:
            return None

        # Already normalized (from Ansible config)
        if isinstance(value, list):
            return value

        # API response format
        if isinstance(value, dict) and "domains" in value:
            reverse_mapping = {v: k for k, v in USER_ROLES_MAPPING.get_dict().items()}
            return [
                {
                    "name": domain_name,
                    "roles": [reverse_mapping.get(role, role) for role in domain_data.get("roles", [])],
                }
                for domain_name, domain_data in value["domains"].items()
            ]

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
                    email=dict(type="str"),
                    login_id=dict(type="str", required=True),
                    first_name=dict(type="str"),
                    last_name=dict(type="str"),
                    user_password=dict(type="str", no_log=True),
                    reuse_limitation=dict(type="int"),
                    time_interval_limitation=dict(type="int"),
                    security_domains=dict(
                        type="list",
                        elements="dict",
                        options=dict(
                            name=dict(
                                type="str",
                                required=True,
                                aliases=[
                                    "security_domain_name",
                                    "domain_name",
                                ],
                            ),
                            roles=dict(
                                type="list",
                                elements="str",
                                choices=USER_ROLES_MAPPING.get_original_data(),
                            ),
                        ),
                        aliases=["domains"],
                    ),
                    remote_id_claim=dict(type="str"),
                    remote_user_authorization=dict(type="bool"),
                ),
            ),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "overridden", "deleted"],
            ),
        )
