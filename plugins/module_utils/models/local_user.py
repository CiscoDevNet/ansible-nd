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
    computed_field,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.constants import NDConstantMapping

# Constant defined here as it is only used in this model
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
    """Security domain configuration for local user (nested model)."""

    # Fields
    name: str = Field(alias="name", exclude=True)
    roles: Optional[List[str]] = Field(default=None, alias="roles", exclude=True)

    # -- Serialization (Model instance -> API payload) --

    @model_serializer()
    def serialize_model(self) -> Dict:
        return {self.name: {"roles": [USER_ROLES_MAPPING.get_dict().get(role, role) for role in (self.roles or [])]}}

    # NOTE: Deserialization defined in `LocalUserModel` due to API response complexity


# TODO: Add field validation (e.g. me, le, choices, etc...) (low priority)
class LocalUserModel(NDBaseModel):
    """
    Local user configuration.

    Identifier: login_id (single field)
    """

    # Identifier configuration
    # TODO: Revisit this identifiers strategy (low priority)
    identifiers: ClassVar[Optional[List[str]]] = ["login_id"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # Keys management configurations
    # TODO: Revisit these configurations (low priority)
    exclude_from_diff: ClassVar[List[str]] = ["user_password"]
    unwanted_keys: ClassVar[List] = [["passwordPolicy", "passwordChangeTime"], ["userID"]]  # Nested path  # Simple key

    # Fields
    # NOTE: `alias` are NOT the ansible aliases. they are the equivalent attribute's names from the API spec
    login_id: str = Field(alias="loginID")
    email: Optional[str] = Field(default=None, alias="email")
    first_name: Optional[str] = Field(default=None, alias="firstName")
    last_name: Optional[str] = Field(default=None, alias="lastName")
    user_password: Optional[SecretStr] = Field(default=None, alias="password")
    reuse_limitation: Optional[int] = Field(default=None, alias="reuseLimitation", exclude=True)
    time_interval_limitation: Optional[int] = Field(default=None, alias="timeIntervalLimitation", exclude=True)
    security_domains: Optional[List[LocalUserSecurityDomainModel]] = Field(default=None, alias="rbac")
    remote_id_claim: Optional[str] = Field(default=None, alias="remoteIDClaim")
    remote_user_authorization: Optional[bool] = Field(default=None, alias="xLaunch")

    # -- Serialization (Model instance -> API payload) --

    @computed_field(alias="passwordPolicy")
    @property
    def password_policy(self) -> Optional[Dict[str, int]]:
        """Computed nested structure for API payload."""
        if self.reuse_limitation is None and self.time_interval_limitation is None:
            return None

        policy = {}
        if self.reuse_limitation is not None:
            policy["reuseLimitation"] = self.reuse_limitation
        if self.time_interval_limitation is not None:
            policy["timeIntervalLimitation"] = self.time_interval_limitation
        return policy

    @field_serializer("user_password")
    def serialize_password(self, value: Optional[SecretStr]) -> Optional[str]:
        return value.get_secret_value() if value else None

    @field_serializer("security_domains")
    def serialize_domains(self, value: Optional[List[LocalUserSecurityDomainModel]]) -> Optional[Dict]:
        # NOTE: exclude `None` values and empty list (-> should we exclude empty list?)
        if not value:
            return None

        domains_dict = {}
        for domain in value:
            domains_dict.update(domain.to_payload())

        return {"domains": domains_dict}

    # -- Deserialization (API response / Ansible payload -> Model instance) --

    @model_validator(mode="before")
    @classmethod
    def deserialize_password_policy(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        password_policy = data.get("passwordPolicy")

        if password_policy and isinstance(password_policy, dict):
            if "reuseLimitation" in password_policy:
                data["reuse_limitation"] = password_policy["reuseLimitation"]
            if "timeIntervalLimitation" in password_policy:
                data["time_interval_limitation"] = password_policy["timeIntervalLimitation"]

            # Remove the nested structure from data to avoid conflicts
            # (since it's a computed field, not a real field)
            data.pop("passwordPolicy", None)

        return data

    @field_validator("security_domains", mode="before")
    @classmethod
    def deserialize_domains(cls, value: Any) -> Optional[List[Dict]]:
        if value is None:
            return None

        # If already in list format (Ansible module representation), return as-is
        if isinstance(value, list):
            return value

        # If in the nested dict format (API representation)
        if isinstance(value, dict) and "domains" in value:
            domains_dict = value["domains"]
            domains_list = []

            for domain_name, domain_data in domains_dict.items():
                domains_list.append({"name": domain_name, "roles": [USER_ROLES_MAPPING.get_dict().get(role, role) for role in domain_data.get("roles", [])]})

            return domains_list

        return value

    # -- Extra --

    # TODO: to generate from Fields: use extra for generating argument_spec (low priority)
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
                            name=dict(type="str", required=True, aliases=["security_domain_name", "domain_name"]),
                            roles=dict(type="list", elements="str", choices=USER_ROLES_MAPPING.get_original_data()),
                        ),
                        aliases=["domains"],
                    ),
                    remote_id_claim=dict(type="str"),
                    remote_user_authorization=dict(type="bool"),
                ),
            ),
            state=dict(type="str", default="merged", choices=["merged", "replaced", "overridden", "deleted"]),
        )
