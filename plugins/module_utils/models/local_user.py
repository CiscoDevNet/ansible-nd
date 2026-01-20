# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from pydantic import Field, field_validator
from types import MappingProxyType
from typing import List, Dict, Any, Optional, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

# TODO: Add Field validation methods
# TODO: define our own Field class for string versioning, ansible aliases
# TODO: Add a method to get identifier(s) -> define a generic NDNetworkResourceModel
# TODO: Surclass BaseModel -> Priority
# TODO: Look at ansible aliases

# TODO: use constants.py file in the future
user_roles_mapping = MappingProxyType({})


class LocalUserSecurityDomainModel(NDBaseModel):

    name: str = Field(alias="name")
    roles: list[str] = Field(default_factory=lambda: ["observer"], alias="roles")

    def to_payload(self) -> Dict[str, Any]:
        return  {
            self.name: {
                "roles": [
                    user_roles_mapping.get(role, role) for role in self.roles
                ]
            }
        }

    @classmethod
    def from_response(cls, name: str, domain_config: List[str]) -> 'NDBaseModel':
        internal_roles = [user_roles_mapping.get(role, role) for role in domain_config.get("roles", [])]
        
        domain_data = {
            "name": name,
            "roles": internal_roles
        }

        return cls(**domain_data)


class LocalUserModel(NDBaseModel):

    # TODO: Define a way to generate it (look at NDBaseModel comments)
    identifiers: ClassVar[List[str]] = ["login_id"]

    # TODO: Use Optinal to remove default values (get them from API response instead)
    email: str = Field(default="", alias="email")
    login_id: str = Field(alias="loginID")
    first_name: str = Field(default="", alias="firstName")
    last_name: str = Field(default="", alias="lastName")
    user_password: str = Field(alias="password")
    reuse_limitation: int = Field(default=0, alias="reuseLimitation")
    time_interval_limitation: int = Field(default=0, alias="timeIntervalLimitation")
    security_domains: List[LocalUserSecurityDomainModel] = Field(default_factory=list, alias="domains")
    remote_id_claim: str = Field(default="", alias="remoteIDClaim")
    remote_user_authorization: bool = Field(default=False, alias="xLaunch")

    def to_payload(self) -> Dict[str, Any]:
        """Convert the model to the specific API payload format required."""

        payload = self.model_dump(by_alias=True, exclude={'domains', 'reuseLimitation', 'timeIntervalLimitation'})

        if self.security_domains:
            payload["rbac"] = {"domains": {}}
            for domain in self.security_domains:
                payload["rbac"]["domains"].update(domain.to_api_payload())

        if self.reuse_limitation or self.time_interval_limitation:
            payload["passwordPolicy"] = {
                "reuseLimitation": self.reuse_limitation,
                "timeIntervalLimitation": self.time_interval_limitation,
            }

        return payload

    @classmethod
    def from_response(cls, payload: Dict[str, Any]) -> 'LocalUserModel':
        
        if reverse_user_roles_mapping is None:
            reverse_user_roles_mapping = {}

        user_data = {
            "email": payload.get("email"),
            "loginID": payload.get("loginID"),
            "firstName": payload.get("firstName"),
            "lastName": payload.get("lastName"),
            "password": payload.get("password"),
            "remoteIDClaim": payload.get("remoteIDClaim"),
            "xLaunch": payload.get("xLaunch"),
        }

        password_policy = payload.get("passwordPolicy", {})
        user_data["reuseLimitation"] = password_policy.get("reuseLimitation", 0)
        user_data["timeIntervalLimitation"] = password_policy.get("timeIntervalLimitation", 0)

        domains_data = []
        rbac = payload.get("rbac", {})
        if rbac and "domains" in rbac:
            for domain_name, domain_config in rbac["domains"].items():
                domains_data.append(LocalUserSecurityDomainModel.from_api_response(domain_name, domain_config))

        user_data["domains"] = domains_data

        return cls(**user_data)
