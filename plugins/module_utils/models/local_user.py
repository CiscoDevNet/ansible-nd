# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from pydantic import Field, field_validator, SecretStr
from types import MappingProxyType
from typing import List, Dict, Any, Optional, ClassVar
from typing_extensions import Self

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

# TODO: Add Field validation methods
# TODO: define our own Field class for string versioning, ansible aliases
# TODO: Add a method to get identifier(s) -> define a generic NDNetworkResourceModel
# TODO: Surclass BaseModel -> Priority
# TODO: Look at ansible aliases

# TODO: To be moved in constants.py file
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
    def from_response(cls, name: str, domain_config: List[str]) -> Self:
        return cls(
            name=name,
            roles=[user_roles_mapping.get(role, role) for role in domain_config.get("roles", [])]
        )


class LocalUserModel(NDBaseModel):

    # TODO: Define a way to generate it (look at NDBaseModel comments)
    identifiers: ClassVar[List[str]] = ["login_id"]

    email: Optional[str] = Field(alias="email")
    login_id: str = Field(alias="loginID")
    first_name: Optional[str] = Field(default="", alias="firstName")
    last_name: Optional[str] = Field(default="", alias="lastName")
    # TODO: Check secrets manipulation when tracking changes while maintaining security
    user_password: Optional[SecretStr] = Field(alias="password")
    reuse_limitation: Optional[int] = Field(default=0, alias="reuseLimitation")
    time_interval_limitation: Optional[int] = Field(default=0, alias="timeIntervalLimitation")
    security_domains: Optional[List[LocalUserSecurityDomainModel]] = Field(alias="domains")
    remote_id_claim: Optional[str] = Field(default="", alias="remoteIDClaim")
    remote_user_authorization: Optional[bool] = Field(default=False, alias="xLaunch")

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
    def from_response(cls, response: Dict[str, Any]) -> Self:
        
        return cls(
            email=response.get("email"),
            login_id=response.get("loginID"),
            first_name=response.get("firstName"),
            last_name=response.get("lastName"),
            user_password=response.get("password"),
            reuse_limitation=response.get("passwordPolicy", {}).get("reuseLimitation"),
            time_interval_limitation=response.get("passwordPolicy", {}).get("timeIntervalLimitation"),
            security_domains=[
                LocalUserSecurityDomainModel.from_response(name, domain_config)
                for name, domain_config in response.get("rbac", {}).get("domains", {}).items()
            ],
            remote_id_claim=response.get("remoteIDClaim"),
            remote_user_authorization=response.get("xLaunch"),
        )
