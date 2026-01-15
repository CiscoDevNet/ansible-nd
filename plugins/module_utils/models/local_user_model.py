# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

# TODO: Add Field validation methods
# TODO: Add a method to get identifier(s) -> define a generic NDNetworkResourceModel
# TODO: Maybe define our own baseModel
# TODO: Look at ansible aliases
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any, Optional

class SecurityDomainModel(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
    )

    name: str = Field(alias="name")
    roles: list[str] = Field(default_factory=lambda: ["observer"], alias="roles")


class LocalUserModel(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        use_enum_values=True,
        validate_assignment=True,
        populate_by_name=True,
    )

    email: str = Field(default="", alias="email")
    login_id: str = Field(alias="loginID")
    first_name: str = Field(default="", alias="firstName")
    last_name: str = Field(default="", alias="lastName")
    user_password: str = Field(alias="password")
    reuse_limitation: int = Field(default=0, alias="reuseLimitation")
    time_interval_limitation: int = Field(default=0, alias="timeIntervalLimitation")
    security_domains: List[SecurityDomainModel] = Field(default_factory=list, alias="domains")
    remote_id_claim: str = Field(default="", alias="remoteIDClaim")
    remote_user_authorization: bool = Field(default=False, alias="xLaunch")

    def to_api_payload(self, user_roles_mapping: Dict[str, str] = None) -> Dict[str, Any]:
        """Convert the model to the specific API payload format required."""
        if user_roles_mapping is None:
            user_roles_mapping = {}

        base_data = self.model_dump(by_alias=True, exclude={'domains', 'reuseLimitation', 'timeIntervalLimitation'})
        
        payload = {
            "email": base_data.get("email"),
            "firstName": base_data.get("firstName"),
            "lastName": base_data.get("lastName"),
            "loginID": base_data.get("loginID"),
            "password": base_data.get("password"),
            "remoteIDClaim": base_data.get("remoteIDClaim"),
            "xLaunch": base_data.get("xLaunch"),
        }

        if self.security_domains:
            payload["rbac"] = {
                "domains": {
                    domain.name: {
                        "roles": [
                            user_roles_mapping.get(role, role) for role in domain.roles
                        ]
                    }
                    for domain in self.security_domains
                }
            }

        if self.reuse_limitation or self.time_interval_limitation:
            payload["passwordPolicy"] = {
                "reuseLimitation": self.reuse_limitation,
                "timeIntervalLimitation": self.time_interval_limitation,
            }

        return payload

    @classmethod
    def from_api_payload(
        cls, 
        payload: Dict[str, Any], 
        reverse_user_roles_mapping: Optional[Dict[str, str]] = None
    ) -> 'LocalUserModel':
        
        if reverse_user_roles_mapping is None:
            reverse_user_roles_mapping = {}

        user_data = {
            "email": payload.get("email", ""),
            "loginID": payload.get("loginID", ""),
            "firstName": payload.get("firstName", ""),
            "lastName": payload.get("lastName", ""),
            "password": payload.get("password", ""),
            "remoteIDClaim": payload.get("remoteIDClaim", ""),
            "xLaunch": payload.get("xLaunch", False),
        }

        password_policy = payload.get("passwordPolicy", {})
        user_data["reuseLimitation"] = password_policy.get("reuseLimitation", 0)
        user_data["timeIntervalLimitation"] = password_policy.get("timeIntervalLimitation", 0)

        domains_data = []
        rbac = payload.get("rbac", {})
        if rbac and "domains" in rbac:
            for domain_name, domain_config in rbac["domains"].items():
                # Map API roles back to internal roles
                api_roles = domain_config.get("roles", [])
                internal_roles = [
                    reverse_user_roles_mapping.get(role, role) for role in api_roles
                ]
                
                domain_data = {
                    "name": domain_name,
                    "roles": internal_roles
                }
                domains_data.append(domain_data)

        user_data["domains"] = domains_data

        return cls(**user_data)

    # @classmethod
    # def from_api_payload_json(
    #     cls, 
    #     json_payload: str, 
    #     reverse_user_roles_mapping: Optional[Dict[str, str]] = None
    # ) -> 'LocalUserModel':

    #     payload = json.loads(json_payload)
    #     return cls.from_api_payload(payload, reverse_user_roles_mapping)
