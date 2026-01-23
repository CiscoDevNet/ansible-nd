# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from pydantic import Field, SecretStr
from types import MappingProxyType
from typing import List, Dict, Any, Optional, ClassVar, Literal
from typing_extensions import Self

# TODO: To be replaced with: from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel, NDNestedModel
from models.base import NDBaseModel, NDNestedModel

# TODO: Move it to constants.py and import it
USER_ROLES_MAPPING = MappingProxyType({
    "fabric_admin": "fabric-admin",
    "observer": "observer",
    "super_admin": "super-admin",
    "support_engineer": "support-engineer",
    "approver": "approver",
    "designer": "designer",
})


class LocalUserSecurityDomainModel(NDNestedModel):
    """Security domain configuration for local user (nested model)."""

    # Fields
    name: str
    roles: Optional[List[str]] = None
    
    def to_payload(self) -> Dict[str, Any]:

        return {
            self.name: {
                "roles": [
                    USER_ROLES_MAPPING.get(role, role)
                    for role in (self.roles or [])
                ]
            }
        }
    
    @classmethod
    def from_response(cls, name: str, domain_config: Dict[str, Any]) -> Self:

        # NOTE: Maybe create a function from it to be moved to utils.py and to be imported
        reverse_mapping = {value: key for key, value in USER_ROLES_MAPPING.items()}
        
        return cls(
            name=name,
            roles=[
                reverse_mapping.get(role, role)
                for role in domain_config.get("roles", [])
            ]
        )


class LocalUserModel(NDBaseModel):
    """
    Local user configuration.

    Identifier: login_id (single field)
    """
    
    # Identifier configuration
    identifiers: ClassVar[List[str]] = ["login_id"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical"]] = "single"
    exclude_from_diff: ClassVar[List[str]] = ["user_password"]
    
    # Fields
    login_id: str = Field(..., alias="loginID")
    email: Optional[str] = None
    first_name: Optional[str] = Field(default=None, alias="firstName")
    last_name: Optional[str] = Field(default=None, alias="lastName")
    user_password: Optional[SecretStr] = Field(default=None, alias="password")
    reuse_limitation: Optional[int] = Field(default=None, alias="reuseLimitation")
    time_interval_limitation: Optional[int] = Field(default=None, alias="timeIntervalLimitation")
    security_domains: Optional[List[LocalUserSecurityDomainModel]] = Field(default=None, alias="domains")
    remote_id_claim: Optional[str] = Field(default=None, alias="remoteIDClaim")
    remote_user_authorization: Optional[bool] = Field(default=None, alias="xLaunch")
    
    def to_payload(self) -> Dict[str, Any]:
        payload = self.model_dump(
            by_alias=True,
            exclude={
                'domains',
                'security_domains',
                'reuseLimitation',
                'reuse_limitation',
                'timeIntervalLimitation',
                'time_interval_limitation'
            },
            exclude_none=True
        )

        if self.user_password:
            payload["password"] = self.user_password.get_secret_value()

        if self.security_domains:
            payload["rbac"] = {"domains": {}}
            for domain in self.security_domains:
                payload["rbac"]["domains"].update(domain.to_payload())

        if self.reuse_limitation is not None or self.time_interval_limitation is not None:
            payload["passwordPolicy"] = {}
            if self.reuse_limitation is not None:
                payload["passwordPolicy"]["reuseLimitation"] = self.reuse_limitation
            if self.time_interval_limitation is not None:
                payload["passwordPolicy"]["timeIntervalLimitation"] = self.time_interval_limitation
        
        return payload
    
    @classmethod
    def from_response(cls, response: Dict[str, Any]) -> Self:
        password_policy = response.get("passwordPolicy", {})
        rbac = response.get("rbac", {})
        domains = rbac.get("domains", {})
        
        security_domains = [
            LocalUserSecurityDomainModel.from_response(name, config)
            for name, config in domains.items()
        ] if domains else None
        
        return cls(
            login_id=response.get("loginID"),
            email=response.get("email"),
            first_name=response.get("firstName"),
            last_name=response.get("lastName"),
            user_password=response.get("password"),
            reuse_limitation=password_policy.get("reuseLimitation"),
            time_interval_limitation=password_policy.get("timeIntervalLimitation"),
            security_domains=security_domains,
            remote_id_claim=response.get("remoteIDClaim"),
            remote_user_authorization=response.get("xLaunch")
        )
