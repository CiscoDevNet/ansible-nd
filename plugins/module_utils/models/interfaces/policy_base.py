# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Shared write-strict / read-tolerant base for interface policy branch models.

Promoted from `LoopbackPolicyStrictBase` (PR #403) so every discriminated-union interface module shares one
implementation; loopback adopts this base on its next touch (coordinate in the PR bodies).
"""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


class InterfacePolicyStrictBase(NDNestedModel):
    """
    # Summary

    Write-strict / read-tolerant base for managed interface policy branch models (NX-OS and IOS-XE). Sets `extra="forbid"` so fields belonging
    to a different `policy_type` are rejected, strips `None`-valued keys first so unset flat-argspec options are not rejected, and declares
    `admin_state` — common to every interface config template on both network OS types.

    ## Raises

    None
    """

    model_config = ConfigDict(extra="forbid")

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")

    @model_validator(mode="before")
    @classmethod
    def strip_none_valued_keys(cls, data, info):
        """
        # Summary

        Drop `None`-valued keys before validation so unset flat-argspec options do not trip `extra="forbid"`. On the read
        path (validation `context={"mode": "read"}`, set by `from_response`), also drop keys not declared on this model so
        ND-injected read-only keys (e.g. loopback `linkStateRoutingTag`, routedHost `ptp`) do not trip `extra="forbid"`
        while write-side input stays strict.

        ## Raises

        None
        """
        if not isinstance(data, dict):
            return data
        data = {key: value for key, value in data.items() if value is not None}
        if info.context and info.context.get("mode") == "read":
            allowed = set(cls.model_fields) | {field.alias for field in cls.model_fields.values() if field.alias}
            data = {key: value for key, value in data.items() if key in allowed}
        return data
