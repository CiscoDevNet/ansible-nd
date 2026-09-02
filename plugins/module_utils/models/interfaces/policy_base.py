# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Shared write-strict / read-tolerant base for interface policy branch models.

Promoted from `LoopbackPolicyStrictBase` (PR #403) so every discriminated-union interface module shares one
implementation; loopback adopts this base on its next touch (coordinate in the PR bodies).
"""

from __future__ import annotations

from typing import Any, ClassVar

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

    # TODO(4.2.1) get-echoes-schema-defaults-for-unset-fields
    # ND 4.2.1 echoes the template default for every field the user never set; the reverse pass of `get_diff` normalizes
    # existing-side matches to absent so replaced/overridden removal detection (issue #410) stays idempotent against
    # default echoes. `adminState: true` is the one default shared by every interface config template on both network
    # OS types, so it lives here. A ClassVar override REPLACES this table rather than merging with it, so per-policy
    # tables spread it back in (`**InterfacePolicyStrictBase.reverse_diff_defaults`).
    reverse_diff_defaults: ClassVar[dict[str, Any]] = {
        "adminState": True,
    }

    admin_state: bool | None = Field(default=None, alias="adminState", description="Enable or disable the interface")

    @model_validator(mode="before")
    @classmethod
    def strip_none_valued_keys(cls, data, info):
        """
        # Summary

        Drop `None`-valued UNDECLARED keys before validation so unset flat-argspec options (wrong-branch fields arriving as
        `None`) do not trip `extra="forbid"`. Declared keys are always kept, `None` or not: a declared `None` never trips
        `forbid`, and dropping declared keys corrupts assignment-revalidation - with `validate_assignment=True`, every
        `setattr` (e.g. inside `NDBaseModel.merge()`) re-runs this validator over the model's full `__dict__`, and any
        declared field dropped here vanishes from the rebuilt `__dict__`, making the next `getattr` raise
        `AttributeError` mid-merge (found by the first nd_interface_ethernet_routed live integration run, 2026-07-27).

        On the read path (validation `context={"mode": "response"}`, set by `NDBaseModel.from_response` on the interface
        model and on any policy model read directly), also drop keys not declared on this model regardless of value, so
        ND-injected read-only keys (e.g. loopback `linkStateRoutingTag`, routedHost `ptp`) do not trip `extra="forbid"`
        while write-side input stays strict.

        ## Raises

        None
        """
        if not isinstance(data, dict):
            return data
        allowed = set(cls.model_fields) | {field.alias for field in cls.model_fields.values() if field.alias}
        data = {key: value for key, value in data.items() if value is not None or key in allowed}
        if info.context and info.context.get("mode") == "response":
            data = {key: value for key, value in data.items() if key in allowed}
        return data
