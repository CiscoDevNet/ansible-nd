# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import LinkTemplateBase, pd


class CsrEvpnMultisiteOverlayTemplateInputs(LinkTemplateBase):
    """CSR EVPN multisite overlay inputs.

    ND 4.2.1 leaves ``ebgpMultihop`` unconstrained and has no default. The
    documented ND 4.3.1 default and range are valid under both schemas and avoid
    synthesizing the invalid 4.3.1 value zero when the input is omitted.
    """

    policy_type_marker: Literal["csrEvpnMultisiteOverlay"] = Field(default="csrEvpnMultisiteOverlay", exclude=True)

    enable_ebgp_password: bool | None = Field(default=None, alias="enableEbgpPassword", json_schema_extra=pd(False))
    ebgp_neighbor_password: str | None = Field(default=None, alias="ebgpNeighborPassword", json_schema_extra={"secret": True})
    ebgp_multihop: int | None = Field(default=None, alias="ebgpMultihop", json_schema_extra=pd(5, minimum=2, maximum=255))
