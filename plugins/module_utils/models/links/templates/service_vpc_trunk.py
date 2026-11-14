# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import LinkTemplateBase


class ServiceVpcTrunkTemplateInputs(LinkTemplateBase):
    """Internal discriminator for ND 4.3's parameterless service vPC policy.

    The wire ``serviceVpcTrunk`` object has only ``policyType``. Its containing
    configData serializer must omit templateInputs; no service-trunk fields
    belong to this policy.
    """

    minimum_nd_version: ClassVar[tuple[int, int] | None] = (4, 3)
    policy_type_marker: Literal["serviceVpcTrunk"] = Field(default="serviceVpcTrunk", exclude=True)
