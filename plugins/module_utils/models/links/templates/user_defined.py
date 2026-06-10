# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict, Field

from .base import LinkTemplateBase


class UserDefinedTemplateInputs(LinkTemplateBase):
    """Template inputs for policy_type=userDefined; shape is open (custom template_name)."""

    model_config = ConfigDict(
        extra="allow",
        populate_by_name=True,
        use_enum_values=True,
    )

    policy_type_marker: Literal["userDefined"] = Field(default="userDefined", exclude=True)

    allowed_vlans: Optional[str] = Field(default=None, alias="allowedVlans")
    mtu: Optional[int] = Field(default=None, alias="mtu")
