# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict, Field

from .base import LinkTemplateBase


class UserDefinedTemplateInputs(LinkTemplateBase):
    """Template inputs for policy_type=userDefined; shape is open (custom template_name)."""

    # Free-form template inputs are the user's configuration, not controller metadata: keep them in `get_diff` (issue #531).
    extras_are_user_intent: ClassVar[bool] = True

    model_config = ConfigDict(
        extra="allow",
        populate_by_name=True,
        use_enum_values=True,
    )

    policy_type_marker: Literal["userDefined"] = Field(default="userDefined", exclude=True)

    allowed_vlans: str | None = Field(default=None, alias="allowedVlans")
    mtu: int | None = Field(default=None, alias="mtu")
