# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
)


class PreprovisionTemplateInputs(
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=preprovision. Limited to the four interface description and config fields ND returns for this policy; including others (mtu, speed, fec, interface_admin_state) breaks idempotency because ND drops them on read."""

    policy_type_marker: Literal["preprovision"] = Field(default="preprovision", exclude=True)
