# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    InterfaceBasicsMixin,
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
)


class PreprovisionTemplateInputs(
    InterfaceBasicsMixin,
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=preprovision (config staged before devices land)."""

    policy_type_marker: Literal["preprovision"] = Field(default="preprovision", exclude=True)
