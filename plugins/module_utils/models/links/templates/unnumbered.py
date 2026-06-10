# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import (
    DhcpRelayMixin,
    InterfaceBasicsMixin,
    InterfaceDescriptionsMixin,
    LinkTemplateBase,
    MacsecCoreMixin,
)


class UnnumberedTemplateInputs(
    InterfaceBasicsMixin,
    InterfaceDescriptionsMixin,
    DhcpRelayMixin,
    MacsecCoreMixin,
    LinkTemplateBase,
):
    """Template inputs for policy_type=unnumbered (borrows IP from another interface)."""

    policy_type_marker: Literal["unnumbered"] = Field(default="unnumbered", exclude=True)
