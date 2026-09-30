# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Permissive fallback template model for policy types this module does not model.

ND 4.2 defines 22 link policy types; this module strictly models a subset for
create/update. The controller can still return a link using any of the others
(for example ``ipfmNumbered`` or ``routedFabric``), and a strict discriminated
union would raise ``ValidationError`` on the full-fabric read -- aborting every
state, even for unrelated supported links.

``UnsupportedTemplateInputs`` preserves such a link verbatim (``extra="allow"``,
no field validation) so it survives the read as an opaque record. It is selected
by ``LinkConfigDataModel`` only when strict parsing fails on a controller read;
user input stays strictly validated against the supported policy types.
"""

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict, Field

from .base import LinkTemplateBase

# Internal discriminator value for the fallback model (never a real ND policyType).
UNSUPPORTED_POLICY_MARKER = "__unsupported__"


class UnsupportedTemplateInputs(LinkTemplateBase):
    """Opaque, read-only preservation of an unsupported policy's templateInputs."""

    model_config = ConfigDict(
        extra="allow",
        populate_by_name=True,
        use_enum_values=True,
    )

    policy_type_marker: Literal["__unsupported__"] = Field(default=UNSUPPORTED_POLICY_MARKER, exclude=True)
