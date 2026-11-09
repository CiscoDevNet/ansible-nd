# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.release_metadata import (
    NDMinimumVersion,
)

ND_COLLECTION_MINIMUM_VERSION = (4, 2, 1, 0)
ND_4_3_1 = (4, 3, 1, 0)


def parse_controller_product_version(value: object) -> tuple[int, int, int, int] | None:
    """Parse an ND product version, ordering lettered bug-fix releases after the base release."""
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)([a-z]*)", str(value or "").strip().lower())
    if match is None:
        return None
    major, minor, patch, suffix = match.groups()
    suffix_order = 0
    for character in suffix:
        suffix_order = suffix_order * 26 + ord(character) - ord("a") + 1
    return int(major), int(minor), int(patch), suffix_order


class ManageFabricReleaseValidationMixin:
    """Apply ND release gates declared on supplied Pydantic model fields."""

    rest_send: Any
    release_gate_family: ClassVar[str] = "fabric"

    @staticmethod
    def _minimum_nd_version(management: NDBaseModel, field_name: str) -> tuple[tuple[int, int, int, int], str] | None:
        """Return a field's declared minimum ND version, if it is later than the collection floor."""
        field_info = type(management).model_fields.get(field_name)
        field_metadata = getattr(field_info, "metadata", ()) if field_info is not None else ()
        minimum_metadata = next(
            (item for item in field_metadata if isinstance(item, NDMinimumVersion)),
            None,
        )
        if minimum_metadata is None:
            return None

        minimum = parse_controller_product_version(minimum_metadata.value)
        if minimum is None:
            raise ValueError(f"Invalid ND minimum product version {minimum_metadata.value!r} on field {field_name!r}")
        if minimum <= ND_COLLECTION_MINIMUM_VERSION:
            return None
        return minimum, minimum_metadata.value

    def preflight(self, model_instances: Sequence[NDBaseModel]) -> None:
        """Reject explicitly supplied fields before their declared minimum release."""
        affected = []
        raw_version = None
        version = None
        version_resolved = False
        for item in model_instances:
            management = getattr(item, "management", None)
            if management is None:
                continue
            unsupported_fields = []
            for field in management.model_fields_set:
                minimum_info = self._minimum_nd_version(management, field)
                if minimum_info is None:
                    continue
                if not version_resolved:
                    raw_version = self.rest_send.controller_product_version
                    version = parse_controller_product_version(raw_version)
                    version_resolved = True
                minimum, minimum_text = minimum_info
                if version is None or version < minimum:
                    unsupported_fields.append(f"{field} (requires ND {minimum_text} or later)")
            if unsupported_fields:
                affected.append(f"{item.get_identifier_value()} ({', '.join(sorted(unsupported_fields))})")

        if affected:
            reported = raw_version or "unknown"
            raise RuntimeError(
                f"{self.release_gate_family} settings require their declared minimum ND product versions; "
                f"controller product version is {reported!r} for fabric(s): "
                f"{', '.join(affected)}"
            )

        super().preflight(model_instances)


class ManageFabricIbgpReleaseValidationMixin(ManageFabricReleaseValidationMixin):
    """Release-validation error context for iBGP and AI iBGP VXLAN."""

    release_gate_family = "iBGP VXLAN"


class ManageFabricEbgpReleaseValidationMixin(ManageFabricReleaseValidationMixin):
    """Release-validation error context for eBGP and AI eBGP VXLAN."""

    release_gate_family = "eBGP VXLAN"


class ManageFabricExternalReleaseValidationMixin(ManageFabricReleaseValidationMixin):
    """Release-validation error context for External Connectivity fabrics."""

    release_gate_family = "External Connectivity"
