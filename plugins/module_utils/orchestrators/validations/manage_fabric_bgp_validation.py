# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    SITE_ID_MAX_ND_4_2,
)


def parse_controller_version(value: object) -> tuple[int, int, int] | None:
    """Return the ND major/minor/patch tuple from a build-version value."""
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:\.|$)", str(value or ""))
    if match is None:
        return None
    return tuple(int(part) for part in match.groups())


class ManageFabricBgpValidationMixin:
    """Apply create/exact-state BGP requirements and release-aware site limits."""

    rest_send: Any

    @staticmethod
    def _missing_bgp_asn(model_instances: Sequence[NDBaseModel]) -> list[str]:
        missing = []
        for item in model_instances:
            management = getattr(item, "management", None)
            if management is None or getattr(management, "bgp_asn", None) is None:
                missing.append(str(item.get_identifier_value()))
        return missing

    @staticmethod
    def _format_missing_bgp_asn(names: list[str], operation: str) -> str:
        return f"management.bgp_asn is required {operation} for fabric(s): {', '.join(names)}"

    def preflight_create(self, model_instances: Sequence[NDBaseModel]) -> None:
        """Require the ND-mandated ASN only for objects classified as creates."""
        missing = self._missing_bgp_asn(model_instances)
        if missing:
            raise RuntimeError(self._format_missing_bgp_asn(missing, "when creating"))
        super().preflight_create(model_instances)

    def preflight(self, model_instances: Sequence[NDBaseModel]) -> None:
        """Validate exact-state completeness and release-specific site-ID limits."""
        state = self.rest_send.params.get("state", "merged")
        if state in {"replaced", "overridden"}:
            missing = self._missing_bgp_asn(model_instances)
            if missing:
                raise RuntimeError(self._format_missing_bgp_asn(missing, f"when state is {state!r}"))

        extended_site_fabrics = []
        for item in model_instances:
            management = getattr(item, "management", None)
            site_id = getattr(management, "site_id", None) if management is not None else None
            if site_id and "." not in site_id and int(site_id) > SITE_ID_MAX_ND_4_2:
                extended_site_fabrics.append(str(item.get_identifier_value()))

        if extended_site_fabrics:
            raw_version = self.rest_send.controller_version
            version = parse_controller_version(raw_version)
            if version is None or version < (4, 3, 1):
                reported = raw_version or "unknown"
                raise RuntimeError(
                    f"site_id values above {SITE_ID_MAX_ND_4_2} require ND 4.3.1 or later; "
                    f"controller version is {reported!r} for fabric(s): {', '.join(extended_site_fabrics)}"
                )

        super().preflight(model_instances)
