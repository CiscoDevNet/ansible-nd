# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from collections.abc import Sequence

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_bgp_validation import (
    ManageFabricBgpValidationMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_release_validation import (
    ND_4_3_1,
    parse_controller_product_version,
)


class ManageCampusFabricValidationMixin(ManageFabricBgpValidationMixin):
    """Apply release-aware validation for Campus-only settings."""

    def preflight(self, model_instances: Sequence[NDBaseModel]) -> None:
        """Reject explicitly supplied ND 4.3.1-only Campus settings earlier."""
        fast_convergence_fabrics = []
        for item in model_instances:
            management = getattr(item, "management", None)
            if management is not None and "bgp_fast_convergence" in management.model_fields_set:
                fast_convergence_fabrics.append(str(item.get_identifier_value()))

        if fast_convergence_fabrics:
            raw_version = self.rest_send.controller_product_version
            version = parse_controller_product_version(raw_version)
            if version is None or version < ND_4_3_1:
                reported = raw_version or "unknown"
                raise RuntimeError(
                    "management.bgp_fast_convergence requires ND 4.3.1 or later when supplied; "
                    f"controller product version is {reported!r} for fabric(s): {', '.join(fast_convergence_fabrics)}"
                )

        super().preflight(model_instances)
