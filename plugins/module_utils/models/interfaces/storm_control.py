# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Shared storm-control mutual-exclusion validator for interface policy models.

Every physical/port-channel/vPC host interface policy exposes, per traffic class (broadcast, multicast, unicast),
both a percentage level (`storm_control_*_level`) and a packets-per-second level (`storm_control_*_level_pps`).
These are mutually exclusive on NX-OS: `storm-control <class> level <pct>` and `storm-control <class> level pps <n>`
are the same single setting, so only one may apply per class.

ND does not enforce this at the API layer. Lab-verified on ND 4.3.1.75 and 4.2.1.10 (issue #351): a create/update
that sets both for one class is accepted (HTTP 204/207) and ND echoes both values back on GET (so there is no
perpetual diff), but at config generation ND silently applies the percentage and drops the pps. The user's pps
intent is silently lost with no error and no diff to warn them.

Because the wire round-trips faithfully there is no wire deviation to work around (no `TODO(X.Y.Z)` marker); this is
a client-side fail-fast guard so the user learns at validation time rather than discovering the dropped pps on the
device. `StormControlMutexMixin` centralizes the check so all five interface policy models share one implementation.
"""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel

# (traffic class label, percentage attribute, pps attribute) for each storm-control class. The attribute names are
# identical across all five interface policy models, so the mixin reads them positionally via getattr.
_STORM_CONTROL_CLASSES: tuple[tuple[str, str, str], ...] = (
    ("broadcast", "storm_control_broadcast_level", "storm_control_broadcast_level_pps"),
    ("multicast", "storm_control_multicast_level", "storm_control_multicast_level_pps"),
    ("unicast", "storm_control_unicast_level", "storm_control_unicast_level_pps"),
)


class StormControlMutexMixin(NDNestedModel):  # pylint: disable=too-few-public-methods
    """
    # Summary

    Mixin for interface policy models that carry the paired `storm_control_<class>_level` (percentage) and
    `storm_control_<class>_level_pps` (packets-per-second) fields. Rejects a config that sets both for the same
    traffic class, since the two are mutually exclusive on NX-OS and ND silently keeps the percentage while dropping
    the pps at config generation (issue #351, lab-verified on ND 4.3.1.75 and 4.2.1.10).

    Add it to a policy model's bases (replacing the direct `NDNestedModel` base); the model keeps defining its own
    fields. The check reads the field values by attribute name, so a model missing one of the pairs is handled
    gracefully (a `None` from `getattr` simply cannot conflict).

    ## Raises

    ### ValueError

    - If both the percentage and pps level are set for the same storm-control class (raised by
      `_reject_storm_control_level_and_pps` during model validation; surfaces as a Pydantic `ValidationError` when constructing an inheriting model).
    """

    @model_validator(mode="after")
    def _reject_storm_control_level_and_pps(self) -> "StormControlMutexMixin":
        """
        # Summary

        Reject any storm-control traffic class that has both its percentage level and its pps level set, naming the
        offending class(es) in the error so the user knows exactly which one to drop.

        ## Raises

        ### ValueError

        - If both the percentage and pps level are set for the same storm-control class (broadcast, multicast, or unicast).
        """
        conflicts = [
            traffic_class
            for traffic_class, pct_attr, pps_attr in _STORM_CONTROL_CLASSES
            if getattr(self, pct_attr, None) is not None and getattr(self, pps_attr, None) is not None
        ]
        if conflicts:
            classes = ", ".join(conflicts)
            raise ValueError(
                f"storm-control percentage and pps levels are mutually exclusive per traffic class, but both are set "
                f"for: {classes}. NX-OS treats them as the same setting and ND silently applies the percentage and "
                f"drops the pps at config generation; set only one of the two per class."
            )
        return self
