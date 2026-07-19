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
device. `StormControlMutexMixin` centralizes the check so all six interface policy models share one implementation.

The guard is scoped to user/proposed input only. Since ND legitimately echoes both values on GET, enforcing the
rule while parsing an ND response would make `query`/`gathered`/`diff` raise before the module could report or
remediate a device already in that state. The check therefore fires on `from_config()` (and any direct/non-response
construction) but is skipped when the validation context carries `mode="response"` (set by `from_response()`), so
the write path fails fast while the read path stays permissive.

Because the percentage and pps are two representations of one NX-OS threshold, the mixin also treats each pair as a
single logical setting during the merge lifecycle (PR #360 review): `merge` clears an existing counterpart when the
proposed config explicitly selects the other variant, and `merge_would_change` reports that pending clear to
`get_diff` so a dual-valued ND echo plus a matching single-variant intent is classified as a change, not `no_diff`.
"""

from __future__ import annotations

from contextvars import ContextVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationInfo, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel

# True while StormControlMutexMixin.merge() is mutating a model in place. Assignment validation re-runs the mutex on
# every setattr with no validation context, so without this suspension any merge into a model legitimately holding
# both values of a pair (a dual-valued ND echo, issue #351) would raise on the first assigned field — even an
# unrelated one. Suspension is safe because merge's counterpart clearing guarantees the merge itself can never
# introduce a new conflict: config input was already validated at construction, and response input is permissive by design.
_MUTEX_SUSPENDED: ContextVar[bool] = ContextVar("storm_control_mutex_suspended", default=False)

# (traffic class label, percentage attribute, pps attribute) for each storm-control class. The attribute names are
# identical across all six interface policy models, so the mixin reads them positionally via getattr.
_STORM_CONTROL_CLASSES: tuple[tuple[str, str, str], ...] = (
    ("broadcast", "storm_control_broadcast_level", "storm_control_broadcast_level_pps"),
    ("multicast", "storm_control_multicast_level", "storm_control_multicast_level_pps"),
    ("unicast", "storm_control_unicast_level", "storm_control_unicast_level_pps"),
)


class StormControlMutexMixin(NDNestedModel):
    """
    # Summary

    Mixin for interface policy models that carry the paired `storm_control_<class>_level` (percentage) and
    `storm_control_<class>_level_pps` (packets-per-second) fields. Rejects a config that sets both for the same
    traffic class, since the two are mutually exclusive on NX-OS and ND silently keeps the percentage while dropping
    the pps at config generation (issue #351, lab-verified on ND 4.3.1.75 and 4.2.1.10).

    Add it to a policy model's bases (replacing the direct `NDNestedModel` base); the model keeps defining its own
    fields. The check reads the field values by attribute name, so a model missing one of the pairs is handled
    gracefully (a `None` from `getattr` simply cannot conflict).

    The check is skipped when the validation context carries `mode="response"` (set by `NDBaseModel.from_response`),
    so parsing an ND echo that carries both values never raises; it fires on `from_config` and any other
    (non-response) construction so user/proposed input still fails fast. See the module docstring for the rationale.

    The mixin also overrides `merge` and `merge_would_change` so the percentage/pps pair behaves as one logical
    setting during the merged-state lifecycle: explicitly selecting one variant in proposed config clears an existing
    counterpart (and is reported as a diff), while a merge that expresses no storm-control intent leaves a dual-valued
    ND echo untouched.

    ## Raises

    ### ValueError

    - If both the percentage and pps level are set for the same storm-control class in a non-response context (raised
      by `_reject_storm_control_level_and_pps` during model validation; surfaces as a Pydantic `ValidationError` when constructing an inheriting model).
    """

    @model_validator(mode="after")
    def _reject_storm_control_level_and_pps(self, info: ValidationInfo) -> "StormControlMutexMixin":
        """
        # Summary

        Reject any storm-control traffic class that has both its percentage level and its pps level set, naming the
        offending class(es) in the error so the user knows exactly which one to drop.

        The check is skipped when the validation context carries `mode="response"` — ND legitimately echoes both
        values on GET (issue #351), so `from_response()` parsing must stay permissive or `query`/`gathered`/`diff`
        would raise before the module could report or remediate an existing device already in that state. Every other
        path (`from_config`, direct construction, any non-response context) enforces the rule so writes fail fast.

        ## Raises

        ### ValueError

        - If both the percentage and pps level are set for the same storm-control class (broadcast, multicast, or unicast) outside a response context.
        """
        if info.context and info.context.get("mode") == "response":
            return self
        if _MUTEX_SUSPENDED.get():
            return self
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

    def merge(self, other: "NDBaseModel") -> "NDBaseModel":
        """
        # Summary

        Merge `other` into `self`, treating each storm-control percentage/pps pair as one logical setting: when
        `other` explicitly selects one variant for a class, the counterpart on `self` is cleared first so switching
        units never passes through (or persists) a both-set state.

        Mutex enforcement is suspended for the duration of the in-place merge because assignment validation re-runs
        the mutex on every `setattr` with no validation context — a merge into a dual-valued ND echo (issue #351)
        would otherwise raise on the first assigned field, even an unrelated one. The suspension cannot mask a real
        conflict: `other` was validated at construction (so it never holds both variants of a pair), and the
        counterpart clearing above guarantees the merge result holds at most one variant per class unless the dual
        state was already present on `self` (a response echo, permissive by design).

        ## Raises

        None
        """
        token = _MUTEX_SUSPENDED.set(True)
        try:
            for counterpart_attr in self._counterparts_to_clear(other):
                setattr(self, counterpart_attr, None)
            return super().merge(other)
        finally:
            _MUTEX_SUSPENDED.reset(token)

    def merge_would_change(self, other: "NDBaseModel") -> bool:
        """
        # Summary

        Report the merge side effect of `merge`'s counterpart clearing to `get_diff`: when `other` explicitly selects
        one variant of a storm-control pair and `self` holds the counterpart, merging would clear that counterpart —
        a change the one-way dict-subset comparison cannot see (e.g. a dual-valued ND echo plus proposed config
        matching the existing pps value, issue #351 / PR #360 review).

        ## Raises

        None
        """
        if self._counterparts_to_clear(other):
            return True
        return super().merge_would_change(other)

    def _counterparts_to_clear(self, other: "NDBaseModel") -> list[str]:
        """
        # Summary

        Return the attribute names on `self` that `merge(other)` must clear: for each storm-control class where
        `other` explicitly selects one variant of the percentage/pps pair, the counterpart attribute on `self` if it
        is currently set. Shared by `merge` (which performs the clearing) and `merge_would_change` (which reports it
        to `get_diff`) so the two can never disagree.

        ## Raises

        None
        """
        to_clear: list[str] = []
        for _traffic_class, pct_attr, pps_attr in _STORM_CONTROL_CLASSES:
            if pct_attr in other.model_fields_set and getattr(other, pct_attr) is not None and getattr(self, pps_attr, None) is not None:
                to_clear.append(pps_attr)
            if pps_attr in other.model_fields_set and getattr(other, pps_attr) is not None and getattr(self, pct_attr, None) is not None:
                to_clear.append(pct_attr)
        return to_clear
