# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Request-level and resource-level evidence must remain independent."""

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.nd_state_reconciliation import (
    MutationEffect,
    MutationJournal,
    MutationOperation,
    MutationOutcome,
    MutationResourceOutcome,
    MutationResult,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.test_nd_state_plan import PlanModel


def checkpoint():
    journal = MutationJournal()
    cp = journal.open(phase="create", effects=[MutationEffect(MutationOperation.CREATE, key, None, PlanModel(name=key)) for key in ("a", "b")])
    return journal, cp


@pytest.mark.parametrize(
    "states,changed,aggregate",
    [
        (("succeeded", "succeeded"), True, "succeeded"),
        (("failed", "failed"), False, "failed"),
        (("succeeded", "failed"), True, "failed"),
        (("succeeded", "unknown"), True, "unknown"),
    ],
)
def test_per_resource_resolution(states, changed, aggregate):
    journal, cp = checkpoint()
    cp.resolve_resources(MutationResult(tuple(MutationResourceOutcome(key, MutationOutcome(state)) for key, state in zip(("a", "b"), states))))
    assert cp.outcome.value == aggregate
    assert journal.changed is changed
    assert journal.may_have_changed is (aggregate == "unknown")
    assert tuple(e.identifier for e in cp.confirmed_effects) == tuple(k for k, s in zip(("a", "b"), states) if s == "succeeded")


def test_missing_and_unrecognized_preserve_success():
    journal, cp = checkpoint()
    cp.resolve_resources(MutationResult((MutationResourceOutcome("a", MutationOutcome.SUCCEEDED), MutationResourceOutcome("other", MutationOutcome.FAILED))))
    assert journal.changed and journal.has_unknown
    assert cp.unknown_identifiers == ("b",)
    assert "Unexpected" in cp.error


@pytest.mark.parametrize("other", [MutationOutcome.SUCCEEDED, MutationOutcome.FAILED])
def test_duplicate_normalized_evidence_is_not_success(other):
    journal, cp = checkpoint()
    cp.resolve_resources(
        MutationResult(
            (MutationResourceOutcome("a", MutationOutcome.SUCCEEDED), MutationResourceOutcome("a", other), MutationResourceOutcome("b", MutationOutcome.FAILED))
        )
    )
    assert cp.outcome == MutationOutcome.UNKNOWN
    assert journal.has_unknown
    assert not cp.confirmed_effects
    assert cp.unknown_identifiers == ("a",)


def test_response_order_has_no_meaning_and_resolution_is_once():
    journal, cp = checkpoint()
    cp.resolve_resources(
        MutationResult(
            (MutationResourceOutcome("b", MutationOutcome.FAILED, messages=("controller refused",)), MutationResourceOutcome("a", MutationOutcome.SUCCEEDED))
        )
    )
    assert cp.confirmed_effects[0].identifier == "a"
    assert journal.changed
    assert cp.resource_outcomes[1].messages == ("controller refused",)
    with pytest.raises(ValueError, match="already resolved"):
        cp.resolve(MutationOutcome.SUCCEEDED)


def test_effect_and_result_evidence_are_defensive():
    model = PlanModel(name="a")
    effect = MutationEffect(MutationOperation.CREATE, "a", None, model)
    model.value = "caller"
    effect.after.value = "reader"
    assert effect.after.value == "default"
    data = {"nested": ["original"]}
    outcome = MutationResourceOutcome("a", MutationOutcome.SUCCEEDED, evidence=(data,))
    data["nested"].append("caller")
    outcome.evidence[0]["nested"].append("reader")
    assert outcome.evidence == ({"nested": ["original"]},)


def test_duplicate_expected_identity_rejected_before_request():
    effect = MutationEffect(MutationOperation.CREATE, "a", None, PlanModel(name="a"))
    with pytest.raises(ValueError, match="Duplicate"):
        MutationJournal().open(phase="create", effects=(effect, effect))


def test_homogeneous_compatibility_and_protocol_uncertainty():
    journal, cp = checkpoint()
    cp.resolve(MutationOutcome.SUCCEEDED, changed=True)
    assert len(cp.confirmed_effects) == 2 and journal.changed
    journal, cp = checkpoint()
    cp.resolve_resources(
        MutationResult(
            (MutationResourceOutcome("a", MutationOutcome.SUCCEEDED), MutationResourceOutcome("b", MutationOutcome.FAILED)),
            protocol_errors=("Malformed neighbor",),
        )
    )
    assert journal.changed and journal.may_have_changed and journal.has_unknown
    assert cp.unknown_identifiers == ()
    assert "Malformed neighbor" in cp.error
