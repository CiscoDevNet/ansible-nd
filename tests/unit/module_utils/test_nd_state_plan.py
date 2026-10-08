# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Pure plans preserve current reconciliation guards and immutable snapshots."""

from typing import ClassVar

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_plan import NDStatePlanner


class PlanModel(NDBaseModel):
    identifiers: ClassVar[list[str]] = ["name"]
    identifier_strategy: ClassVar[str] = "single"
    replacement_preserve_fields: ClassVar[set[str]] = {"dynamic"}
    name: str
    value: str = "default"
    dynamic: str | None = None
    is_unsupported_policy: bool = False

    def describe_unsupported_policy(self):
        return "Unsupported object"


def collection(*items):
    return NDConfigCollection(PlanModel, list(items))


@pytest.mark.parametrize("state,creates,deletes", [("replaced", 1, 0), ("overridden", 1, 1), ("deleted", 0, 1), ("merged", 1, 0)])
def test_state_operations(state, creates, deletes):
    before = collection(PlanModel(name="old"))
    desired = collection(PlanModel(name="new")) if state != "deleted" else collection(PlanModel(name="old"))
    plan = NDStatePlanner.plan(state=state, before=before, proposed=desired)
    assert len(plan.creates) == creates
    assert len(plan.deletes) == deletes
    assert before.keys() == ["old"]
    assert plan.changed


def test_snapshot_and_operations_are_defensive():
    desired = collection(PlanModel(name="new"))
    plan = NDStatePlanner.plan(state="replaced", before=collection(), proposed=desired)
    desired.get("new").value = "caller"
    plan.creates[0].value = "executor"
    plan.after.get("new").value = "reader"
    assert plan.after.get("new").value == "default"
    assert plan.proposed.get("new").value == "default"


def test_replacement_preserves_dynamic_values():
    plan = NDStatePlanner.plan(
        state="replaced", before=collection(PlanModel(name="a", value="old", dynamic="assigned")), proposed=collection(PlanModel(name="a", value="new"))
    )
    assert plan.updates[0].dynamic == "assigned"


@pytest.mark.parametrize("state", ["replaced", "deleted"])
def test_unsupported_explicit_target_rejected(state):
    with pytest.raises(ValueError, match="Unsupported"):
        NDStatePlanner.plan(state=state, before=collection(PlanModel(name="a", is_unsupported_policy=True)), proposed=collection(PlanModel(name="a")))


def test_override_retains_unsupported_omitted_object():
    plan = NDStatePlanner.plan(state="overridden", before=collection(PlanModel(name="a", is_unsupported_policy=True)), proposed=collection())
    assert not plan.changed
    assert plan.after.keys() == ["a"]


def test_empty_and_noop_and_invalid_state():
    before = collection(PlanModel(name="a"))
    assert not NDStatePlanner.plan(state="replaced", before=before, proposed=before).changed
    assert not NDStatePlanner.plan(state="deleted", before=before, proposed=collection()).changed
    with pytest.raises(ValueError, match="Invalid state"):
        NDStatePlanner.plan(state="gathered", before=before, proposed=before)
