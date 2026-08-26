# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the mutation-free ND state planning boundary."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import ClassVar, Literal

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import (
    LoopbackInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_plan import (
    NDStatePlanner,
)


def _loopback(
    name: str, *, ip: str | None = None, description: str | None = None
) -> dict:
    policy = {
        key: value
        for key, value in {"ip": ip, "description": description}.items()
        if value is not None
    }
    return {
        "switch_ip": "192.0.2.1",
        "interface_name": name,
        "config_data": {"network_os": {"policy": policy}},
    }


def _collection(config: list[dict], state: str = "merged") -> NDConfigCollection:
    return NDConfigCollection.from_ansible_config(
        data=config, model_class=LoopbackInterfaceModel, context={"state": state}
    )


def _description(collection: NDConfigCollection) -> str | None:
    return collection.to_ansible_config()[0]["config_data"]["network_os"]["policy"].get(
        "description"
    )


def _set_description(model: LoopbackInterfaceModel, value: str) -> None:
    model.config_data.network_os.policy.description = value


def test_merged_plan_preserves_fields_without_mutating_inputs() -> None:
    """Merged planning emits the final merged item and leaves both inputs unchanged."""
    before = _collection(
        [_loopback("loopback10", ip="192.0.2.10/32", description="old")]
    )
    proposed = _collection([_loopback("LOOPBACK10", description="new")])
    original_before = before.to_ansible_config()
    original_proposed = proposed.to_ansible_config()

    plan = NDStatePlanner.plan(state="merged", before=before, proposed=proposed)

    assert len(plan.updates) == 1
    assert not plan.creates
    assert not plan.deletes
    policy = plan.after.to_ansible_config()[0]["config_data"]["network_os"]["policy"]
    assert policy["ip"] == "192.0.2.10"
    assert policy["description"] == "new"
    assert before.to_ansible_config() == original_before
    assert proposed.to_ansible_config() == original_proposed


def test_overridden_plan_calculates_update_create_delete_and_after_state() -> None:
    """Override planning is complete, deterministic, and mutation-free."""
    before = _collection(
        [
            _loopback("loopback10", ip="192.0.2.10/32"),
            _loopback("loopback20", ip="192.0.2.20/32"),
        ],
        state="overridden",
    )
    proposed = _collection(
        [
            _loopback("loopback10", ip="192.0.2.110/32"),
            _loopback("loopback30", ip="192.0.2.30/32"),
        ],
        state="overridden",
    )

    plan = NDStatePlanner.plan(state="overridden", before=before, proposed=proposed)

    assert [item.interface_name for item in plan.updates] == ["loopback10"]
    assert [item.interface_name for item in plan.creates] == ["loopback30"]
    assert [item.interface_name for item in plan.deletes] == ["loopback20"]
    assert set(plan.after.keys()) == {
        ("192.0.2.1", "loopback10"),
        ("192.0.2.1", "loopback30"),
    }
    assert plan.changed is True
    assert plan.mutation_count == 3
    assert list(before.keys()) == [
        ("192.0.2.1", "loopback10"),
        ("192.0.2.1", "loopback20"),
    ]


def test_deleted_plan_only_selects_identifiers_that_exist() -> None:
    """Delete planning ignores absent identifiers and preserves the input collection."""
    before = _collection([_loopback("loopback10", ip="192.0.2.10/32")])
    proposed = _collection(
        [
            {"switch_ip": "192.0.2.1", "interface_name": "loopback10"},
            {"switch_ip": "192.0.2.1", "interface_name": "loopback99"},
        ],
        state="deleted",
    )

    plan = NDStatePlanner.plan(state="deleted", before=before, proposed=proposed)

    assert [item.interface_name for item in plan.deletes] == ["loopback10"]
    assert len(plan.after) == 0
    assert len(before) == 1


def test_plan_public_values_are_defensive_snapshots() -> None:
    """Mutating inputs or returned plan values cannot change the stored plan."""
    key = ("192.0.2.1", "loopback10")
    before = _collection([_loopback("loopback10", description="old")])
    proposed = _collection([_loopback("loopback10", description="new")])
    plan = NDStatePlanner.plan(state="merged", before=before, proposed=proposed)

    _set_description(before.get(key), "mutated-before")
    _set_description(proposed.get(key), "mutated-proposed")
    assert _description(plan.before) == "old"
    assert _description(plan.proposed) == "new"
    assert _description(plan.after) == "new"

    returned_after = plan.after
    returned_after.delete(key)
    assert len(plan.after) == 1

    returned_update = plan.updates[0]
    _set_description(returned_update, "mutated-operation")
    assert _description(plan.after) == "new"
    assert plan.updates[0].config_data.network_os.policy.description == "new"

    with pytest.raises(FrozenInstanceError):
        plan.state = "deleted"


class _ExplodingMergeModel(NDBaseModel):
    """Model whose merge mutates its receiver before raising."""

    identifiers: ClassVar[list[str] | None] = ["name"]
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "single"

    name: str
    value: str

    def merge(self, _other: "NDBaseModel") -> "NDBaseModel":
        self.value = "partial"
        raise RuntimeError("merge failed")


def test_ignored_planning_error_does_not_leak_partial_item_mutation() -> None:
    """A suppressed item error leaves the last valid planned state untouched."""
    before = NDConfigCollection(
        model_class=_ExplodingMergeModel,
        items=[_ExplodingMergeModel(name="one", value="before")],
    )
    proposed = NDConfigCollection(
        model_class=_ExplodingMergeModel,
        items=[_ExplodingMergeModel(name="one", value="after")],
    )

    plan = NDStatePlanner.plan(
        state="merged", before=before, proposed=proposed, ignore_errors=True
    )

    assert plan.after.get("one").value == "before"
    assert plan.changed is False
    assert plan.mutation_count == 0
    assert plan.errors == ("Failed to process one: merge failed",)


def test_invalid_state_fails_without_changing_inputs() -> None:
    """Unsupported state values cannot reach execution."""
    before = _collection([])
    proposed = _collection([])

    with pytest.raises(ValueError, match="Invalid state"):
        NDStatePlanner.plan(state="gathered", before=before, proposed=proposed)

    assert len(before) == 0
    assert len(proposed) == 0
