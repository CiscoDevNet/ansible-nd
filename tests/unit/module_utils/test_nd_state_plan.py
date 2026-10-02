# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the mutation-free ND state planning boundary."""

from __future__ import annotations

from dataclasses import replace

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_trunk_host_interface import (
    EthernetTrunkHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import LoopbackInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_plan import NDStatePlanner
from ansible_collections.cisco.nd.tests.unit.module_utils.state_reconciliation_helpers import PlanModel, collection


def _loopback(name: str, *, ip: str | None = None, description: str | None = None) -> dict:
    policy = {key: value for key, value in {"ip": ip, "description": description}.items() if value is not None}
    return {
        "switch_ip": "192.0.2.1",
        "interface_name": name,
        "config_data": {"network_os": {"policy": policy}},
    }


def _collection(config: list[dict], state: str = "merged") -> NDConfigCollection:
    return NDConfigCollection.from_ansible_config(data=config, model_class=LoopbackInterfaceModel, context={"state": state})


def test_merged_plan_preserves_unspecified_current_fields_without_mutating_before() -> None:
    """Merged planning emits the final merged item and leaves its inputs unchanged."""
    before = _collection([_loopback("loopback10", ip="192.0.2.10/32", description="old")])
    proposed = _collection([_loopback("LOOPBACK10", description="new")])
    original_before = before.to_ansible_config()

    plan = NDStatePlanner.plan(state="merged", before=before, proposed=proposed)

    assert len(plan.updates) == 1
    assert not plan.creates
    assert not plan.deletes
    policy = plan.after.to_ansible_config()[0]["config_data"]["network_os"]["policy"]
    assert policy["ip"] == "192.0.2.10"
    assert policy["description"] == "new"
    assert before.to_ansible_config() == original_before


@pytest.mark.parametrize("state,creates,deletes", [("replaced", 1, 0), ("overridden", 1, 1), ("deleted", 0, 1), ("merged", 1, 0)])
def test_synthetic_state_operations(state, creates, deletes):
    before = collection(PlanModel(name="old"))
    desired = collection(PlanModel(name="new")) if state != "deleted" else collection(PlanModel(name="old"))
    plan = NDStatePlanner.plan(state=state, before=before, proposed=desired)
    assert len(plan.creates) == creates
    assert len(plan.deletes) == deletes
    assert before.keys() == ["old"]
    assert plan.changed


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


def test_empty_deleted_and_identical_replacement_are_noops():
    before = collection(PlanModel(name="a"))
    assert not NDStatePlanner.plan(state="replaced", before=before, proposed=before).changed
    assert not NDStatePlanner.plan(state="deleted", before=before, proposed=collection()).changed


def test_public_dataclass_replacement_supports_before_and_operation_rewrites():
    plan = NDStatePlanner.plan(state="overridden", before=collection(PlanModel(name="old")), proposed=collection(PlanModel(name="new")))
    before = collection(PlanModel(name="inventory"))
    rewritten = replace(plan, before=before, creates=(), deletes=plan.deletes + plan.creates)
    assert rewritten.before is before
    assert rewritten.creates == ()
    assert [item.name for item in rewritten.deletes] == ["old", "new"]
    assert rewritten.after is plan.after
    assert [item.name for item in plan.creates] == ["new"]


@pytest.mark.parametrize("size", [1000, 2000])
def test_noop_planning_copies_inventory_once(monkeypatch, size):
    before = collection(*(PlanModel(name=str(index)) for index in range(size)))
    copied_sizes = []
    original_copy = NDConfigCollection.copy

    def counted_copy(items):
        copied_sizes.append(len(items))
        return original_copy(items)

    monkeypatch.setattr(NDConfigCollection, "copy", counted_copy)
    plan = NDStatePlanner.plan(state="replaced", before=before, proposed=before)
    assert not plan.changed
    assert copied_sizes == [size]


def test_override_deletes_omitted_inventory_in_one_batch(monkeypatch):
    deleted_batches = []
    original_delete = NDConfigCollection.delete_many

    def counted_delete(items, keys):
        deleted_batches.append(set(keys))
        return original_delete(items, keys)

    monkeypatch.setattr(NDConfigCollection, "delete_many", counted_delete)
    plan = NDStatePlanner.plan(state="overridden", before=collection(PlanModel(name="a"), PlanModel(name="b")), proposed=collection())
    assert deleted_batches == [{"a", "b"}]
    assert set(item.name for item in plan.deletes) == {"a", "b"}


def test_overridden_plan_calculates_update_create_delete_and_after_state() -> None:
    """Override planning is complete before execution and remains mutation-free."""
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
    assert set(plan.after.keys()) == {("192.0.2.1", "loopback10"), ("192.0.2.1", "loopback30")}
    assert plan.changed is True
    assert plan.mutation_count == 3
    assert set(before.keys()) == {
        ("192.0.2.1", "loopback10"),
        ("192.0.2.1", "loopback20"),
    }


def test_deleted_plan_only_selects_identifiers_that_exist() -> None:
    """Delete planning ignores absent identifiers and produces the final collection."""
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


def test_invalid_state_fails_without_changing_inputs() -> None:
    """Unsupported state values cannot reach execution."""
    before = _collection([])
    proposed = _collection([])

    with pytest.raises(ValueError, match="Invalid state"):
        NDStatePlanner.plan(state="gathered", before=before, proposed=proposed)

    assert len(before) == 0
    assert len(proposed) == 0


def test_merged_plan_applies_vlan_mapping_flag_and_entries_atomically() -> None:
    """Merged planning retains a complete Ethernet trunk VLAN-mapping pair."""
    identity = {"switch_ip": "192.0.2.1", "interface_name": "Ethernet1/44"}
    before = NDConfigCollection.from_ansible_config(
        data=[
            {
                **identity,
                "config_data": {"network_os": {"policy": {"vlan_mapping": False}}},
            }
        ],
        model_class=EthernetTrunkHostInterfaceModel,
        context={"state": "merged"},
    )
    proposed = NDConfigCollection.from_ansible_config(
        data=[
            {
                **identity,
                "config_data": {
                    "network_os": {
                        "policy": {
                            "vlan_mapping": True,
                            "vlan_mapping_entries": [
                                {
                                    "customer_inner_vlan_id": 3121,
                                    "customer_vlan_id": ["3122-3123"],
                                    "dot1q_tunnel": True,
                                    "provider_vlan_id": 3120,
                                }
                            ],
                        }
                    }
                },
            }
        ],
        model_class=EthernetTrunkHostInterfaceModel,
        context={"state": "merged"},
    )
    original_before = before.to_ansible_config()

    plan = NDStatePlanner.plan(state="merged", before=before, proposed=proposed)

    assert len(plan.updates) == 1
    policy = plan.after.to_ansible_config()[0]["config_data"]["network_os"]["policy"]
    assert policy["vlan_mapping"] is True
    assert policy["vlan_mapping_entries"] == [
        {
            "customer_inner_vlan_id": 3121,
            "customer_vlan_id": ["3122-3123"],
            "dot1q_tunnel": True,
            "provider_vlan_id": 3120,
        }
    ]
    assert before.to_ansible_config() == original_before
