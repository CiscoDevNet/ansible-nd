# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the mutation-free ND state planning boundary."""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import LoopbackInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.models.links.links import NDLinkModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_plan import NDStatePlanner


def _loopback(name: str, *, ip: str | None = None, description: str | None = None) -> dict:
    policy = {"policy_type": "loopback", **{key: value for key, value in {"ip": ip, "description": description}.items() if value is not None}}
    return {
        "switch_ip": "192.0.2.1",
        "interface_name": name,
        "config_data": {"network_os": {"network_os_type": "nx-os", "policy": policy}},
    }


def _collection(config: list[dict], state: str = "merged") -> NDConfigCollection:
    return NDConfigCollection.from_ansible_config(data=config, model_class=LoopbackInterfaceModel, context={"state": state})


def _link_identity() -> dict:
    return {
        "src_cluster_name": "c1",
        "dst_cluster_name": "c1",
        "src_fabric_name": "f1",
        "dst_fabric_name": "f1",
        "src_switch_name": "leaf1",
        "dst_switch_name": "spine1",
        "src_interface_name": "Ethernet1/1",
        "dst_interface_name": "Ethernet1/1",
    }


def _unsupported_link_collection() -> NDConfigCollection:
    response = {
        "srcClusterName": "c1",
        "dstClusterName": "c1",
        "srcFabricName": "f1",
        "dstFabricName": "f1",
        "srcSwitchName": "leaf1",
        "dstSwitchName": "spine1",
        "srcInterfaceName": "Ethernet1/1",
        "dstInterfaceName": "Ethernet1/1",
        "linkId": "L-opaque",
        "configData": {"policyType": "ipfmNumbered", "templateInputs": {"srcIp": "192.0.2.1"}},
    }
    return NDConfigCollection.from_api_response(response_data=[response], model_class=NDLinkModel)


def _supported_link_collection(state: str) -> NDConfigCollection:
    config = {
        **_link_identity(),
        "config_data": {"policy_type": "numbered", "template_inputs": {"src_ip": "192.0.2.1", "dst_ip": "192.0.2.2"}},
    }
    return NDConfigCollection.from_ansible_config(data=[config], model_class=NDLinkModel, context={"state": state})


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


def test_explicit_unsupported_update_fails() -> None:
    """A proposed supported policy cannot replace an opaque controller object."""
    before = _unsupported_link_collection()
    proposed = _supported_link_collection("replaced")

    with pytest.raises(ValueError, match="cannot modify"):
        NDStatePlanner.plan(state="replaced", before=before, proposed=proposed)


def test_ignored_unsupported_update_is_reported_and_preserved() -> None:
    """ignore_errors records the update refusal without mutating the opaque object."""
    before = _unsupported_link_collection()
    proposed = _supported_link_collection("merged")

    plan = NDStatePlanner.plan(state="merged", before=before, proposed=proposed, ignore_errors=True)

    assert not plan.changed
    assert len(plan.errors) == 1
    assert "cannot modify" in plan.errors[0]
    assert list(plan.after)[0].is_unsupported_policy is True


def test_explicit_unsupported_delete_fails_even_with_ignore_errors() -> None:
    """Explicit deletion of an opaque object remains a hard safety failure."""
    before = _unsupported_link_collection()
    proposed = NDConfigCollection.from_ansible_config(
        data=[_link_identity()],
        model_class=NDLinkModel,
        context={"state": "deleted"},
    )

    with pytest.raises(ValueError, match="cannot delete"):
        NDStatePlanner.plan(state="deleted", before=before, proposed=proposed, ignore_errors=True)


def test_overridden_preserves_unsupported_objects() -> None:
    """Authoritative reconciliation excludes opaque objects from implicit deletes."""
    before = _unsupported_link_collection()
    proposed = NDConfigCollection(model_class=NDLinkModel)

    plan = NDStatePlanner.plan(state="overridden", before=before, proposed=proposed)

    assert not plan.deletes
    assert [item.link_id for item in plan.after] == ["L-opaque"]
