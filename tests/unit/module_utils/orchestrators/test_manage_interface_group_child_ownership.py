# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Prove generated vPC children without assigning raw peer slots to switches."""

from __future__ import annotations

import re
from collections import Counter
from copy import deepcopy
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_interface_group_deploy_confirmation import (
    DEPLOY,
    ENTRYPOINTS,
    PREVIEW,
    _build,
    _deploy_body,
    _preview_body,
    _response,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import (
    ResponseGenerator,
)

PAIR = {"SN1": "SN2", "SN2": "SN1", "SN3": "SN4", "SN4": "SN3"}
SUBMITTED = {("SN1", "vPC10")}
CHILDREN = {
    ("SN1", "port-channel10"),
    ("SN1", "Ethernet1/12"),
    ("SN2", "port-channel20"),
    ("SN2", "Ethernet1/47"),
}


def _record(serial, name, interface_type, mode, policy, *, operational_id=None):
    record = {
        "switchId": serial,
        "interfaceName": name,
        "interfaceType": interface_type,
        "configData": {
            "mode": mode,
            "networkOS": {"networkOSType": "nx-os", "policy": policy},
        },
    }
    if operational_id is not None:
        record["operData"] = {"portChannelId": operational_id}
    return record


def _policy(record):
    return record["configData"]["networkOS"]["policy"]


def _find(inventories, serial, name):
    return next(record for record in inventories[serial] if record["interfaceName"].lower() == name.lower())


def _pair_records(
    *,
    family="trunk",
    echo="switch_local",
    name="vpc10",
    switches=("SN1", "SN2"),
    ids=(10, 20),
    members=None,
):
    """Use different member names and PC IDs so guessing orientation cannot pass."""
    members = members if members is not None else (("Ethernet1/12",), ("Ethernet1/47",))
    result = {serial: [] for serial in switches}
    slots = [
        {"PortChannelId": ids[0], "MemberPorts": list(members[0])},
        {"PortChannelId": ids[1], "MemberPorts": list(members[1])},
    ]
    for index, serial in enumerate(switches):
        ordered = list(reversed(slots)) if echo == "reversed_pair_wide" or (echo == "switch_local" and index == 1) else slots
        parent_policy = {
            "policyType": family + "VpcHost",
            "peerSwitchId": switches[1 - index],
        }
        for number, slot in enumerate(ordered, 1):
            for key, value in slot.items():
                parent_policy[f"peer{number}{key}"] = deepcopy(value)
        result[serial].append(_record(serial, name, "vpc", family, parent_policy))
        pc_name = f"port-channel{ids[index]}"
        result[serial].append(
            _record(
                serial,
                pc_name,
                "portChannel",
                family,
                {
                    "policyType": family + "VpcMember",
                    "portChannelId": pc_name,
                    "primaryInterface": name,
                },
            )
        )
        for member in members[index]:
            member_type = "vpcMember" if family == "trunk" else "accessVpcPoMember"
            result[serial].append(
                _record(
                    serial,
                    member,
                    "ethernet",
                    family,
                    {
                        "policyType": member_type,
                        "portChannelId": pc_name,
                        "primaryInterface": name,
                    },
                    operational_id=ids[index],
                )
            )
    return result


def _merge_inventories(*inventories):
    result = {}
    for inventory in inventories:
        for serial, records in inventory.items():
            result.setdefault(serial, []).extend(deepcopy(records))
    return result


def _inventory_calls(sender):
    return [call for call in sender.calls if re.fullmatch(r".*/switches/[^/]+/interfaces", urlsplit(call["path"]).path)]


def _fixture(
    inventories,
    *,
    submitted=None,
    reported=None,
    page_size=None,
    page_patch=None,
    final_pending=0,
):
    """Keep the real response pipeline; replace only the network boundary.

    Preview supplies no generated-child CLI, forcing the ownership fallback.
    Inventories are served only AFTER deployment, with real pagination metadata.
    """
    submitted = set(SUBMITTED if submitted is None else submitted)
    reported = set(CHILDREN if reported is None else reported)
    orchestrator, sender = _build([], targets=submitted)
    orchestrator._vpc_peer_cache = dict(PAIR)
    wire_responses = []
    sender.ownership_wire_responses = wire_responses
    deploy_count = 0

    def responses():
        nonlocal deploy_count
        while True:
            path = sender.path
            split = urlsplit(path)
            if split.path == DEPLOY:
                deploy_count += 1
                response = _response(path, _deploy_body(reported))
            elif split.path == PREVIEW:
                targets = set()
                for item in sender.payload["interfaces"]:
                    pair = (item["switchId"], item["interfaceName"])
                    targets.add(pair)
                    if pair[1].lower().startswith("vpc"):
                        targets.add((PAIR[pair[0]], pair[1]))
                # Parent discovery is clean too; child CLI evidence is absent.
                response = _response(
                    path,
                    _preview_body(targets, lines=final_pending if _inventory_calls(sender) else 0),
                )
            else:
                # Keep the same controller evidence available to the previous
                # exact-parent reader for an old-versus-new regression proof.
                # The current implementation must use complete inventories.
                parent_match = re.fullmatch(
                    r"/api/v1/manage/fabrics/fab1/switches/([^/]+)/interfaces/([^/]+)",
                    split.path,
                )
                if parent_match is not None:
                    serial, name = (unquote(value) for value in parent_match.groups())
                    assert name.lower().startswith("vpc")
                    response = _response(
                        path,
                        deepcopy(_find(inventories, serial, name)),
                        code=200,
                        verb="GET",
                    )
                    wire_responses.append(response)
                    yield response
                    continue
                match = re.fullmatch(
                    r"/api/v1/manage/fabrics/fab1/switches/([^/]+)/interfaces",
                    split.path,
                )
                if match is None:
                    pytest.fail(f"Unexpected REST request while proving children: {path}")
                assert deploy_count > 0, "Ownership discovery must not broaden the exact-success path"
                serial = unquote(match[1])
                assert serial in inventories, "Only requested vPC-pair switches may be discovered"
                query = parse_qs(split.query)
                offset = int(query.get("offset", [0])[0])
                requested_max = int(query.get("max", [500])[0])
                all_rows = sorted(
                    inventories[serial],
                    key=lambda record: record.get("interfaceName", "").lower(),
                )
                count = min(page_size or requested_max, requested_max)
                rows = deepcopy(all_rows[offset : offset + count])
                body = {
                    "interfaces": rows,
                    "meta": {
                        "counts": {
                            "total": len(all_rows),
                            "remaining": max(0, len(all_rows) - offset - len(rows)),
                        }
                    },
                }
                if page_patch is not None:
                    page_patch(serial, offset, body)
                response = _response(path, body, code=200, verb="GET")
            wire_responses.append(response)
            yield response

    sender.gen = ResponseGenerator(responses())
    return orchestrator, sender


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("family", ["trunk", "access"])
@pytest.mark.parametrize("echo", ["pair_wide", "switch_local", "reversed_pair_wide"])
def test_exact_children_survive_both_peer_slot_orders_and_policy_families(entrypoint, family, echo):
    inventories = _pair_records(family=family, echo=echo)
    orchestrator, sender = _fixture(inventories)

    getattr(orchestrator, entrypoint)()

    assert not orchestrator._pending_interfaces
    assert len(_inventory_calls(sender)) == 2
    assert Counter(call["path"] for call in sender.calls)[DEPLOY] == 1
    assert all(call["verb"] in {"GET", "POST"} for call in sender.calls)
    assert all(call["path"] == DEPLOY or call["path"] == PREVIEW or call in _inventory_calls(sender) for call in sender.calls)


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_correct_child_deployment_survives_reversed_raw_parent_slots(entrypoint):
    """Behavioral regression gate that does not require a particular read strategy."""
    orchestrator, sender = _fixture(_pair_records(echo="reversed_pair_wide"))

    getattr(orchestrator, entrypoint)()

    assert not orchestrator._pending_interfaces
    deployments = [call for call in sender.calls if call["path"] == DEPLOY]
    assert len(deployments) == 1
    assert deployments[0]["payload"] == {"interfaces": [{"switchId": "SN1", "interfaceName": "vPC10"}]}


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize(
    "members",
    [((), ()), (("Ethernet1/12",), ())],
    ids=["both-peers-empty", "one-peer-empty"],
)
def test_exact_generated_port_channels_keep_valid_empty_peer_support(entrypoint, members):
    inventories = _pair_records(members=members)
    children = {("SN1", "port-channel10"), ("SN2", "port-channel20")}
    orchestrator, sender = _fixture(inventories, reported=children)

    getattr(orchestrator, entrypoint)()

    assert not orchestrator._pending_interfaces
    assert len(_inventory_calls(sender)) == 2
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_missing_ethernet_parent_pointer_uses_verified_local_port_channel_chain_on_copied_data(
    entrypoint,
):
    inventories = _pair_records()
    _policy(_find(inventories, "SN1", "Ethernet1/12")).pop("primaryInterface")
    original = deepcopy(inventories)
    orchestrator, sender = _fixture(inventories)

    getattr(orchestrator, entrypoint)()

    assert not orchestrator._pending_interfaces
    assert inventories == original
    # Retained wire evidence must not acquire a manufactured controller field.
    for response in sender.ownership_wire_responses:
        for row in response.get("DATA", {}).get("interfaces", []):
            if row.get("switchId") == "SN1" and row.get("interfaceName") == "Ethernet1/12":
                assert "primaryInterface" not in _policy(row)


@pytest.mark.parametrize("pointer", ["vpc999", "", " ", False, 0, {}])
def test_explicit_wrong_or_malformed_ethernet_parent_pointer_is_not_repaired(pointer):
    inventories = _pair_records()
    _policy(_find(inventories, "SN1", "Ethernet1/12"))["primaryInterface"] = pointer
    orchestrator, sender = _fixture(inventories)

    with pytest.raises((RuntimeError, ValueError)):
        orchestrator.deploy_pending()

    assert orchestrator._pending_interfaces == SUBMITTED
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


@pytest.mark.parametrize("pointer", [None, "vpc999", "", " ", False, {}])
def test_generated_port_channel_requires_exact_explicit_logical_parent(pointer):
    inventories = _pair_records()
    _policy(_find(inventories, "SN1", "port-channel10"))["primaryInterface"] = pointer
    orchestrator, sender = _fixture(inventories, reported={("SN1", "port-channel10")})

    with pytest.raises((RuntimeError, ValueError)):
        orchestrator.deploy_pending()

    assert orchestrator._pending_interfaces == SUBMITTED
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("portChannelId", "port-channel99"),
        ("portChannelId", True),
        ("portChannelId", -1),
        ("policyType", "accessVpcMember"),
    ],
)
def test_generated_port_channel_self_identity_and_parent_family_must_agree(field, value):
    inventories = _pair_records()
    _policy(_find(inventories, "SN1", "port-channel10"))[field] = value
    orchestrator, sender = _fixture(inventories, reported={("SN1", "port-channel10")})

    with pytest.raises((RuntimeError, ValueError)):
        orchestrator.deploy_pending()

    assert orchestrator._pending_interfaces == SUBMITTED
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


@pytest.mark.parametrize(
    "policy_type",
    ["poMember", "vpcPeerLinkMember", "accessVpcPoMember", "unknownVpcMember"],
)
def test_same_pair_does_not_authorize_standalone_protected_or_wrong_family_ethernet(
    policy_type,
):
    inventories = _pair_records()
    _policy(_find(inventories, "SN1", "Ethernet1/12"))["policyType"] = policy_type
    orchestrator, sender = _fixture(inventories, reported={("SN1", "Ethernet1/12")})

    with pytest.raises((RuntimeError, ValueError)):
        orchestrator.deploy_pending()

    assert orchestrator._pending_interfaces == SUBMITTED
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


@pytest.mark.parametrize(
    "configured,operational",
    [("port-channel99", 10), ("port-channel10", 99), (True, 10), (-1, 10)],
)
def test_ethernet_configured_operational_and_local_parent_ids_cannot_conflict(configured, operational):
    inventories = _pair_records()
    record = _find(inventories, "SN1", "Ethernet1/12")
    _policy(record)["portChannelId"] = configured
    record["operData"]["portChannelId"] = operational
    orchestrator, sender = _fixture(inventories, reported={("SN1", "Ethernet1/12")})

    with pytest.raises((RuntimeError, ValueError)):
        orchestrator.deploy_pending()

    assert orchestrator._pending_interfaces == SUBMITTED
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


@pytest.mark.parametrize("reported", [{("SN1", "Ethernet1/14")}, {("SN1", "port-channel30")}])
def test_other_vpc_on_the_same_pair_cannot_authorize_unrelated_children(reported):
    inventories = _merge_inventories(
        _pair_records(),
        _pair_records(name="vpc11", ids=(30, 40), members=(("Ethernet1/14",), ("Ethernet1/48",))),
    )
    orchestrator, sender = _fixture(inventories, reported=reported)

    with pytest.raises((RuntimeError, ValueError)):
        orchestrator.deploy_pending()

    assert orchestrator._pending_interfaces == SUBMITTED
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_many_vpcs_on_the_same_pair_share_two_complete_inventory_reads(entrypoint):
    inventories = _merge_inventories(
        _pair_records(),
        _pair_records(name="vpc11", ids=(30, 40), members=(("Ethernet1/14",), ("Ethernet1/48",))),
    )
    submitted = SUBMITTED | {("SN2", "vPC11")}
    reported = CHILDREN | {("SN1", "Ethernet1/14"), ("SN2", "port-channel40")}
    orchestrator, sender = _fixture(inventories, submitted=submitted, reported=reported)

    getattr(orchestrator, entrypoint)()

    assert not orchestrator._pending_interfaces
    reads = _inventory_calls(sender)
    assert len(reads) == 2
    assert {unquote(urlsplit(call["path"]).path.split("/")[-2]) for call in reads} == {
        "SN1",
        "SN2",
    }
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


def test_same_vpc_number_on_two_pairs_keeps_independent_ownership_scope():
    inventories = _merge_inventories(_pair_records(), _pair_records(switches=("SN3", "SN4"), ids=(30, 40)))
    submitted = SUBMITTED | {("SN3", "vPC10")}
    reported = CHILDREN | {("SN3", "Ethernet1/12"), ("SN4", "port-channel40")}
    orchestrator, sender = _fixture(inventories, submitted=submitted, reported=reported)

    orchestrator.deploy_pending()

    assert not orchestrator._pending_interfaces
    assert len(_inventory_calls(sender)) == 4


@pytest.mark.parametrize("patch", ["wrong-switch", "empty-switch", "duplicate-name", "incomplete-metadata"])
def test_bad_complete_inventory_cannot_be_used_as_membership_proof(patch):
    inventories = _pair_records()

    def page_patch(serial, offset, body):
        if serial != "SN1" or offset:
            return
        if patch == "wrong-switch":
            body["interfaces"][0]["switchId"] = "SN3"
        elif patch == "empty-switch":
            body["interfaces"][0]["switchId"] = ""
        elif patch == "duplicate-name":
            body["interfaces"].append(deepcopy(body["interfaces"][0]))
            body["meta"]["counts"]["total"] += 1
        else:
            body["meta"]["counts"]["total"] += 1

    orchestrator, sender = _fixture(inventories, page_patch=page_patch)
    with pytest.raises((RuntimeError, ValueError)):
        orchestrator.deploy_pending()
    assert orchestrator._pending_interfaces == SUBMITTED
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


def test_rows_without_switch_id_keep_exact_inventory_url_scope():
    inventories = _pair_records()
    for records in inventories.values():
        for record in records:
            record.pop("switchId")
    orchestrator, sender = _fixture(inventories)

    orchestrator.deploy_pending()

    assert not orchestrator._pending_interfaces
    assert len(_inventory_calls(sender)) == 2
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


def test_complete_inventory_pagination_collects_members_outside_the_first_page():
    orchestrator, sender = _fixture(_pair_records(), page_size=1)

    orchestrator.deploy_pending()

    assert not orchestrator._pending_interfaces
    # Three records per switch: logical parent, generated Po, physical member.
    assert len(_inventory_calls(sender)) == 6
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


@pytest.mark.parametrize(
    "peer_change",
    [
        "wrong-peer",
        "missing-parent",
        "wrong-mode",
        "wrong-policy",
        "inconsistent-slots",
    ],
)
def test_reciprocal_parent_and_compatible_family_are_required(peer_change):
    inventories = _pair_records()
    parent = _find(inventories, "SN2", "vpc10")
    if peer_change == "wrong-peer":
        _policy(parent)["peerSwitchId"] = "SN3"
    elif peer_change == "missing-parent":
        inventories["SN2"].remove(parent)
    elif peer_change == "wrong-mode":
        parent["configData"]["mode"] = "access"
    elif peer_change == "wrong-policy":
        _policy(parent)["policyType"] = "accessVpcHost"
    else:
        _policy(parent)["peer1MemberPorts"] = ["Ethernet1/99"]
    orchestrator, sender = _fixture(inventories)

    with pytest.raises((RuntimeError, ValueError)):
        orchestrator.deploy_pending()

    assert orchestrator._pending_interfaces == SUBMITTED
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


def test_shared_index_is_not_bypassed_when_another_parent_claims_the_same_member():
    inventories = _pair_records()
    duplicate = deepcopy(_find(inventories, "SN1", "vpc10"))
    duplicate["interfaceName"] = "vpc99"
    inventories["SN1"].append(duplicate)
    orchestrator, sender = _fixture(inventories, reported={("SN1", "Ethernet1/12")})

    with pytest.raises((RuntimeError, ValueError)):
        orchestrator.deploy_pending()

    assert orchestrator._pending_interfaces == SUBMITTED
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


@pytest.mark.parametrize(
    "contradiction",
    [
        "wrong-parent",
        "wrong-local-id",
        "conflicting-operational-id",
        "missing-physical-row",
        "extra-physical-member",
        "wrong-policy-family",
    ],
)
def test_port_channel_only_reply_still_validates_complete_physical_membership(
    contradiction,
):
    inventories = _pair_records()
    member = _find(inventories, "SN1", "Ethernet1/12")
    if contradiction == "wrong-parent":
        _policy(member)["primaryInterface"] = "vpc99"
    elif contradiction == "wrong-local-id":
        _policy(member)["portChannelId"] = "port-channel99"
    elif contradiction == "conflicting-operational-id":
        member["operData"]["portChannelId"] = 99
    elif contradiction == "missing-physical-row":
        inventories["SN1"].remove(member)
    elif contradiction == "extra-physical-member":
        extra = deepcopy(member)
        extra["interfaceName"] = "Ethernet1/99"
        inventories["SN1"].append(extra)
    else:
        _policy(member)["policyType"] = "accessVpcPoMember"
    orchestrator, sender = _fixture(inventories, reported={("SN1", "port-channel10")})

    with pytest.raises((RuntimeError, ValueError)):
        orchestrator.deploy_pending()

    assert orchestrator._pending_interfaces == SUBMITTED
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


def test_pending_child_preview_cannot_be_cleared_by_membership_proof():
    orchestrator, sender = _fixture(_pair_records(), final_pending=1)

    with pytest.raises(RuntimeError, match="pending"):
        orchestrator.deploy_pending()

    assert orchestrator._pending_interfaces == SUBMITTED
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1
    assert len(_inventory_calls(sender)) == 2
    # The normal failure finalizer must not issue another deployment.
    assert orchestrator.deploy_accepted_mutations() == {
        "interfaces": [],
        "switches": [],
    }
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


def test_a_second_fallback_attempt_requires_a_fresh_post_deployment_inventory_snapshot():
    inventories = _pair_records()
    orchestrator, sender = _fixture(inventories, reported={("SN1", "Ethernet1/12")})
    orchestrator.deploy_pending()
    assert not orchestrator._pending_interfaces
    _policy(_find(inventories, "SN1", "Ethernet1/12"))["primaryInterface"] = "vpc99"
    orchestrator._pending_interfaces = set(SUBMITTED)

    with pytest.raises((RuntimeError, ValueError)):
        orchestrator.deploy_pending()

    assert orchestrator._pending_interfaces == SUBMITTED
    assert len(_inventory_calls(sender)) == 4
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 2


def test_exact_parent_success_does_not_fetch_any_interface_inventory():
    orchestrator, sender = _build([_response(DEPLOY, _deploy_body(SUBMITTED))], targets=SUBMITTED)

    orchestrator.deploy_pending()

    assert not orchestrator._pending_interfaces
    assert [call["path"] for call in sender.calls] == [DEPLOY]


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_unrelated_vpc_missing_optional_member_pointer_does_not_create_false_cross_switch_owner(entrypoint):
    """Orient foreign parent claims without authorizing that foreign parent's children."""
    unrelated = _pair_records(
        name="vpc11",
        ids=(30, 40),
        members=(("Ethernet1/14",), ("Ethernet1/12",)),
    )
    for rows in unrelated.values():
        for row in rows:
            if row.get("interfaceType") == "ethernet":
                _policy(row).pop("primaryInterface")
    inventories = _merge_inventories(_pair_records(), unrelated)
    original = deepcopy(inventories)
    orchestrator, sender = _fixture(inventories, reported={("SN1", "Ethernet1/12")})

    getattr(orchestrator, entrypoint)()

    assert not orchestrator._pending_interfaces
    assert len(_inventory_calls(sender)) == 2
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1
    assert inventories == original
    for response in sender.ownership_wire_responses:
        for row in response.get("DATA", {}).get("interfaces", []):
            if (row.get("switchId"), row.get("interfaceName")) in {
                ("SN1", "Ethernet1/14"),
                ("SN2", "Ethernet1/12"),
            }:
                assert "primaryInterface" not in _policy(row)


@pytest.mark.parametrize("corruption", ["wrong-parent", "missing-pointer", "wrong-local-id", "wrong-policy"])
def test_unrelated_missing_member_pointer_cannot_be_oriented_from_a_corrupt_local_port_channel(corruption):
    """A failed foreign-parent proof must not silently erase its conflicting claim."""
    unrelated = _pair_records(
        name="vpc11",
        ids=(30, 40),
        members=(("Ethernet1/14",), ("Ethernet1/12",)),
    )
    for rows in unrelated.values():
        for row in rows:
            if row.get("interfaceType") == "ethernet":
                _policy(row).pop("primaryInterface")
    local_po_policy = _policy(_find(unrelated, "SN1", "port-channel30"))
    if corruption == "wrong-parent":
        local_po_policy["primaryInterface"] = "vpc99"
    elif corruption == "missing-pointer":
        local_po_policy.pop("primaryInterface")
    elif corruption == "wrong-local-id":
        local_po_policy["portChannelId"] = "port-channel99"
    else:
        local_po_policy["policyType"] = "accessVpcMember"
    inventories = _merge_inventories(_pair_records(), unrelated)
    orchestrator, sender = _fixture(inventories, reported={("SN1", "Ethernet1/12")})

    with pytest.raises((RuntimeError, ValueError), match="ownership|parent"):
        orchestrator.deploy_pending()

    assert orchestrator._pending_interfaces == SUBMITTED
    assert len(_inventory_calls(sender)) == 2
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1
