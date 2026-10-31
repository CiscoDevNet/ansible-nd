# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Keep vPC preview requests separate from the two-peer evidence they require."""

from __future__ import annotations

from copy import deepcopy

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_interface_group import ManageInterfaceGroupOrchestrator
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_interface_group_deploy_confirmation import (
    DEPLOY,
    ENTRYPOINTS,
    PREVIEW,
    _build,
    _deploy_body,
    _payload,
    _preview_body,
    _response,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator

PEERS = {"SN1": "SN2", "SN2": "SN1", "SN3": "SN4", "SN4": "SN3"}
VPC_PAIR = {("SN1", "vPC10"), ("SN2", "vPC10")}


def _identities(body):
    return {(row["switchId"], row["interfaceName"].lower()) for row in body["configurationDiffs"]}


def _requested(call):
    return {(row["switchId"], row["interfaceName"].lower()) for row in call["payload"]["interfaces"]}


def _endpoint(targets, *, expands=True, deployment=None, configs=None):
    """Model ND expanding EACH submitted vPC, including duplicate requests.

    Keeping the expansion at the network boundary reproduces the live failure:
    sending both peers produces duplicate response rows instead of the fixture
    silently returning one row per expected identity.
    """
    orchestrator, sender = _build([], targets=targets)
    orchestrator._vpc_peer_cache = dict(PEERS)

    def responses():
        if deployment is not None:
            yield _response(DEPLOY, deployment)
        while True:
            assert sender.path == PREVIEW
            rows = []
            for item in sender.payload["interfaces"]:
                name = item["interfaceName"]
                serial = item["switchId"]
                owners = (serial, PEERS[serial]) if expands and name.lower().startswith("vpc") else (serial,)
                for owner in owners:
                    row = _preview_body({(owner, name)})["configurationDiffs"][0]
                    row["combinedConfigs"][0]["config"] = (configs or {}).get((owner, name.lower()), "")
                    rows.append(row)
            yield _response(PREVIEW, {"configurationDiffs": rows})

    sender.gen = ResponseGenerator(responses())
    return orchestrator, sender


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("expands", [True, False], ids=["pair-expanding-controller", "switch-local-controller"])
def test_mixed_vpc_deploy_requests_one_parent_but_confirms_both_peers(entrypoint, expands):
    """The live vPC200 + ordinary port-channel failure must not manufacture duplicates."""
    submitted = {("SN1", "vPC10"), ("SN2", "Port-channel104")}
    orchestrator, sender = _endpoint(submitted, expands=expands, deployment={})

    getattr(orchestrator, entrypoint)()

    assert not orchestrator._pending_interfaces
    assert sender.calls[0]["path"] == DEPLOY
    assert sender.calls[0]["payload"] == _payload(submitted)
    previews = sender.calls[1:]
    assert all(call["path"] == PREVIEW for call in previews)
    assert len(previews) == (2 if expands else 4)
    for call in previews[:: 1 if expands else 2]:
        requested = _requested(call)
        assert ("SN2", "port-channel104") in requested
        assert len({pair for pair in requested if pair[1] == "vpc10"}) == 1
    if not expands:
        assert all(_requested(call) == {("SN2", "vpc10")} for call in previews[1::2])


@pytest.mark.parametrize("expands", [True, False])
def test_multiple_pairs_ids_and_peer_aliases_keep_distinct_logical_targets(expands):
    verification = VPC_PAIR | {
        ("SN1", "vPC20"),
        ("SN2", "vPC20"),
        ("SN3", "vPC10"),
        ("SN4", "vPC10"),
        ("SN1", "Ethernet1/30"),
        ("SN2", "Ethernet1/30"),
        ("SN4", "Port-channel104"),
    }
    orchestrator, sender = _endpoint(verification, expands=expands)

    response, pending, error = orchestrator._collect_interface_preview(verification)

    assert error is None
    assert not pending
    assert _identities(response) == {(serial, name.lower()) for serial, name in verification}
    assert len(response["configurationDiffs"]) == len(verification)
    assert len(sender.calls) == (1 if expands else 2)
    initial = _requested(sender.calls[0])
    assert {pair for pair in initial if not pair[1].startswith("vpc")} == {
        ("SN1", "ethernet1/30"),
        ("SN2", "ethernet1/30"),
        ("SN4", "port-channel104"),
    }
    assert len(initial & {("SN1", "vpc10"), ("SN2", "vpc10")}) == 1
    assert len(initial & {("SN1", "vpc20"), ("SN2", "vpc20")}) == 1
    assert len(initial & {("SN3", "vpc10"), ("SN4", "vpc10")}) == 1
    if not expands:
        missing = {(serial, name.lower()) for serial, name in verification} - initial
        assert _requested(sender.calls[1]) == missing


def test_asymmetric_proven_children_remain_exact_switch_scoped_preview_targets():
    children = {("SN1", "Port-channel10"), ("SN1", "Ethernet1/12"), ("SN2", "Port-channel20"), ("SN2", "Ethernet1/47")}
    verification = VPC_PAIR | children
    configs = {
        ("SN1", "vpc10"): "interface port-channel10\ninterface Ethernet1/12\n",
        ("SN2", "vpc10"): "interface port-channel20\ninterface Ethernet1/47\n",
    }
    orchestrator, sender = _endpoint(verification, configs=configs)

    response, pending, error = orchestrator._collect_interface_preview(verification)

    assert error is None
    assert not pending
    assert _identities(response) == {(serial, name.lower()) for serial, name in verification}
    assert len(sender.calls) == 1
    requested = _requested(sender.calls[0])
    assert {pair for pair in requested if not pair[1].startswith("vpc")} == {(serial, name.lower()) for serial, name in children}
    rows = {(row["switchId"], row["interfaceName"].lower()): row for row in response["configurationDiffs"]}
    assert "Ethernet1/12" in rows[("SN1", "vpc10")]["combinedConfigs"][0]["config"]
    assert "Ethernet1/47" in rows[("SN2", "vpc10")]["combinedConfigs"][0]["config"]


def test_ordinary_interfaces_are_not_collapsed_or_peer_resolved(monkeypatch):
    verification = {("SN1", "Ethernet1/30"), ("SN2", "Ethernet1/30"), ("SN2", "Port-channel104")}
    orchestrator, sender = _build([_response(PREVIEW, _preview_body(verification))], targets=verification)

    def unexpected_peer_lookup(self, switch_id):
        pytest.fail(f"Ordinary interface preview must not resolve peer for {switch_id}")

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_get_vpc_peer_id", unexpected_peer_lookup)
    response, pending, error = orchestrator._collect_interface_preview(verification)

    assert error is None
    assert not pending
    assert sender.calls[0]["payload"] == _payload(verification)
    assert len(sender.calls) == 1
    assert len(response["configurationDiffs"]) == 3


def test_known_reverse_peer_cache_can_supply_request_scope_without_an_extra_lookup(monkeypatch):
    orchestrator, sender = _build([_response(PREVIEW, _preview_body(VPC_PAIR))], targets=VPC_PAIR)
    orchestrator._vpc_peer_cache = {"SN2": "SN1"}

    def unexpected_peer_lookup(self, switch_id):
        pytest.fail(f"Existing unambiguous peer scope must not need another GET for {switch_id}")

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_get_vpc_peer_id", unexpected_peer_lookup)
    _response_body, pending, error = orchestrator._collect_interface_preview(VPC_PAIR)

    assert error is None
    assert not pending
    assert len(sender.calls) == 1
    assert len(_requested(sender.calls[0])) == 1


@pytest.mark.parametrize(
    "verification,cache",
    [
        (VPC_PAIR | {("SN3", "vPC10")}, {"SN1": "SN2", "SN3": "SN2"}),
        (VPC_PAIR | {("SN2", "vPC20"), ("SN3", "vPC20")}, {"SN1": "SN2", "SN3": "SN2"}),
        (VPC_PAIR | {("SN3", "vPC10")}, {"SN1": "SN2", "SN2": "SN3", "SN3": "SN2"}),
    ],
    ids=["two-incoming-peers", "two-incoming-peers-across-vpc-ids", "conflicting-reverse-peer"],
)
def test_conflicting_cached_peer_scope_fails_before_any_preview_request(verification, cache):
    orchestrator, sender = _build([_response(PREVIEW, _preview_body(verification))], targets=verification)
    orchestrator._vpc_peer_cache = cache

    _response_body, _pending, error = orchestrator._collect_interface_preview(verification)

    assert error is not None
    assert "conflicting" in error
    assert not sender.calls
    assert orchestrator._pending_interfaces == verification


def test_peer_lookup_cannot_overwrite_and_hide_prior_conflicting_evidence(monkeypatch):
    orchestrator, sender = _build([], targets=VPC_PAIR)
    orchestrator._vpc_peer_cache = {"SN2": "SN3"}
    lookups = []

    def lookup(self, switch_id):
        lookups.append(switch_id)
        self._vpc_peer_cache.update({"SN1": "SN2", "SN2": "SN1"})
        return "SN2"

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_get_vpc_peer_id", lookup)
    _response_body, _pending, error = orchestrator._collect_interface_preview(VPC_PAIR)

    assert error is not None
    assert "conflicting" in error
    assert lookups == ["SN1"]
    assert not sender.calls


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_deploy_verification_preserves_conflicting_peer_evidence_before_lookup(entrypoint, monkeypatch):
    submitted = {("SN1", "vPC10")}
    orchestrator, sender = _build([_response(DEPLOY, {})], targets=submitted)
    orchestrator._vpc_peer_cache = {"SN2": "SN3"}
    lookups = []

    def lookup(self, switch_id):
        lookups.append(switch_id)
        self._vpc_peer_cache.update({"SN1": "SN2", "SN2": "SN1"})
        return "SN2"

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_get_vpc_peer_id", lookup)
    with pytest.raises(RuntimeError, match="conflicting"):
        getattr(orchestrator, entrypoint)()

    assert lookups == ["SN1"]
    assert orchestrator._pending_interfaces == submitted
    assert [call["path"] for call in sender.calls] == [DEPLOY]


def _invalid_initial_bodies():
    verification = VPC_PAIR | {("SN1", "Ethernet1/20")}
    complete = _preview_body(verification)
    first = next(row for row in complete["configurationDiffs"] if row["interfaceName"] == "vPC10")
    bodies = [
        {"configurationDiffs": []},
        {"configurationDiffs": [None]},
        _preview_body(VPC_PAIR),  # Missing an ordinary target cannot trigger vPC fallback.
        _preview_body({("SN2", "vPC10"), ("SN1", "Ethernet1/20")}),  # The requested representative is missing.
        _preview_body(verification | {("SN3", "vPC10")}),
        {"configurationDiffs": complete["configurationDiffs"] + [deepcopy(first)]},
    ]
    conflicting = deepcopy(complete)
    duplicate = deepcopy(first)
    duplicate["combinedConfigs"][0]["lines"] = 1
    conflicting["configurationDiffs"].append(duplicate)
    bodies.append(conflicting)
    for patch in ({"status": "failed"}, {"status": "warning"}, {"switchId": ""}, {"combinedConfigs": []}):
        body = deepcopy(complete)
        next(row for row in body["configurationDiffs"] if row["interfaceName"] == "vPC10").update(patch)
        bodies.append(body)
    body = deepcopy(complete)
    next(row for row in body["configurationDiffs"] if row["interfaceName"] == "vPC10")["combinedConfigs"][0]["lines"] = True
    bodies.append(body)
    return bodies


@pytest.mark.parametrize("preview", _invalid_initial_bodies())
def test_invalid_initial_reply_never_retries_or_weakens_evidence(preview):
    verification = VPC_PAIR | {("SN1", "Ethernet1/20")}
    orchestrator, sender = _build([_response(PREVIEW, preview)], targets=verification)
    orchestrator._vpc_peer_cache = dict(PEERS)

    _response_body, _pending, error = orchestrator._collect_interface_preview(verification)

    assert error is not None
    assert orchestrator._pending_interfaces == verification
    assert [call["path"] for call in sender.calls] == [PREVIEW]


@pytest.mark.parametrize(
    "first_lines,second_targets,second_lines,expected_pending",
    [
        (0, {("SN2", "vPC10")}, 0, set()),
        (0, VPC_PAIR, 0, set()),
        (2, VPC_PAIR, 0, {("SN1", "vpc10")}),
        (0, VPC_PAIR, 3, {("SN1", "vpc10"), ("SN2", "vpc10")}),
        (2, {("SN2", "vPC10")}, 3, {("SN1", "vpc10"), ("SN2", "vpc10")}),
    ],
)
def test_missing_peer_fallback_merges_only_valid_evidence_and_keeps_any_pending(first_lines, second_targets, second_lines, expected_pending):
    orchestrator, sender = _build(
        [
            _response(PREVIEW, _preview_body({("SN1", "vPC10")}, lines=first_lines)),
            _response(PREVIEW, _preview_body(second_targets, lines=second_lines)),
        ],
        targets=VPC_PAIR,
    )
    orchestrator._vpc_peer_cache = dict(PEERS)

    response, pending, error = orchestrator._collect_interface_preview(VPC_PAIR)

    assert error is None
    assert pending == expected_pending
    assert _identities(response) == {("SN1", "vpc10"), ("SN2", "vpc10")}
    assert len(response["configurationDiffs"]) == 2
    assert [_requested(call) for call in sender.calls] == [{("SN1", "vpc10")}, {("SN2", "vpc10")}]


def test_overlapping_peer_read_keeps_child_configuration_from_both_valid_snapshots():
    first = _preview_body({("SN1", "vPC10")}, lines=2, config="interface Ethernet1/12\n")
    second = _preview_body(VPC_PAIR, config="interface Ethernet1/47\n")
    first["configurationDiffs"][0]["combinedConfigs"].append({"configType": "expected", "lines": 1, "config": "interface port-channel10\n"})
    row = next(item for item in second["configurationDiffs"] if item["switchId"] == "SN1")
    row["combinedConfigs"].append({"configType": "expected", "lines": 1, "config": "interface port-channel20\n"})
    orchestrator, _sender = _build([_response(PREVIEW, first), _response(PREVIEW, second)], targets=VPC_PAIR)
    orchestrator._vpc_peer_cache = dict(PEERS)

    response, pending, error = orchestrator._collect_interface_preview(VPC_PAIR)

    assert error is None
    assert pending == {("SN1", "vpc10")}
    row = next(item for item in response["configurationDiffs"] if item["switchId"] == "SN1")
    pending_sections = [item for item in row["combinedConfigs"] if item["configType"] == "pending"]
    assert len(pending_sections) == 1
    assert pending_sections[0]["lines"] == 2
    retained = "\n".join(item.get("config", "") for item in row["combinedConfigs"])
    assert all(name in retained for name in ("Ethernet1/12", "Ethernet1/47", "port-channel10", "port-channel20"))


def _invalid_fallback_bodies():
    peer = _preview_body({("SN2", "vPC10")})
    failed = deepcopy(peer)
    failed["configurationDiffs"][0]["status"] = "failed"
    duplicate = {"configurationDiffs": peer["configurationDiffs"] * 2}
    missing = _preview_body({("SN1", "vPC10")})
    unrelated = _preview_body({("SN2", "vPC10"), ("SN3", "vPC10")})
    ordinary_overlap = _preview_body({("SN2", "vPC10"), ("SN1", "Ethernet1/20")})
    return [{}, {"configurationDiffs": []}, {"configurationDiffs": [None]}, failed, duplicate, missing, unrelated, ordinary_overlap]


@pytest.mark.parametrize("preview", _invalid_fallback_bodies())
def test_invalid_missing_peer_reply_cannot_confirm_or_mutate_queue(preview):
    verification = VPC_PAIR | {("SN1", "Ethernet1/20")}
    orchestrator, sender = _build(
        [_response(PREVIEW, _preview_body({("SN1", "vPC10"), ("SN1", "Ethernet1/20")})), _response(PREVIEW, preview)],
        targets=verification,
    )
    orchestrator._vpc_peer_cache = dict(PEERS)

    _response_body, _pending, error = orchestrator._collect_interface_preview(verification)

    assert error is not None
    assert orchestrator._pending_interfaces == verification
    assert len(sender.calls) == 2
    assert _requested(sender.calls[1]) == {("SN2", "vpc10")}


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_pending_missing_peer_remains_queued_without_redeployment(entrypoint):
    """One verification round retains its bounded request for a missing peer."""
    submitted = {("SN1", "vPC10")}
    local = _preview_body(submitted)
    peer = _preview_body({("SN2", "vPC10")})
    pending_peer = _preview_body({("SN2", "vPC10")}, lines=1)
    later_response = _response(PREVIEW, local)
    replies = [
        _response(DEPLOY, {}),
        _response(PREVIEW, local),
        _response(PREVIEW, peer),
        _response(PREVIEW, local),
        _response(PREVIEW, pending_peer),
        later_response,
        _response(PREVIEW, peer),
    ]
    orchestrator, sender = _build(replies, targets=submitted)
    orchestrator._vpc_peer_cache = dict(PEERS)

    with pytest.raises(RuntimeError, match="pending configuration remains"):
        getattr(orchestrator, entrypoint)()

    assert orchestrator._pending_interfaces == submitted
    assert [call["path"] for call in sender.calls] == [DEPLOY, PREVIEW, PREVIEW, PREVIEW, PREVIEW]
    # Parent ownership is prepared once, followed by one verification round.
    # Each requests the missing peer once; neither retries a pending result.
    assert all(_requested(call) == {("SN1", "vpc10")} for call in sender.calls[1::2])
    assert all(_requested(call) == {("SN2", "vpc10")} for call in sender.calls[2::2])
    if entrypoint == "deploy_pending":
        assert orchestrator.deploy_accepted_mutations() == {"interfaces": [], "switches": []}
        assert len(sender.calls) == 5
    assert sender.gen.next == later_response


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_exact_mixed_deploy_result_still_needs_no_preview_or_peer_lookup(entrypoint, monkeypatch):
    submitted = {("SN2", "vPC10"), ("SN3", "vPC10"), ("SN1", "Ethernet1/20")}
    orchestrator, sender = _build([_response(DEPLOY, _deploy_body(submitted))], targets=submitted)

    def unexpected_peer_lookup(self, switch_id):
        pytest.fail(f"Exact deployment success must not resolve peer for {switch_id}")

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_get_vpc_peer_id", unexpected_peer_lookup)
    getattr(orchestrator, entrypoint)()

    assert not orchestrator._pending_interfaces
    assert [call["path"] for call in sender.calls] == [DEPLOY]
    assert sender.calls[0]["payload"] == _payload(submitted)
