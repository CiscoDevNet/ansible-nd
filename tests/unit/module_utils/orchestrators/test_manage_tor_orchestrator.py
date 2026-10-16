# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``ManageTorOrchestrator``.

Covers the ToR-specific behaviour that overrides ``NDBaseOrchestrator``:

- ``query_all`` issues a single fabric-wide GET (``includeCandidates=false``,
  no leaf filter) that returns every existing association across all leaves,
  with vPC pairings already collapsed to one entry by the API, and injects
  ``fabricName`` into each association.
- ``config_actions`` support via ``ConfigActionsMixin``: the orchestrator adopts
  the shared ``FABRIC_CONFIG_ACTIONS`` policy and drives save + switch-scoped
  deploy through ``run_config_actions``.

The shared REST infrastructure (``_request``, verbosity tagging) is covered by
``test_base_orchestrator.py`` and is not re-exercised here. The generic config
action mechanics (policy validation, ``only_switch_ids`` scoping, check-mode
planning) are covered by ``test_config_actions.py``.
"""

# pylint: disable=protected-access,redefined-outer-name

from __future__ import annotations

from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.parser import parse_config_actions
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import FABRIC_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_tor import (
    ManageTorOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_tor.manage_tor import (
    ManageTorModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import (
    MockAnsibleModule,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import (
    ResponseGenerator,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import RecordingSender

# =============================================================================
# Test harness
# =============================================================================


def _build_rest_send(response_dicts: list[dict], params: dict[str, Any], controller_version: str = "4.3.1") -> RestSend:
    """Build a real ``RestSend`` wired to a file-based ``Sender`` yielding
    ``response_dicts`` in order, with ``params`` exposed via ``rest_send.params``.

    ``controller_version`` defaults to a 4.3+ build so the associate path does
    not pre-reserve resources; reservation tests pass a 4.2.x version explicitly.
    """

    def responses():
        yield from response_dicts

    sender = RecordingSender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(responses())

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    rest_send = RestSend(params)
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    rest_send.controller_version = controller_version
    return rest_send


def _resp(data: Any = None, *, return_code: int = 200, method: str = "GET") -> dict:
    return {
        "RETURN_CODE": return_code,
        "METHOD": method,
        "REQUEST_PATH": "/api/v1",
        "MESSAGE": "OK",
        "DATA": data if data is not None else {},
    }


def _make_results() -> Results:
    r = Results()
    r.state = "merged"
    r.check_mode = False
    return r


# =============================================================================
# query_all
# =============================================================================


def test_manage_tor_orchestrator_query_all_returns_fabric_wide():
    """query_all issues one fabric-wide GET and returns every association across
    all leaves; vPC pairings arrive already collapsed to a single entry with
    both member IDs inline, and fabricName is injected into each association."""
    responses = [
        _resp(
            {
                "associations": [
                    # single leaf <-> single tor
                    {"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1"},
                    # vPC leaf <-> vPC tor (single self-contained entry)
                    {
                        "accessOrTorSwitchId": "T3",
                        "accessOrTorPeerSwitchId": "T4",
                        "aggregationOrLeafSwitchId": "L3",
                        "aggregationOrLeafPeerSwitchId": "L4",
                    },
                ]
            }
        ),
        # Resource enrichment, one call per distinct aggregation scope.
        _resp({"associations": [{"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1", "resources": {}}]}),
        _resp({"associations": []}),
    ]
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send(responses, params)

    with does_not_raise():
        orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())
        result = orchestrator.query_all()

    assert len(result) == 2
    for assoc in result:
        assert assoc["fabricName"] == "fab1"
    vpc = [a for a in result if a["accessOrTorSwitchId"] == "T3"][0]
    assert vpc["accessOrTorPeerSwitchId"] == "T4"
    assert vpc["aggregationOrLeafPeerSwitchId"] == "L4"


# =============================================================================
# query_all resource enrichment
# =============================================================================


def _record_requests(orchestrator, responses):
    """Replace _request with a recorder yielding ``responses`` in order.

    Returns the list that accumulates each request's path.
    """
    paths = []
    queue = list(responses)

    def fake_request(path, verb, **kwargs):
        paths.append(path)
        return queue.pop(0) if queue else {}

    orchestrator._request = fake_request
    return paths


def test_manage_tor_orchestrator_query_all_merges_resources():
    """Resources are merged onto the matching association.

    ND omits resources from the fabric-wide list, so they are backfilled from an
    includeCandidates=true query scoped to the association's aggregation side.
    """
    params = {"check_mode": False, "fabric_name": "fab1", "config": [], "state": "merged"}
    orchestrator = ManageTorOrchestrator(rest_send=_build_rest_send([], params), results=_make_results())
    paths = _record_requests(
        orchestrator,
        [
            {"associations": [{"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1"}]},
            {
                "associations": [
                    {
                        "accessOrTorSwitchId": "T1",
                        "aggregationOrLeafSwitchId": "L1",
                        "resources": {"accessOrTorPortChannelId": 511, "aggregationOrLeafPortChannelId": 512},
                    }
                ]
            },
        ],
    )

    result = orchestrator.query_all()

    assert result[0]["resources"] == {"accessOrTorPortChannelId": 511, "aggregationOrLeafPortChannelId": 512}
    assert "includeCandidates=false" in paths[0]
    assert "aggregationOrLeafSwitchId=L1" in paths[1]
    assert "includeCandidates=true" in paths[1]


def test_manage_tor_orchestrator_query_all_scopes_vpc_pair_with_peer():
    """A vPC leaf pair is queried with both leaf IDs.

    ND returns an empty resources object when only one half of the pair is sent.
    """
    params = {"check_mode": False, "fabric_name": "fab1", "config": [], "state": "merged"}
    orchestrator = ManageTorOrchestrator(rest_send=_build_rest_send([], params), results=_make_results())
    vpc = {
        "accessOrTorSwitchId": "T3",
        "accessOrTorPeerSwitchId": "T4",
        "aggregationOrLeafSwitchId": "L3",
        "aggregationOrLeafPeerSwitchId": "L4",
    }
    paths = _record_requests(
        orchestrator,
        [
            {"associations": [dict(vpc)]},
            {"associations": [dict(vpc, resources={"accessOrTorVpcId": 10, "aggregationOrLeafVpcId": 20})]},
        ],
    )

    result = orchestrator.query_all()

    assert result[0]["resources"] == {"accessOrTorVpcId": 10, "aggregationOrLeafVpcId": 20}
    assert "aggregationOrLeafSwitchId=L3" in paths[1]
    assert "aggregationOrLeafPeerSwitchId=L4" in paths[1]


def test_manage_tor_orchestrator_query_all_one_call_per_scope():
    """Associations sharing an aggregation scope cost a single enrichment call."""
    params = {"check_mode": False, "fabric_name": "fab1", "config": [], "state": "merged"}
    orchestrator = ManageTorOrchestrator(rest_send=_build_rest_send([], params), results=_make_results())
    paths = _record_requests(
        orchestrator,
        [
            {
                "associations": [
                    {"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1", "aggregationOrLeafPeerSwitchId": "L2"},
                    {"accessOrTorSwitchId": "T2", "aggregationOrLeafSwitchId": "L1", "aggregationOrLeafPeerSwitchId": "L2"},
                ]
            },
            {"associations": []},
        ],
    )

    orchestrator.query_all()

    # Two associations, one shared scope: one membership call plus one enrichment call.
    assert len(paths) == 2


def test_manage_tor_orchestrator_query_all_discards_candidate_rows():
    """Candidate rows for ToRs paired elsewhere never contaminate the result.

    A scoped query also returns switches associated to a different leaf, carrying
    proposed (not configured) allocations. They are dropped by identity matching
    against the authoritative membership list rather than by parsing ``remarks``.
    """
    params = {"check_mode": False, "fabric_name": "fab1", "config": [], "state": "merged"}
    orchestrator = ManageTorOrchestrator(rest_send=_build_rest_send([], params), results=_make_results())
    _record_requests(
        orchestrator,
        [
            {"associations": [{"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1"}]},
            {
                "associations": [
                    {"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1", "resources": {"accessOrTorPortChannelId": 511}},
                    # Paired with a different leaf; its 501 is a proposed allocation.
                    {"accessOrTorSwitchId": "T9", "aggregationOrLeafSwitchId": "L1", "resources": {"accessOrTorPortChannelId": 501}},
                ]
            },
        ],
    )

    result = orchestrator.query_all()

    assert len(result) == 1
    assert result[0]["accessOrTorSwitchId"] == "T1"
    assert result[0]["resources"] == {"accessOrTorPortChannelId": 511}


def test_manage_tor_orchestrator_query_all_skips_enrichment_for_deleted():
    """`deleted` matches on identity alone, so it must not pay for enrichment."""
    params = {"check_mode": False, "fabric_name": "fab1", "config": [], "state": "deleted"}
    orchestrator = ManageTorOrchestrator(rest_send=_build_rest_send([], params), results=_make_results())
    paths = _record_requests(
        orchestrator,
        [{"associations": [{"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1"}]}],
    )

    result = orchestrator.query_all()

    assert len(paths) == 1
    assert "resources" not in result[0]


def test_manage_tor_orchestrator_query_all_ignores_unknown_resource_keys():
    """Only the six known resource IDs are merged; response extras are dropped."""
    params = {"check_mode": False, "fabric_name": "fab1", "config": [], "state": "merged"}
    orchestrator = ManageTorOrchestrator(rest_send=_build_rest_send([], params), results=_make_results())
    _record_requests(
        orchestrator,
        [
            {"associations": [{"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1"}]},
            {
                "associations": [
                    {
                        "accessOrTorSwitchId": "T1",
                        "aggregationOrLeafSwitchId": "L1",
                        "resources": {"accessOrTorPortChannelId": 511, "someFutureKey": "x"},
                    }
                ]
            },
        ],
    )

    result = orchestrator.query_all()

    assert result[0]["resources"] == {"accessOrTorPortChannelId": 511}


def test_manage_tor_orchestrator_association_key_is_order_independent():
    """vPC members sort, so ND reporting a different primary/peer still matches."""
    submitted = {
        "accessOrTorSwitchId": "T3",
        "accessOrTorPeerSwitchId": "T4",
        "aggregationOrLeafSwitchId": "L3",
        "aggregationOrLeafPeerSwitchId": "L4",
    }
    swapped = {
        "accessOrTorSwitchId": "T4",
        "accessOrTorPeerSwitchId": "T3",
        "aggregationOrLeafSwitchId": "L4",
        "aggregationOrLeafPeerSwitchId": "L3",
    }
    assert ManageTorOrchestrator._association_key(submitted) == ManageTorOrchestrator._association_key(swapped)


def test_manage_tor_orchestrator_query_all_empty_fabric():
    """query_all returns an empty list when the fabric has no associations."""
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send([_resp({"associations": []})], params)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())
    with does_not_raise():
        result = orchestrator.query_all()
    assert result == []


# =============================================================================
# associate / disassociate (top-level JSON array request body)
# =============================================================================


def test_manage_tor_orchestrator_create_bulk_sends_array_body():
    """associate (create_bulk) POSTs a top-level JSON array of switch pairs to
    accessAssociationActions/associate. The array body must reach the wire
    intact -- ND rejects anything but a bare array here, and RestSend must not
    coerce or reject the list."""
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send([_resp({"status": "success"}, return_code=207, method="POST")], params)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())

    pairs = [
        ManageTorModel(fabric_name="fab1", access_or_tor_switch_id="T1", aggregation_or_leaf_switch_id="L1"),
        ManageTorModel(fabric_name="fab1", access_or_tor_switch_id="T2", aggregation_or_leaf_switch_id="L2"),
    ]

    with does_not_raise():
        orchestrator.create_bulk(pairs)

    assert rest_send.path.endswith("/accessAssociationActions/associate")
    assert rest_send.committed_payload == [
        {"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1"},
        {"accessOrTorSwitchId": "T2", "aggregationOrLeafSwitchId": "L2"},
    ]


def test_manage_tor_orchestrator_delete_bulk_sends_array_body():
    """disassociate (delete_bulk) POSTs a top-level JSON array of switch-pair
    identifiers to accessAssociationActions/disassociate."""
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send([_resp({"status": "success"}, return_code=207, method="POST")], params)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())

    pairs = [
        ManageTorModel(fabric_name="fab1", access_or_tor_switch_id="T1", aggregation_or_leaf_switch_id="L1"),
    ]

    with does_not_raise():
        orchestrator.delete_bulk(pairs)

    assert rest_send.path.endswith("/accessAssociationActions/disassociate")
    assert rest_send.committed_payload == [
        {"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1"},
    ]


# =============================================================================
# config_actions
# =============================================================================


def test_manage_tor_orchestrator_uses_shared_fabric_policy():
    """ToR config actions are governed by the shared fabric policy, so the module
    argspec, validation and deploy scopes cannot drift from the fabric modules."""
    assert ManageTorOrchestrator.config_actions_policy is FABRIC_CONFIG_ACTIONS


def test_manage_tor_orchestrator_filter_switches_needing_deploy():
    """Only switches whose configSyncStatus is not inSync are selected."""
    switches = [
        {"serialNumber": "S1", "additionalData": {"configSyncStatus": "outOfSync"}},
        {"serialNumber": "S2", "additionalData": {"configSyncStatus": "inSync"}},
        {"serialNumber": "S3", "additionalData": {}},
    ]
    assert ManageTorOrchestrator._filter_switches_needing_deploy(switches) == ["S1", "S3"]


def test_manage_tor_orchestrator_scoped_deploy_matches_on_switch_id_not_serial():
    """The deploy allowlist is keyed by ``switchId``, which may differ from the serial.

    ``affected_switch_ids()`` returns the model's ``*_switch_id`` values, and the
    mixin builds its candidates with ``_switch_identifier`` (switchId preferred).
    Where the two differ -- ACI nodes report a node ID as ``switchId`` -- matching on
    serials would empty the intersection and turn the deploy into a silent no-op.
    """
    switches = {
        "switches": [
            {"switchId": "NODE-101", "serialNumber": "FOC111AAA", "additionalData": {"configSyncStatus": "outOfSync"}},
            {"switchId": "NODE-102", "serialNumber": "FOC222BBB", "additionalData": {"configSyncStatus": "outOfSync"}},
        ]
    }
    responses = [
        _resp(switches, method="GET"),  # context build: fabric membership
        _resp({"status": "Config save is completed"}, method="POST"),  # config_save
        _resp(switches, method="GET"),  # post-save deploy target resolution
        _resp({"status": "success"}, return_code=207, method="POST"),  # switchActions/deploy
        _resp(  # post-deploy verification
            {"switches": [{"switchId": "NODE-101", "additionalData": {"configSyncStatus": "inSync"}}]},
            method="GET",
        ),
    ]
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send(responses, params)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())
    actions = parse_config_actions(
        params={"config_actions": {"save": True, "deploy": True, "type": "switch"}},
        raw_args={"config_actions": {"save": True, "deploy": True, "type": "switch"}},
        policy=FABRIC_CONFIG_ACTIONS,
    )

    with does_not_raise():
        orchestrator.run_config_actions(
            actions=actions,
            fabric_names=["fab1"],
            state="merged",
            only_switch_ids={"NODE-101"},
        )

    assert rest_send.sender.payload_for("switchActions/deploy") == {"switchIds": ["NODE-101"]}


def test_manage_tor_orchestrator_run_config_actions_save_and_scoped_switch_deploy():
    """run_config_actions runs configSave then a switch-level deploy scoped to the
    switches of the associations changed this run, not every out-of-sync switch.

    S3 is out of sync but untouched by this run, so it must not be deployed.
    """
    switches = {
        "switches": [
            {"serialNumber": "S1", "additionalData": {"configSyncStatus": "outOfSync"}},
            {"serialNumber": "S2", "additionalData": {"configSyncStatus": "inSync"}},
            {"serialNumber": "S3", "additionalData": {"configSyncStatus": "outOfSync"}},
        ]
    }
    responses = [
        _resp(switches, method="GET"),  # context build: fabric membership
        _resp({"status": "Config save is completed"}, method="POST"),  # config_save
        _resp(switches, method="GET"),  # post-save deploy target resolution
        _resp({"status": "success"}, return_code=207, method="POST"),  # switchActions/deploy
        _resp(  # post-deploy verification
            {"switches": [{"serialNumber": "S1", "additionalData": {"configSyncStatus": "inSync"}}]},
            method="GET",
        ),
    ]
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send(responses, params)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())
    actions = parse_config_actions(
        params={"config_actions": {"save": True, "deploy": True, "type": "switch"}},
        raw_args={"config_actions": {"save": True, "deploy": True, "type": "switch"}},
        policy=FABRIC_CONFIG_ACTIONS,
    )

    with does_not_raise():
        orchestrator.run_config_actions(
            actions=actions,
            fabric_names=["fab1"],
            state="merged",
            only_switch_ids={"S1", "S2"},
        )

    assert any(path.endswith("/switchActions/deploy") for path in rest_send.sender.paths())
    assert rest_send.sender.payload_for("switchActions/deploy") == {"switchIds": ["S1"]}


def test_manage_tor_orchestrator_run_config_actions_noop_issues_no_requests():
    """With save and deploy both disabled the orchestrator must not call ND at all.

    The sender is primed with no responses, so any request would raise.
    """
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send([], params)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())
    actions = parse_config_actions(params={}, raw_args={}, policy=FABRIC_CONFIG_ACTIONS)

    with does_not_raise():
        result = orchestrator.run_config_actions(actions=actions, fabric_names=["fab1"], state="merged")

    assert result is None


# =============================================================================
# 207 Multi-Status per-item failure handling (benign-message allowlist)
# =============================================================================


def _pair(tor: str = "T1", leaf: str = "L1") -> ManageTorModel:
    return ManageTorModel(fabric_name="fab1", access_or_tor_switch_id=tor, aggregation_or_leaf_switch_id=leaf)


def test_manage_tor_orchestrator_create_bulk_benign_207_is_success():
    """A 207 whose only failed item reports a port-channel id defaulted to 0
    (the id was omitted) is benign -- ND still records the association intent --
    so create_bulk must not raise."""
    body = {
        "associations": [
            {
                "accessOrTorSwitchId": "T1",
                "aggregationOrLeafSwitchId": "L1",
                "status": "failed",
                "message": "Out of Range : DCNM-UUID-302030 Id [0] is not within the range of 1 and 4096",
            },
        ]
    }
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send([_resp(body, return_code=207, method="POST")], params)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())

    with does_not_raise():
        orchestrator.create_bulk([_pair()])


def test_manage_tor_orchestrator_create_bulk_real_207_failure_raises():
    """A 207 failed item that is NOT the benign omitted-id case must raise, and
    the raised message must carry the real failure item."""
    body = {
        "associations": [
            {
                "accessOrTorSwitchId": "T1",
                "aggregationOrLeafSwitchId": "L1",
                "status": "failed",
                "message": "Out of Range : DCNM-UUID-302030 Id [5000] is not within the range of 1 and 4096",
            },
        ]
    }
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send([_resp(body, return_code=207, method="POST")], params)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())

    with pytest.raises(Exception, match="Bulk associate failed"):
        orchestrator.create_bulk([_pair()])


def test_manage_tor_orchestrator_create_bulk_mixed_raises_on_real_only():
    """A 207 mixing a benign omitted-id failure with a genuine failure raises,
    reporting only the genuine failure (the benign item is suppressed)."""
    body = {
        "associations": [
            {
                "accessOrTorSwitchId": "T1",
                "aggregationOrLeafSwitchId": "L1",
                "status": "failed",
                "message": "Out of Range : DCNM-UUID-1 Id [0] is not within the range of 1 and 4096",
            },
            {
                "accessOrTorSwitchId": "T2",
                "aggregationOrLeafSwitchId": "L2",
                "status": "failed",
                "message": "Switch T2 is not reachable",
            },
        ]
    }
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send([_resp(body, return_code=207, method="POST")], params)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())

    with pytest.raises(Exception, match="Switch T2 is not reachable") as exc_info:
        orchestrator.create_bulk([_pair("T1", "L1"), _pair("T2", "L2")])
    assert "Id [0]" not in str(exc_info.value)


def test_manage_tor_orchestrator_create_bulk_all_success_207_no_raise():
    """A 207 whose items all succeed must not raise."""
    body = {
        "associations": [
            {"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1", "status": "success", "message": "associated"},
        ]
    }
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send([_resp(body, return_code=207, method="POST")], params)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())

    with does_not_raise():
        orchestrator.create_bulk([_pair()])


def test_manage_tor_orchestrator_delete_bulk_real_207_failure_raises():
    """A genuine 207 failure on disassociate raises under the disassociate prefix."""
    body = {
        "associations": [
            {
                "accessOrTorSwitchId": "T1",
                "aggregationOrLeafSwitchId": "L1",
                "status": "failed",
                "message": "Association not found",
            },
        ]
    }
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send([_resp(body, return_code=207, method="POST")], params)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())

    with pytest.raises(Exception, match="Bulk disassociate failed"):
        orchestrator.delete_bulk([_pair()])


# =============================================================================
# Version-gated resource reservation (ND 4.2.x reserve -> associate)
# =============================================================================


@pytest.mark.parametrize(
    "version, expected",
    [
        ("4.2.1.10", (4, 2)),
        ("4.3.0", (4, 3)),
        ("5.0", (5, 0)),
        (None, None),
        ("", None),
        ("garbage", None),
        ("4", None),
    ],
)
def test_manage_tor_orchestrator_parse_major_minor(version, expected):
    """_parse_major_minor extracts (major, minor) or None for unparseable input."""
    assert ManageTorOrchestrator._parse_major_minor(version) == expected


@pytest.mark.parametrize(
    "version, expected",
    [
        ("4.2.1.10", True),  # 4.2.x requires manual reservation
        ("4.3.0", False),  # 4.3+ allocates implicitly
        ("5.1.2", False),
        (None, True),  # unknown version -> reserve (current GA is 4.2.x)
    ],
)
def test_manage_tor_orchestrator_requires_manual_resource_reservation(version, expected):
    """The capability flag is driven by the controller (major, minor) version."""
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send([], params, controller_version=version)
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())
    assert orchestrator._requires_manual_resource_reservation() is expected


def test_manage_tor_orchestrator_create_bulk_reserves_on_4_2_when_resources_omitted():
    """On ND 4.2.x, an associate that omits the resource IDs first POSTs to
    reserveResources and merges the allocated IDs into the associate payload."""
    reserved = {
        "accessOrTorPortChannelId": 501,
        "aggregationOrLeafPortChannelId": 502,
    }
    responses = [
        _resp({"resources": reserved}, method="POST"),  # reserveResources
        _resp({"status": "success"}, return_code=207, method="POST"),  # associate
    ]
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send(responses, params, controller_version="4.2.1.10")
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())

    with does_not_raise():
        orchestrator.create_bulk([_pair()])

    # Last committed payload is the associate array carrying the reserved IDs.
    assert rest_send.path.endswith("/accessAssociationActions/associate")
    assert rest_send.committed_payload == [
        {
            "accessOrTorSwitchId": "T1",
            "aggregationOrLeafSwitchId": "L1",
            "resources": reserved,
        }
    ]


def test_manage_tor_orchestrator_create_bulk_skips_reserve_on_4_3():
    """On ND 4.3+, associate omits the resource IDs and no reserveResources call
    is made (a single associate response is the only request consumed)."""
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send(
        [_resp({"status": "success"}, return_code=207, method="POST")],
        params,
        controller_version="4.3.1",
    )
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())

    with does_not_raise():
        orchestrator.create_bulk([_pair()])

    assert rest_send.path.endswith("/accessAssociationActions/associate")
    assert rest_send.committed_payload == [
        {"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1"},
    ]


def test_manage_tor_orchestrator_create_bulk_skips_reserve_when_user_supplies_resources():
    """On ND 4.2.x, a user-supplied resource ID is honoured as-is -- no
    reserveResources call is made (only the associate request is consumed)."""
    params = {"check_mode": False, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send(
        [_resp({"status": "success"}, return_code=207, method="POST")],
        params,
        controller_version="4.2.1.10",
    )
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())

    pair = ManageTorModel(
        fabric_name="fab1",
        access_or_tor_switch_id="T1",
        aggregation_or_leaf_switch_id="L1",
        access_or_tor_port_channel_id=777,
    )

    with does_not_raise():
        orchestrator.create_bulk([pair])

    assert rest_send.path.endswith("/accessAssociationActions/associate")
    assert rest_send.committed_payload == [
        {
            "accessOrTorSwitchId": "T1",
            "aggregationOrLeafSwitchId": "L1",
            "resources": {"accessOrTorPortChannelId": 777},
        }
    ]


def test_manage_tor_orchestrator_create_bulk_skips_reserve_in_check_mode():
    """Check mode never mutates the controller: reserveResources is skipped even
    on ND 4.2.x with the resource IDs omitted."""
    params = {"check_mode": True, "fabric_name": "fab1", "config": []}
    rest_send = _build_rest_send([], params, controller_version="4.2.1.10")
    orchestrator = ManageTorOrchestrator(rest_send=rest_send, results=_make_results())

    with does_not_raise():
        orchestrator.create_bulk([_pair()])

    assert rest_send.committed_payload == [
        {"accessOrTorSwitchId": "T1", "aggregationOrLeafSwitchId": "L1"},
    ]
