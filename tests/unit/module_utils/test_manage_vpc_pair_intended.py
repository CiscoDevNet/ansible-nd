# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Configured vPC intent remains authoritative before physical activation."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair import query, resources
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import VpcPairResourceError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vpc_pair.vpc_pair_model import VpcPairModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection

PH1, PH2 = "PLACEHOLDER-1", "PLACEHOLDER-2"
SW1, SW2 = "PHYSICAL-1", "PHYSICAL-2"


def _pair(first=PH1, second=PH2, virtual=False):
    return {"switchId": first, "peerSwitchId": second, "useVirtualPeerLink": virtual, "vpcAction": "pair"}


def _page(pairs, total=None, remaining=None, next_link=None):
    result = {"vpcPairs": pairs}
    if total is not None or remaining is not None or next_link is not None:
        result["meta"] = {}
    if total is not None or remaining is not None:
        result["meta"]["counts"] = {"total": total, "remaining": remaining}
    if next_link is not None:
        result["meta"]["links"] = {"next": next_link}
    return result


@pytest.mark.parametrize("payload", [None, [], "", {}, {"vpcPairs": None}, {"vpcPairs": {}}, {"items": ""}, {"data": False}])
def test_intended_query_rejects_missing_or_malformed_list_wrapper(payload):
    nd = MagicMock()
    nd.request.return_value = payload

    with pytest.raises(VpcPairResourceError):
        query._query_intended_vpc_pairs(nd, "fabric-1")


@pytest.mark.parametrize(
    "row",
    [
        None,
        [],
        "row",
        {},
        {"switchId": PH1},
        {"switchId": PH1, "peerSwitchId": ""},
        {"switchId": " ", "peerSwitchId": PH2},
        {"switchId": 123, "peerSwitchId": PH2},
        {"switchId": PH1, "peerSwitchId": PH1},
        {"switchId": PH1, "peerSwitchId": PH2, "useVirtualPeerLink": "false"},
    ],
)
def test_intended_query_rejects_malformed_pair_rows(row):
    nd = MagicMock()
    nd.request.return_value = {"vpcPairs": [row]}

    with pytest.raises(VpcPairResourceError):
        query._query_intended_vpc_pairs(nd, "fabric-1")


@pytest.mark.parametrize("wrapper", ["vpcPairs", "items", "data"])
def test_explicit_empty_intended_list_is_valid(wrapper):
    nd = MagicMock()
    nd.request.return_value = {wrapper: []}

    assert query._query_intended_vpc_pairs(nd, "fabric-1") == []
    assert nd.request.call_count == 1


def test_intended_query_pages_with_exact_counts_and_preserves_view():
    nd = MagicMock()
    nd.request.side_effect = [
        _page([_pair()], total=2, remaining=1, next_link="/untrusted?view=deployedPairs&offset=99"),
        _page([_pair(SW1, SW2)], total=2, remaining=0),
    ]

    assert query._query_intended_vpc_pairs(nd, "fabric-1") == [_pair(), _pair(SW1, SW2)]
    assert nd.request.call_count == 2
    for offset, call in enumerate(nd.request.call_args_list):
        path = urlsplit(call.args[0])
        assert path.path == "/api/v1/manage/fabrics/fabric-1/vpcPairs"
        assert parse_qs(path.query) == {"view": ["intendedPairs"], "max": ["500"], "offset": [str(offset)]}


@pytest.mark.parametrize(
    "meta",
    [
        None,
        [],
        {"counts": None},
        {"counts": {}},
        {"counts": {"total": True, "remaining": 0}},
        {"counts": {"total": 1, "remaining": False}},
        {"counts": {"total": -1, "remaining": 0}},
        {"counts": {"total": "1", "remaining": 0}},
        {"counts": {"total": 2, "remaining": 0}},
        {"links": []},
        {"links": {"next": True}},
        {"counts": {"total": 1, "remaining": 0}, "links": {"next": "/next"}},
    ],
)
def test_intended_query_rejects_invalid_or_conflicting_pagination_metadata(meta):
    nd = MagicMock()
    nd.request.return_value = {"vpcPairs": [_pair()], "meta": meta}

    with pytest.raises(VpcPairResourceError):
        query._query_intended_vpc_pairs(nd, "fabric-1")


def test_intended_query_rejects_changed_total_between_pages():
    nd = MagicMock()
    nd.request.side_effect = [_page([_pair()], 2, 1), _page([_pair(SW1, SW2)], 3, 1)]

    with pytest.raises(VpcPairResourceError, match="inconsistent"):
        query._query_intended_vpc_pairs(nd, "fabric-1")


def test_intended_query_rejects_repeated_pair_even_with_reversed_peers():
    nd = MagicMock()
    nd.request.side_effect = [_page([_pair()], 2, 1), _page([_pair(PH2, PH1)], 2, 0)]

    with pytest.raises(VpcPairResourceError, match="repeated"):
        query._query_intended_vpc_pairs(nd, "fabric-1")


def test_intended_query_rejects_partial_page_without_progress():
    nd = MagicMock()
    nd.request.return_value = _page([], total=1, remaining=1)

    with pytest.raises(VpcPairResourceError, match="no progress"):
        query._query_intended_vpc_pairs(nd, "fabric-1")


def _inventory(*pairs):
    result = {}
    for index, pair in enumerate(pairs):
        for number, serial in enumerate((pair["switchId"], pair["peerSwitchId"])):
            result[serial] = {
                "serialNumber": serial,
                "fabricManagementIp": f"192.0.2.{10 + index * 2 + number}",
                "vpcConfigured": serial.startswith("PHYSICAL"),
                "vpcData": {"peerSwitchId": pair["peerSwitchId"] if number == 0 else pair["switchId"]},
            }
    return result


def _context(monkeypatch, pairs, state="merged", inventory=None, config=None):
    module = SimpleNamespace(
        params={
            "fabric_name": "fabric-1",
            "state": state,
            "config": config or [],
            "config_actions": {"save": False, "deploy": False},
            "verify": {"enabled": False},
        },
        check_mode=False,
        warn=MagicMock(),
    )
    nd = MagicMock()
    nd.request.return_value = _page(deepcopy(pairs), total=len(pairs), remaining=0)
    monkeypatch.setattr(query, "NDModuleV2", lambda supplied: nd)
    monkeypatch.setattr(query, "_is_external_fabric", MagicMock(return_value=False))
    monkeypatch.setattr(query, "normalize_vpc_playbook_switch_identifiers", MagicMock(return_value=None))
    inventory_query = MagicMock(return_value=deepcopy(inventory if inventory is not None else _inventory(*pairs)))
    monkeypatch.setattr(query, "_validate_fabric_switches", inventory_query)
    direct = {pair["switchId"]: deepcopy(pair) for pair in pairs}
    direct_query = MagicMock(side_effect=lambda **kwargs: deepcopy(direct.get(kwargs["switch_id"])))
    monkeypatch.setattr(query, "_get_direct_vpc_pair", direct_query)
    membership = MagicMock(return_value=False)
    monkeypatch.setattr(query, "_is_switch_in_vpc_pair", membership)
    monkeypatch.setattr(query, "_get_recommendation_details", MagicMock(side_effect=AssertionError("Unexpected recommendation fallback")))
    return SimpleNamespace(module=module), nd, inventory_query, direct_query, membership


def test_gathered_placeholder_pair_survives_inactive_overview(monkeypatch):
    pair = _pair(virtual=True)
    context, nd, inventory_query, direct_query, membership = _context(monkeypatch, [pair], state="gathered")

    result = query.custom_vpc_query_all(context)

    assert result == [pair]
    assert context.module.params["_have"] == [pair]
    assert context.module.params["_pending_delete"] == []
    inventory_query.assert_not_called()
    membership.assert_not_called()
    direct_query.assert_called_once()
    assert nd.request.call_count == 1


def test_physical_and_placeholder_pairs_both_remain_configured(monkeypatch):
    pairs = [_pair(virtual=True), _pair(SW1, SW2)]
    context, _nd, inventory_query, _direct_query, membership = _context(monkeypatch, pairs)

    result = query.custom_vpc_query_all(context)

    assert result == pairs
    assert context.module.params["_have"] == pairs
    assert context.module.params["_pending_create"] == []
    assert context.module.params["_pending_delete"] == []
    assert set(context.module.params["_fabric_switches"]) == {PH1, PH2, SW1, SW2}
    inventory_query.assert_called_once()
    membership.assert_not_called()


def test_empty_intended_override_does_not_resurrect_stale_inventory_or_direct_pair(monkeypatch):
    stale = _pair(SW1, SW2)
    context, _nd, _inventory_query, direct_query, membership = _context(monkeypatch, [], state="overridden", inventory=_inventory(stale))
    direct_query.side_effect = lambda **kwargs: stale if kwargs["switch_id"] == SW1 else None
    membership.return_value = True

    result = query.custom_vpc_query_all(context)

    assert result == []
    assert context.module.params["_have"] == []
    direct_query.assert_called()


@pytest.mark.parametrize("state", ["overridden", "gathered"])
def test_unreadable_intended_list_fails_closed_without_inventory_fallback(monkeypatch, state):
    context, nd, inventory_query, direct_query, membership = _context(monkeypatch, [], state=state)
    nd.request.side_effect = RuntimeError("list unavailable")

    with pytest.raises(VpcPairResourceError, match="complete intended"):
        query.custom_vpc_query_all(context)

    inventory_query.assert_not_called()
    direct_query.assert_not_called()
    membership.assert_not_called()


def test_direct_enrichment_cannot_replace_intended_peer(monkeypatch):
    monkeypatch.setattr(query, "_get_direct_vpc_pair", lambda **kwargs: _pair(PH1, SW1))

    with pytest.raises(VpcPairResourceError, match="conflicts"):
        query._enrich_pairs_from_direct_vpc(MagicMock(), "fabric-1", [_pair()], timeout=1)


@pytest.mark.parametrize("state", ["gathered", "overridden"])
def test_missing_list_mode_and_unavailable_direct_read_fail_closed(monkeypatch, state):
    pair = _pair()
    pair.pop("useVirtualPeerLink")
    context, _nd, inventory_query, direct_query, _membership = _context(monkeypatch, [pair], state=state)
    direct_query.side_effect = None
    direct_query.return_value = None

    with pytest.raises(VpcPairResourceError, match="useVirtualPeerLink"):
        query.custom_vpc_query_all(context)

    inventory_query.assert_not_called()


@pytest.mark.parametrize("virtual", [False, True])
def test_explicit_list_mode_survives_unavailable_direct_read(monkeypatch, virtual):
    monkeypatch.setattr(query, "_get_direct_vpc_pair", lambda **kwargs: None)

    assert query._enrich_pairs_from_direct_vpc(MagicMock(), "fabric-1", [_pair(virtual=virtual)], timeout=1) == [_pair(virtual=virtual)]


def test_omitted_list_mode_is_preserved_until_direct_enrichment(monkeypatch):
    missing_mode = {"switchId": PH1, "peerSwitchId": PH2}
    parsed = query._extract_vpc_pairs_from_list_response({"vpcPairs": [missing_mode]})
    assert "useVirtualPeerLink" not in parsed[0]
    monkeypatch.setattr(query, "_get_direct_vpc_pair", lambda **kwargs: _pair(virtual=True))

    assert query._enrich_pairs_from_direct_vpc(MagicMock(), "fabric-1", parsed, timeout=1) == [_pair(virtual=True)]


@pytest.mark.parametrize("mode", [None, "false", 0])
def test_direct_enrichment_rejects_unreadable_or_non_boolean_mode(monkeypatch, mode):
    pair = _pair()
    pair.pop("useVirtualPeerLink")
    monkeypatch.setattr(query, "_get_direct_vpc_pair", lambda **kwargs: dict(pair, useVirtualPeerLink=mode))

    with pytest.raises(VpcPairResourceError, match="useVirtualPeerLink"):
        query._enrich_pairs_from_direct_vpc(MagicMock(), "fabric-1", [pair], timeout=1)


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
def test_matching_placeholder_replay_has_no_state_machine_create_update_or_delete(monkeypatch, state):
    pair = _pair(virtual=True)
    config = [{"switch_id": PH1, "peer_switch_id": PH2, "use_virtual_peer_link": True}]
    listed = dict(pair)
    listed.pop("useVirtualPeerLink")  # Actual placeholder list shape; the direct GET owns this value.
    context, _nd, _inventory_query, direct_query, membership = _context(monkeypatch, [listed], state=state, config=config)
    direct_query.side_effect = lambda **kwargs: deepcopy(pair)
    observed = query.custom_vpc_query_all(context)
    machine = object.__new__(resources.VpcPairStateMachine)
    machine.module = context.module
    machine.model_class = VpcPairModel
    machine.existing = NDConfigCollection.from_api_response(observed, VpcPairModel)
    machine.sent = NDConfigCollection(VpcPairModel)
    machine.model_orchestrator = MagicMock()
    machine.logs = []

    machine.manage_state(state=state, new_configs=config)

    machine.model_orchestrator.create.assert_not_called()
    machine.model_orchestrator.update.assert_not_called()
    machine.model_orchestrator.delete.assert_not_called()
    assert [row["status"] for row in machine.logs] == ["no_change"]
    assert machine.module.params["_pending_create"] == []
    assert machine.module.params["_pending_delete"] == []
    membership.assert_not_called()


def test_metadata_free_full_page_reads_next_offset_before_claiming_complete():
    first_page = [_pair(f"FULL-{number:04d}-A", f"FULL-{number:04d}-B") for number in range(500)]
    nd = MagicMock()
    nd.request.side_effect = [_page(first_page), _page([])]

    assert query._query_intended_vpc_pairs(nd, "fabric-1") == first_page
    assert nd.request.call_count == 2
    queries = [parse_qs(urlsplit(call.args[0]).query) for call in nd.request.call_args_list]
    assert [item["offset"] for item in queries] == [["0"], ["500"]]
    assert all(item["view"] == ["intendedPairs"] and item["max"] == ["500"] for item in queries)


def test_direct_enrichment_rejects_wrong_primary_even_when_peer_matches(monkeypatch):
    monkeypatch.setattr(query, "_get_direct_vpc_pair", lambda **kwargs: _pair(SW1, PH2))

    with pytest.raises(VpcPairResourceError):
        query._enrich_pairs_from_direct_vpc(MagicMock(), "fabric-1", [_pair()], timeout=1)


def test_intended_list_rejects_one_chassis_in_multiple_pairs():
    nd = MagicMock()
    nd.request.return_value = _page([_pair(PH1, PH2), _pair(PH1, SW1)])

    with pytest.raises(VpcPairResourceError):
        query._query_intended_vpc_pairs(nd, "fabric-1")
    assert nd.request.call_count == 1


def test_metadata_free_partial_pages_are_drained_until_explicit_empty_page():
    nd = MagicMock()
    nd.request.side_effect = [_page([_pair()]), _page([_pair(SW1, SW2)]), _page([])]

    assert query._query_intended_vpc_pairs(nd, "fabric-1") == [_pair(), _pair(SW1, SW2)]
    assert nd.request.call_count == 3
    queries = [parse_qs(urlsplit(call.args[0]).query) for call in nd.request.call_args_list]
    assert [item["offset"] for item in queries] == [["0"], ["1"], ["2"]]
    assert all(item["view"] == ["intendedPairs"] and item["max"] == ["500"] for item in queries)


def test_staged_unpair_keeps_pending_physical_sync_without_resurrecting_intent(monkeypatch):
    operational_pair = _pair(SW1, SW2)
    inventory = _inventory(operational_pair)
    for row in inventory.values():
        row["configSyncStatus"] = "pending"
    config = [{"switch_id": SW1, "peer_switch_id": SW2}]
    context, _nd, _inventory_query, direct_query, membership = _context(monkeypatch, [], state="merged", inventory=inventory, config=config)
    context.module.params["config_actions"] = {"save": True, "deploy": True}
    direct_query.side_effect = lambda **kwargs: operational_pair if kwargs["switch_id"] == SW1 else None
    membership.return_value = True
    monkeypatch.setattr(query, "_is_pair_in_sync_from_overview", MagicMock(return_value=False))

    assert query.custom_vpc_query_all(context) == []
    assert context.module.params["_have"] == []
    assert context.module.params["_not_in_sync_pairs"] == [{"switchId": SW1, "peerSwitchId": SW2}]
    assert context.module.params["_pending_create"] == []
    assert context.module.params["_pending_delete"] == []


def test_empty_deleted_scope_cannot_treat_unreadable_intent_as_nothing_to_delete(monkeypatch):
    context, nd, inventory_query, direct_query, membership = _context(monkeypatch, [], state="deleted")
    assert context.module.params["config"] == []
    nd.request.side_effect = RuntimeError("list unavailable")

    with pytest.raises(VpcPairResourceError, match="complete intended"):
        query.custom_vpc_query_all(context)

    inventory_query.assert_not_called()
    direct_query.assert_not_called()
    membership.assert_not_called()
