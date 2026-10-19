# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Requested-pair identity, preflight safety, and scale regressions."""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.config_models import InterfaceGroupConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_interface_group import ManageInterfaceGroupOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.modules import nd_manage_interface_group


def _group(name, switch, names=None):
    return InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": name,
            "type": "vpc",
            "switch_interfaces": [] if switch is None else [{"switch_id": switch, "interface_names": names or ["vPC200"]}],
        }
    )


def _orchestrator(state="merged"):
    return ManageInterfaceGroupOrchestrator(
        rest_send=RestSend(
            {
                "fabric_name": "fab1",
                "state": state,
                "check_mode": False,
                "config_actions": {"deploy": False, "type": "resource"},
            }
        )
    )


@pytest.mark.parametrize("requested", ["SN1", "SN2"])
@pytest.mark.parametrize(
    "response",
    [
        {"switchId": "SN1", "peerSwitchId": "SN2"},
        {"switchId": "SN2", "peerSwitchId": "SN1"},
    ],
)
def test_pair_orientation_and_task_local_cache(monkeypatch, requested, response):
    calls = []

    def request(self, path, verb, **kwargs):
        assert verb == HttpVerbEnum.GET
        calls.append(path)
        return response

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", request)
    orchestrator = _orchestrator()
    assert orchestrator._get_vpc_pair(requested) == ("SN1", "SN2")
    assert orchestrator._get_vpc_pair("SN1") == ("SN1", "SN2")
    assert orchestrator._get_vpc_pair("SN2") == ("SN1", "SN2")
    assert orchestrator._get_vpc_peer_id("SN1") == "SN2"
    assert orchestrator._get_vpc_peer_id("SN2") == "SN1"
    assert len(calls) == 1
    _orchestrator()._get_vpc_pair(requested)
    assert len(calls) == 2  # A fresh task must not reuse an older snapshot.


@pytest.mark.parametrize(
    "response",
    [
        None,
        [],
        {},
        {"peerSwitchId": "SN2"},
        {"switchId": "SN1"},
        {"switchId": "SN1", "peerSwitchId": None},
        {"switchId": " ", "peerSwitchId": "SN2"},
        {"switchId": "SN1", "peerSwitchId": " "},
        {"switchId": True, "peerSwitchId": "SN2"},
        {"switchId": "SN1", "peerSwitchId": ["SN2"]},
        {"switchId": "SN1", "peerSwitchId": "SN1"},
        {"switchId": "SN9", "peerSwitchId": "SN10"},
    ],
)
def test_invalid_pair_never_enters_cache(monkeypatch, response):
    orchestrator = _orchestrator()
    monkeypatch.setattr(orchestrator, "_request", lambda **kwargs: response)
    with pytest.raises(RuntimeError, match="Cannot establish vPC pair for switch 'SN1'"):
        orchestrator._get_vpc_pair("SN1")
    assert orchestrator._vpc_pair_cache == {}
    assert orchestrator._vpc_peer_cache == {}


def test_conflicting_pair_is_rejected_atomically(monkeypatch):
    orchestrator = _orchestrator()
    responses = iter(
        [
            {"switchId": "SN1", "peerSwitchId": "SN2"},
            {"switchId": "SN9", "peerSwitchId": "SN2"},
        ]
    )
    monkeypatch.setattr(orchestrator, "_request", lambda **kwargs: next(responses))
    orchestrator._get_vpc_pair("SN1")
    pairs, peers = deepcopy(orchestrator._vpc_pair_cache), deepcopy(orchestrator._vpc_peer_cache)
    with pytest.raises(RuntimeError, match="conflicting peer identity"):
        orchestrator._get_vpc_pair("SN9")
    assert orchestrator._vpc_pair_cache == pairs
    assert orchestrator._vpc_peer_cache == peers


@pytest.mark.parametrize("requested, expected", [("SN000", "SN000"), ("PN000", "SN000"), ("SN127", "SN127"), ("PN127", "SN127")])
def test_unrelated_pair_availability_cannot_block_requested_owner(monkeypatch, requested, expected):
    orchestrator = _orchestrator()
    orchestrator._existing_groups = {str(i): _group(str(i), f"SN{i:03}") for i in range(128)}
    calls = []

    def request(**kwargs):
        assert kwargs["path"].endswith(f"/switches/{requested}/vpcPair")
        calls.append(kwargs["path"])
        return {"switchId": requested, "peerSwitchId": requested.replace("SN", "PN") if requested.startswith("SN") else expected}

    monkeypatch.setattr(orchestrator, "_request", request)
    proposed = _group(str(int(expected[2:])), requested)
    orchestrator.preflight([proposed])
    assert proposed.switch_interfaces[0].switch_id == expected
    assert len(calls) == 1
    before = NDConfigCollection(model_class=InterfaceGroupConfigModel, items=[orchestrator._existing_groups[proposed.interface_group_name]])
    assert before.get_diff_config(proposed, exclude_unset=True) == "no_diff"


def test_new_pair_and_many_interfaces_need_only_one_lookup(monkeypatch):
    orchestrator = _orchestrator()
    calls = []

    def request(**kwargs):
        calls.append(kwargs["path"])
        return {"switchId": "SN1", "peerSwitchId": "SN2"}

    monkeypatch.setattr(orchestrator, "_request", request)
    names = [f"vPC{i}" for i in range(1, 101)]
    proposed = _group("new", "SN1", names)
    orchestrator.preflight([proposed])
    assert len(calls) == 1
    assert len(proposed.switch_interfaces[0].interface_names) == 100


@pytest.mark.parametrize("state", ["replaced", "overridden"])
def test_opposite_peer_move_keeps_remove_before_add(monkeypatch, state):
    orchestrator = _orchestrator(state)
    source, target = _group("source", "SN2"), _group("target", None)
    orchestrator._existing_groups = {"source": source, "target": target}
    calls = []

    def request(**kwargs):
        assert kwargs["verb"] == HttpVerbEnum.GET
        calls.append(kwargs["path"])
        return {"switchId": "SN1", "peerSwitchId": "SN2"}

    monkeypatch.setattr(orchestrator, "_request", request)
    wanted = [_group("target", "SN1")]
    if state == "replaced":
        wanted.append(_group("source", None))
    orchestrator.preflight(wanted)
    assert set(orchestrator._move_plan) == {"source"}
    assert wanted[0].switch_interfaces[0].switch_id == "SN2"
    existing = NDConfigCollection(model_class=InterfaceGroupConfigModel, items=[source, target])
    proposed = NDConfigCollection(model_class=InterfaceGroupConfigModel, items=wanted)
    orchestrator.prepare_mutations(existing, proposed, check_mode=True)
    assert existing.get("source").switch_interfaces == []
    assert len(calls) == 1


def test_confirmed_pair_limits_readback_matching_to_its_two_switches(monkeypatch):
    orchestrator = _orchestrator()
    monkeypatch.setattr(orchestrator, "_request", lambda **kwargs: {"switchId": "SN1", "peerSwitchId": "SN2"})
    orchestrator._get_vpc_pair("SN1")

    def unexpected_request(**kwargs):
        raise AssertionError(f"Unrelated lookup: {kwargs['path']}")

    monkeypatch.setattr(orchestrator, "_request", unexpected_request)
    expected = _group("group", "SN1")
    assert orchestrator._matches_expected_model(_group("group", "SN2"), expected)
    assert not orchestrator._matches_expected_model(_group("group", "SN9"), expected)
    assert not orchestrator._vpc_switch_ids_are_equivalent("SN9", "SN1")


class _TaskResult(BaseException):
    pass


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("bad_response", [None, {"peerSwitchId": "SN10"}, {"switchId": "SN9", "peerSwitchId": "SN9"}, RuntimeError("HTTP 503 unavailable")])
def test_pair_failure_reports_unchanged_before_any_batch_write(monkeypatch, state, bad_response):
    before = {"existing": _group("existing", "SN1")}
    calls = []

    class Module:
        check_mode = False
        _verbosity = 0
        no_log_values = set()
        params = {
            "fabric_name": "fab1",
            "state": state,
            "output_level": "normal",
            "config_actions": {"deploy": True, "type": "resource"},
            "config": [_group("existing", "SN1").to_config(), _group("new", "SN9").to_config()],
        }

        def fail_json(self, **kwargs):
            raise _TaskResult(kwargs)

        def exit_json(self, **kwargs):
            raise AssertionError("Invalid pair must fail the task")

    def query_all(self):
        self._existing_groups = deepcopy(before)
        return [value.model_dump(by_alias=True, mode="json", exclude_none=True) for value in before.values()]

    def request(self, path, verb, **kwargs):
        assert verb == HttpVerbEnum.GET
        calls.append(path)
        if path.endswith("/switches/SN1/vpcPair"):
            return {"switchId": "SN1", "peerSwitchId": "SN2"}
        assert path.endswith("/switches/SN9/vpcPair")
        if isinstance(bad_response, Exception):
            raise bad_response
        return bad_response

    monkeypatch.setattr(nd_manage_interface_group, "AnsibleModule", lambda **kwargs: Module())
    monkeypatch.setattr(nd_manage_interface_group, "setup_logging", lambda module: None)
    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "query_all", query_all)
    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", request)
    with pytest.raises(_TaskResult) as result:
        nd_manage_interface_group.main()
    output = result.value.args[0]
    assert output["changed"] is False
    assert output["before"] == output["after"]
    assert output["diff"] == []
    assert "Cannot establish vPC pair for switch 'SN9'" in output["msg"]
    if isinstance(bad_response, Exception):
        assert "HTTP 503 unavailable" in output["msg"]
    assert len(calls) == 2


@pytest.mark.parametrize("pair_count", [32, 64, 128])
def test_cached_full_preflight_work_is_bounded_by_member_count(monkeypatch, pair_count):
    """Guard the review's cached-data case, where network counts alone miss the defect."""
    orchestrator = _orchestrator()
    names = [f"vPC{i}" for i in range(1, 21)]
    for i in range(pair_count):
        first, second = f"SN{i:03}", f"PN{i:03}"
        pair = tuple(sorted((first, second)))
        orchestrator._vpc_pair_cache[first] = orchestrator._vpc_pair_cache[second] = pair
        orchestrator._vpc_peer_cache[first], orchestrator._vpc_peer_cache[second] = second, first
    orchestrator._existing_groups = {str(i): _group(str(i), f"SN{i:03}", names) for i in range(pair_count)}
    wanted = [_group(str(i), f"PN{i:03}", names) for i in range(pair_count)]
    counts = []
    for name in ("_get_vpc_pair", "_get_vpc_peer_id", "_vpc_switch_ids_are_equivalent"):
        method = getattr(orchestrator, name)

        def counted(*args, _method=method, **kwargs):
            counts.append(1)
            return _method(*args, **kwargs)

        monkeypatch.setattr(orchestrator, name, counted)

    def unexpected_request(**kwargs):
        raise AssertionError("Cached pair identities must not cause controller requests")

    monkeypatch.setattr(orchestrator, "_request", unexpected_request)
    orchestrator.preflight(wanted)
    assert len(counts) <= pair_count * len(names) * 3
    assert [item.switch_interfaces[0].switch_id for item in wanted] == [f"SN{i:03}" for i in range(pair_count)]
