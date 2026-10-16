# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Interface Group deployment evidence through the real REST response pipeline."""

from __future__ import annotations

import logging
from copy import deepcopy
from types import SimpleNamespace
from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.config_models import InterfaceGroupConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_interface_group import ManageInterfaceGroupOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.modules import nd_manage_interface_group
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

TARGETS = frozenset({("SN1", "Ethernet1/10"), ("SN2", "Ethernet1/11")})
DEPLOY = "/api/v1/manage/fabrics/fab1/interfaceActions/deploy"
PREVIEW = "/api/v1/manage/fabrics/fab1/interfaceActions/preview"
VPC_PARENT_GET = "/api/v1/manage/fabrics/fab1/switches/SN1/interfaces/vPC10"
ENTRYPOINTS = ("deploy_pending", "deploy_accepted_mutations")


class RecordingSender(Sender):
    """Replace only the network boundary, retaining all response handling."""

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[dict[str, Any]] = []

    def commit(self) -> None:
        self.calls.append({"path": self.path, "verb": self.verb, "payload": deepcopy(self.payload)})
        super().commit()


def _payload(targets=TARGETS):
    return {"interfaces": [{"switchId": switch_id, "interfaceName": name} for switch_id, name in sorted(targets)]}


def _deploy_body(targets=TARGETS):
    return {"results": [{**pair, "status": "success"} for pair in _payload(targets)["interfaces"]]}


def _preview_body(targets=TARGETS, *, lines=0, config=""):
    return {
        "configurationDiffs": [
            {**pair, "status": "success", "combinedConfigs": [{"configType": "pending", "lines": lines, "config": config}]}
            for pair in _payload(targets)["interfaces"]
        ]
    }


def _vpc_parent_body():
    return {
        "switchId": "SN1",
        "interfaceName": "vPC10",
        "interfaceType": "vpc",
        "configData": {
            "networkOS": {
                "policy": {
                    "peerSwitchId": "SN2",
                    "peer1PortChannelId": 10,
                    "peer1MemberPorts": ["Ethernet1/12"],
                    "peer2PortChannelId": 20,
                    "peer2MemberPorts": ["Ethernet1/13"],
                }
            }
        },
    }


def _vpc_inventory_path(serial):
    return f"/api/v1/manage/fabrics/fab1/switches/{serial}/interfaces?offset=0&max=500&sort=interfaceName%3Aasc"


def _vpc_inventory_responses(first="SN2", parent_patch=None):
    """Complete local member/port-channel evidence replaces positional parent-only proof."""
    responses = []
    for serial in (first, "SN1" if first == "SN2" else "SN2"):
        peer, pc_id, member_name = ("SN2", 10, "Ethernet1/12") if serial == "SN1" else ("SN1", 20, "Ethernet1/13")
        parent = _vpc_parent_body()
        parent["switchId"] = serial
        parent["configData"]["mode"] = "trunk"
        parent["configData"]["networkOS"]["networkOSType"] = "nx-os"
        parent["configData"]["networkOS"]["policy"].update(policyType="trunkVpcHost", peerSwitchId=peer)
        if parent_patch and serial == "SN1":
            parent.update(deepcopy(parent_patch))
        rows = [parent]
        for name, kind, policy_type in ((f"Port-channel{pc_id}", "portChannel", "trunkVpcMember"), (member_name, "ethernet", "vpcMember")):
            rows.append(
                {
                    "switchId": serial,
                    "interfaceName": name,
                    "interfaceType": kind,
                    "configData": {
                        "mode": "trunk",
                        "networkOS": {
                            "networkOSType": "nx-os",
                            "policy": {"policyType": policy_type, "portChannelId": f"port-channel{pc_id}", "primaryInterface": "vPC10"},
                        },
                    },
                }
            )
        responses.append(_response(_vpc_inventory_path(serial), {"interfaces": rows, "meta": {"counts": {"total": 3, "remaining": 0}}}, code=200, verb="GET"))
    return responses


def _response(path, data, *, code=207, verb="POST"):
    return {"RETURN_CODE": code, "METHOD": verb, "REQUEST_PATH": path, "MESSAGE": "Multi-Status" if code == 207 else "OK", "DATA": deepcopy(data)}


def _build(responses, *, targets=TARGETS, deploy=True):
    sender = RecordingSender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(iter(responses))
    handler = ResponseHandler()
    handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    handler.verb = HttpVerbEnum.GET
    handler.commit()
    rest = RestSend({"check_mode": False, "fabric_name": "fab1", "state": "merged", "config_actions": {"deploy": deploy, "type": "resource"}})
    rest.sender = sender
    rest.response_handler = handler
    rest.unit_test = True
    rest.timeout = 1
    orchestrator = ManageInterfaceGroupOrchestrator(rest_send=rest)
    orchestrator._pending_interfaces = set(targets)
    return orchestrator, sender


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_complete_deploy_keeps_fast_path(entrypoint):
    """Exact success proves all targets without extra reads, save, or deploy."""
    orchestrator, sender = _build([_response(DEPLOY, _deploy_body())])
    result = getattr(orchestrator, entrypoint)()
    assert not orchestrator._pending_interfaces
    assert [call["path"] for call in sender.calls] == [DEPLOY]
    assert sender.calls[0]["payload"] == _payload()
    if entrypoint == "deploy_accepted_mutations":
        assert result == {"interfaces": sorted(TARGETS), "switches": []}
    else:
        assert result == _deploy_body()


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("data", [{}, {"results": []}, {"results": [_deploy_body()["results"][0]]}, None, []])
@pytest.mark.parametrize("code", [200, 202, 204, 207])
def test_insufficient_deploy_requires_exact_preview(entrypoint, data, code):
    """HTTP acceptance alone cannot clear any requested target."""
    orchestrator, sender = _build([_response(DEPLOY, data, code=code), _response(PREVIEW, _preview_body())])
    getattr(orchestrator, entrypoint)()
    assert not orchestrator._pending_interfaces
    assert [call["path"] for call in sender.calls] == [DEPLOY, PREVIEW]
    assert all(call["payload"] == _payload() for call in sender.calls)


CONTRADICTORY_DEPLOY = [
    {"results": [_deploy_body({("SN3", "Ethernet1/99")})["results"][0]]},
    {"results": _deploy_body()["results"] + _deploy_body({("SN1", "Ethernet1/99")})["results"]},
    {"results": [_deploy_body()["results"][0]] * 2},
    {"results": _deploy_body()["results"] + [_deploy_body()["results"][0]]},
    {"results": [None]},
    {"results": ["bad"]},
    {"results": [{"status": "success"}]},
    {"results": [{"switchId": "SN1", "interfaceName": "", "status": "success"}]},
    {"results": {"status": "success"}},
    {"results": None},
    {"results": [{"switchId": "SN1", "interfaceName": "Ethernet1/10", "status": "failed"}]},
    {"results": [{"switchId": "SN1", "interfaceName": "Ethernet1/10", "status": "warning"}]},
    {"results": [{"switchId": "SN1", "interfaceName": "Ethernet1/10"}]},
]


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("data", CONTRADICTORY_DEPLOY)
def test_contradictory_deploy_fails_without_preview(entrypoint, data):
    """Unrelated or malformed success rows cannot substitute for missing targets."""
    orchestrator, sender = _build([_response(DEPLOY, data)])
    with pytest.raises(Exception, match="contradictory|Request failed"):
        getattr(orchestrator, entrypoint)()
    assert orchestrator._pending_interfaces == TARGETS
    assert [call["path"] for call in sender.calls] == [DEPLOY]
    if entrypoint == "deploy_pending":
        assert orchestrator.deploy_accepted_mutations() == {"interfaces": [], "switches": []}
        assert len(sender.calls) == 1


def _bad_preview_bodies():
    bodies = [{}, {"configurationDiffs": []}, {"configurationDiffs": {}}, {"configurationDiffs": [None]}]
    bodies += [_preview_body({("SN1", "Ethernet1/10")}), _preview_body(TARGETS | {("SN3", "Ethernet1/99")})]
    duplicate = _preview_body()
    duplicate["configurationDiffs"][1] = deepcopy(duplicate["configurationDiffs"][0])
    bodies.append(duplicate)
    for patch in [
        {"switchId": ""},
        {"interfaceName": None},
        {"status": "failed"},
        {"status": "warning"},
        {"status": None},
        {"combinedConfigs": None},
        {"combinedConfigs": []},
        {"combinedConfigs": [None]},
        {"combinedConfigs": [{"configType": "expected", "lines": 0}]},
        {"combinedConfigs": [{"configType": "pending", "lines": 0}] * 2},
        {"combinedConfigs": [{"configType": None, "lines": 0}]},
    ]:
        body = _preview_body()
        body["configurationDiffs"][0].update(patch)
        bodies.append(body)
    bodies.extend(_preview_body(lines=lines) for lines in [None, -1, True, "0", 0.0])
    return bodies


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("preview", _bad_preview_bodies())
def test_invalid_preview_never_confirms_deployment(entrypoint, preview):
    """Missing pending counts or identities fail immediately with the queue intact."""
    orchestrator, sender = _build([_response(DEPLOY, {}), _response(PREVIEW, preview)])
    with pytest.raises(RuntimeError):
        getattr(orchestrator, entrypoint)()
    assert orchestrator._pending_interfaces == TARGETS
    assert [call["path"] for call in sender.calls] == [DEPLOY, PREVIEW]


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("converges", [False, True])
def test_pending_preview_reads_are_bounded_without_redeployment(entrypoint, converges):
    previews = [_preview_body(lines=1)] * 3
    if converges:
        previews[2] = _preview_body()
    orchestrator, sender = _build([_response(DEPLOY, {})] + [_response(PREVIEW, body) for body in previews])
    if converges:
        getattr(orchestrator, entrypoint)()
        assert not orchestrator._pending_interfaces
    else:
        with pytest.raises(RuntimeError, match="pending configuration remains"):
            getattr(orchestrator, entrypoint)()
        assert orchestrator._pending_interfaces == TARGETS
    assert [call["path"] for call in sender.calls] == [DEPLOY, PREVIEW, PREVIEW, PREVIEW]


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_deploy_disabled_or_empty_queue_makes_no_calls(entrypoint):
    disabled, sender = _build([], deploy=False)
    getattr(disabled, entrypoint)()
    assert disabled._pending_interfaces == TARGETS
    assert not sender.calls
    empty, sender = _build([], targets=set())
    getattr(empty, entrypoint)()
    assert not sender.calls


@pytest.mark.parametrize("raises", [False, True])
def test_read_only_preview_restores_check_mode(monkeypatch, raises):
    orchestrator, _sender = _build([])
    orchestrator.rest_send.check_mode = True

    def request(self, **kwargs):
        assert self.rest_send.check_mode is False
        assert kwargs["operation_type"] == OperationType.QUERY
        if raises:
            raise RuntimeError("preview unavailable")
        return _preview_body()

    monkeypatch.setattr(ManageInterfaceGroupOrchestrator, "_request", request)
    if raises:
        with pytest.raises(RuntimeError, match="preview unavailable"):
            orchestrator._preview_interfaces(TARGETS)
    else:
        assert orchestrator._preview_interfaces(TARGETS) == _preview_body()
    assert orchestrator.rest_send.check_mode is True


@pytest.mark.parametrize("targets", [{("", "Ethernet1/10")}, {("SN1", "")}, {("SN1", "Ethernet1/10"), ("SN1", "ethernet1/10")}])
def test_invalid_submitted_identities_fail_before_deployment(targets):
    orchestrator, sender = _build([], targets=targets)
    with pytest.raises(RuntimeError, match="invalid or duplicate"):
        orchestrator.deploy_pending()
    assert orchestrator._pending_interfaces == targets
    assert not sender.calls


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("interface_name", ["Port-channel10", "vPC10"])
def test_exact_parent_success_needs_no_preview_or_peer_lookup(entrypoint, interface_name):
    targets = {("SN1", interface_name)}
    orchestrator, sender = _build([_response(DEPLOY, _deploy_body(targets))], targets=targets)
    getattr(orchestrator, entrypoint)()
    assert [call["path"] for call in sender.calls] == [DEPLOY]
    assert not orchestrator._pending_interfaces


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("config_type", ["pending", "expected"])
@pytest.mark.parametrize("line_ending", ["\n", "\r\n"])
def test_port_channel_derived_members_require_exact_post_preview(entrypoint, config_type, line_ending):
    targets = {("SN1", "Port-channel10")}
    child = {("SN1", "Ethernet1/12")}
    parent_preview = _preview_body(
        targets, lines=2 if config_type == "pending" else 0, config="interface Ethernet1/12\n  channel-group 10 mode active\ninterface port-channel10\n"
    )
    parent_preview["configurationDiffs"][0]["combinedConfigs"].append({"configType": "expected", "lines": 2, "config": ""})
    if config_type == "expected":
        parent_preview["configurationDiffs"][0]["combinedConfigs"][0]["config"] = ""
        parent_preview["configurationDiffs"][0]["combinedConfigs"][1]["config"] = "interface Ethernet1/12\n"
    for config in parent_preview["configurationDiffs"][0]["combinedConfigs"]:
        config["config"] = config["config"].replace("\n", line_ending)
    deploy = _deploy_body(targets | child)
    orchestrator, sender = _build(
        [_response(DEPLOY, deploy), _response(PREVIEW, parent_preview), _response(PREVIEW, _preview_body(targets | child))], targets=targets
    )
    getattr(orchestrator, entrypoint)()
    assert [call["path"] for call in sender.calls] == [DEPLOY, PREVIEW, PREVIEW]
    assert sender.calls[-1]["payload"] == _payload(targets | child)
    assert not orchestrator._pending_interfaces


@pytest.mark.parametrize("child", [("SN1", "Ethernet1/99"), ("SN2", "Ethernet1/12")])
def test_port_channel_cannot_authorize_unproven_child(child):
    targets = {("SN1", "Port-channel10")}
    parent_preview = _preview_body(targets, config="interface Ethernet1/12\n")
    orchestrator, sender = _build([_response(DEPLOY, _deploy_body(targets | {child})), _response(PREVIEW, parent_preview)], targets=targets)
    with pytest.raises(RuntimeError, match="unrelated identity"):
        orchestrator.deploy_pending()
    assert orchestrator._pending_interfaces == targets
    assert [call["path"] for call in sender.calls] == [DEPLOY, PREVIEW]


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("deploy_targets", [{("SN1", "vPC10")}, {("SN1", "vPC10"), ("SN2", "vPC10")}])
def test_vpc_requires_both_exact_peer_preview_rows(entrypoint, deploy_targets):
    submitted = {("SN1", "vPC10")}
    peers = submitted | {("SN2", "vPC10")}
    replies = [_response(DEPLOY, _deploy_body(deploy_targets))]
    if deploy_targets != submitted:
        replies.extend([_response(PREVIEW, _preview_body(peers)), _response(PREVIEW, _preview_body(peers))])
    orchestrator, sender = _build(replies, targets=submitted)
    orchestrator._vpc_peer_cache = {"SN1": "SN2", "SN2": "SN1"}
    getattr(orchestrator, entrypoint)()
    expected_paths = [DEPLOY] if deploy_targets == submitted else [DEPLOY, PREVIEW, PREVIEW]
    assert [call["path"] for call in sender.calls] == expected_paths
    assert sender.calls[0]["payload"] == _payload(submitted)
    assert all(call["payload"] == _payload(submitted) for call in sender.calls[1:])
    assert not orchestrator._pending_interfaces


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_vpc_generated_peer_children_use_strict_scoped_fallback(entrypoint):
    """The peer's parent preview may omit generated member CLI."""
    submitted = {("SN1", "vPC10")}
    peers = submitted | {("SN2", "vPC10")}
    children = {("SN1", "Port-channel10"), ("SN1", "Ethernet1/12"), ("SN2", "Port-channel20"), ("SN2", "Ethernet1/13")}
    parent_preview = _preview_body(peers)
    parent_preview["configurationDiffs"][0]["combinedConfigs"][0].update(config="interface port-channel10\ninterface Ethernet1/12\n")
    orchestrator, sender = _build(
        [
            _response(DEPLOY, _deploy_body(children)),
            _response(PREVIEW, parent_preview),
            *_vpc_inventory_responses(),
            _response(PREVIEW, _preview_body(peers | children)),
        ],
        targets=submitted,
    )
    orchestrator._vpc_peer_cache = {"SN1": "SN2"}
    getattr(orchestrator, entrypoint)()
    assert [call["path"] for call in sender.calls] == [DEPLOY, PREVIEW, _vpc_inventory_path("SN2"), _vpc_inventory_path("SN1"), PREVIEW]
    assert sender.calls[1]["payload"] == _payload(submitted)
    assert sender.calls[-1]["payload"] == _payload(submitted | children)
    assert not orchestrator._pending_interfaces


@pytest.mark.parametrize("child", [("SN3", "Ethernet1/12"), ("SN2", "Vlan10"), ("SN2", "e1/12")])
def test_vpc_cannot_authorize_arbitrary_result_scope(child):
    submitted = {("SN1", "vPC10")}
    peers = submitted | {("SN2", "vPC10")}
    orchestrator, sender = _build([_response(DEPLOY, _deploy_body({child})), _response(PREVIEW, _preview_body(peers))], targets=submitted)
    orchestrator._vpc_peer_cache = {"SN1": "SN2"}
    with pytest.raises(RuntimeError, match="unrelated identity"):
        orchestrator.deploy_pending()
    assert [call["path"] for call in sender.calls] == [DEPLOY, PREVIEW]
    assert orchestrator._pending_interfaces == submitted


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
@pytest.mark.parametrize("child", [("SN1", "Ethernet1/99"), ("SN2", "Ethernet1/99"), ("SN2", "Port-channel99")])
def test_vpc_unrelated_child_on_valid_pair_requires_membership_evidence(entrypoint, child):
    submitted = {("SN1", "vPC10")}
    peers = submitted | {("SN2", "vPC10")}
    orchestrator, sender = _build(
        [
            _response(DEPLOY, _deploy_body(submitted | {child})),
            _response(PREVIEW, _preview_body(peers)),
            *_vpc_inventory_responses(first=child[0]),
        ],
        targets=submitted,
    )
    orchestrator._vpc_peer_cache = {"SN1": "SN2"}
    with pytest.raises(RuntimeError, match="ownership"):
        getattr(orchestrator, entrypoint)()
    assert [call["path"] for call in sender.calls] == [
        DEPLOY,
        PREVIEW,
        _vpc_inventory_path(child[0]),
        _vpc_inventory_path("SN1" if child[0] == "SN2" else "SN2"),
    ]
    assert orchestrator._pending_interfaces == submitted


@pytest.mark.parametrize(
    "parent_patch",
    [{"interfaceType": "ethernet"}, {"switchId": "SN2"}, {"configData": {}}, {"configData": {"networkOS": {"policy": {"peerSwitchId": "SN3"}}}}],
)
def test_vpc_child_requires_valid_parent_readback(parent_patch):
    submitted = {("SN1", "vPC10")}
    peers = submitted | {("SN2", "vPC10")}
    orchestrator, sender = _build(
        [
            _response(DEPLOY, _deploy_body(submitted | {("SN2", "Ethernet1/13")})),
            _response(PREVIEW, _preview_body(peers)),
            *_vpc_inventory_responses(parent_patch=parent_patch),
        ],
        targets=submitted,
    )
    orchestrator._vpc_peer_cache = {"SN1": "SN2"}
    with pytest.raises(RuntimeError, match="ownership"):
        orchestrator.deploy_pending()
    assert [call["path"] for call in sender.calls] == [DEPLOY, PREVIEW, _vpc_inventory_path("SN2"), _vpc_inventory_path("SN1")]
    assert orchestrator._pending_interfaces == submitted


@pytest.mark.parametrize(
    "preview", [{}, {"configurationDiffs": []}, _preview_body({("SN2", "Port-channel10")}), _preview_body({("SN1", "Port-channel10")}, lines=True)]
)
def test_invalid_parent_preview_cannot_confirm_ambiguous_deployment(preview):
    targets = {("SN1", "Port-channel10")}
    orchestrator, sender = _build([_response(DEPLOY, {}), _response(PREVIEW, preview)], targets=targets)
    with pytest.raises(RuntimeError, match="Cannot establish parent deployment identities"):
        orchestrator.deploy_pending()
    assert [call["path"] for call in sender.calls] == [DEPLOY, PREVIEW]
    assert orchestrator._pending_interfaces == targets


def test_vpc_missing_peer_evidence_cannot_clear_queue():
    submitted = {("SN1", "vPC10")}
    peers = submitted | {("SN2", "vPC10")}
    orchestrator, sender = _build(
        [
            _response(DEPLOY, {}),
            _response(PREVIEW, _preview_body(peers)),
            _response(PREVIEW, _preview_body(submitted)),
            _response(PREVIEW, _preview_body(submitted)),
        ],
        targets=submitted,
    )
    orchestrator._vpc_peer_cache = {"SN1": "SN2"}
    with pytest.raises(RuntimeError, match="missing=.*SN2"):
        orchestrator.deploy_pending()
    assert orchestrator._pending_interfaces == submitted
    assert len(sender.calls) == 4
    assert all(call["payload"] == _payload(submitted) for call in sender.calls[1:3])
    assert sender.calls[-1]["payload"] == _payload({("SN2", "vPC10")})


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_vpc_one_peer_preview_with_incomplete_fallback_cannot_confirm_deploy(entrypoint):
    submitted = {("SN1", "vPC10")}
    orchestrator, sender = _build(
        [_response(DEPLOY, {}), _response(PREVIEW, _preview_body(submitted)), _response(PREVIEW, _preview_body(set()))],
        targets=submitted,
    )
    orchestrator._vpc_peer_cache = {"SN1": "SN2"}
    with pytest.raises(RuntimeError, match="missing=.*SN2"):
        getattr(orchestrator, entrypoint)()
    assert [call["path"] for call in sender.calls] == [DEPLOY, PREVIEW, PREVIEW]
    assert sender.calls[1]["payload"] == _payload(submitted)
    assert sender.calls[2]["payload"] == _payload({("SN2", "vPC10")})
    assert orchestrator._pending_interfaces == submitted


@pytest.mark.parametrize("peer", [None, "", "SN1"])
def test_vpc_unknown_or_self_peer_cannot_confirm_ambiguous_deploy(peer):
    targets = {("SN1", "vPC10")}
    orchestrator, sender = _build([_response(DEPLOY, {})], targets=targets)
    orchestrator._vpc_peer_cache = {"SN1": peer}
    with pytest.raises(RuntimeError, match="no valid peer"):
        orchestrator.deploy_pending()
    assert [call["path"] for call in sender.calls] == [DEPLOY]
    assert orchestrator._pending_interfaces == targets


@pytest.mark.parametrize("entrypoint", ENTRYPOINTS)
def test_mixed_success_failure_207_keeps_queue_and_skips_preview(entrypoint):
    rows = _deploy_body()["results"]
    rows[1].update(status="failed", message="Interface deployment failed")
    orchestrator, sender = _build([_response(DEPLOY, {"results": rows})])
    with pytest.raises(Exception, match="Request failed"):
        getattr(orchestrator, entrypoint)()
    assert [call["path"] for call in sender.calls] == [DEPLOY]
    assert orchestrator._pending_interfaces == TARGETS


@pytest.mark.parametrize("confirmed", [False, True])
def test_module_finalizer_reports_deployed_only_after_preview_proof(confirmed):
    previews = [_preview_body()] if confirmed else [_preview_body(lines=1)] * 3
    orchestrator, sender = _build([_response(DEPLOY, {"results": [_deploy_body()["results"][0]]})] + [_response(PREVIEW, body) for body in previews])
    note = nd_manage_interface_group._finalize_accepted_intent(SimpleNamespace(model_orchestrator=orchestrator), False, logging.getLogger(__name__))
    assert ("those changes were deployed" in note) is confirmed
    assert ("outcome could not be confirmed" in note) is not confirmed
    assert orchestrator._pending_interfaces == (set() if confirmed else TARGETS)
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1


@pytest.mark.parametrize("confirmed", [False, True])
def test_module_preserves_primary_failure_after_accepted_write(monkeypatch, confirmed):
    """A real accepted PUT is queued before main enters its failure finalizer."""
    path = "/api/v1/manage/fabrics/fab1/interfaceGroups/test-group"
    previews = [_preview_body()] if confirmed else [_preview_body(lines=1)] * 3
    orchestrator, sender = _build(
        [_response(path, {}, code=204, verb="PUT"), _response(DEPLOY, {})] + [_response(PREVIEW, body) for body in previews], targets=set()
    )
    before_group = InterfaceGroupConfigModel.from_config(
        {
            "interface_group_name": "test-group",
            "type": "ethernetWithPolicy",
            "switch_interfaces": [{"switch_id": sn, "interface_names": [name]} for sn, name in sorted(TARGETS)],
        }
    )
    after_group = deepcopy(before_group)
    after_group.ethernet_attributes.cdp = False
    orchestrator._existing_groups = {"test-group": before_group}
    before = NDConfigCollection(model_class=InterfaceGroupConfigModel, items=[before_group])

    class ModuleFailed(Exception):
        pass

    class FakeModule:
        params = {**orchestrator.rest_send.params, "output_level": "normal"}
        check_mode = False
        _verbosity = 0

        @staticmethod
        def fail_json(**kwargs):
            raise ModuleFailed(kwargs)

        @staticmethod
        def exit_json(**kwargs):
            pytest.fail(f"Unexpected success: {kwargs}")

    def manage_state():
        orchestrator._put_and_record(before_group, after_group)
        assert orchestrator.has_accepted_changes
        assert orchestrator._pending_interfaces == TARGETS
        raise RuntimeError("later target update rejected")

    output = NDOutput("normal", state="merged")
    output.assign(before=before, after=before)
    state = SimpleNamespace(
        model_orchestrator=orchestrator, model_class=InterfaceGroupConfigModel, before=before, output=output, results=Results(), manage_state=manage_state
    )
    monkeypatch.setattr(nd_manage_interface_group, "AnsibleModule", lambda **kwargs: FakeModule())
    monkeypatch.setattr(nd_manage_interface_group, "require_pydantic", lambda module: None)
    monkeypatch.setattr(nd_manage_interface_group, "setup_logging", lambda module: None)
    monkeypatch.setattr(nd_manage_interface_group, "_normalize_module_params", lambda module: [])
    monkeypatch.setattr(nd_manage_interface_group, "NDStateMachine", lambda **kwargs: state)
    with pytest.raises(ModuleFailed) as exc_info:
        nd_manage_interface_group.main()
    result = exc_info.value.args[0]
    assert result["msg"].startswith("Module failed: later target update rejected")
    assert ("those changes were deployed" in result["msg"]) is confirmed
    assert result["changed"] is True
    assert result["after"] == [after_group.to_config()]
    assert orchestrator._pending_interfaces == (set() if confirmed else TARGETS)
    assert [call["path"] for call in sender.calls[:2]] == [path, DEPLOY]
    assert sum(call["path"] == DEPLOY for call in sender.calls) == 1
