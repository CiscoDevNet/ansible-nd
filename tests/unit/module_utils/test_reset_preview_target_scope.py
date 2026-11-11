# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Fabric reset proof validates exact targets without rejecting unrelated switches."""

from collections import Counter
from copy import deepcopy
from urllib.parse import urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_executor import InterfaceWorkflowExecutor
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import InterfaceWorkflowPlanner
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_trunk_host_interface import EthernetTrunkHostInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import InterfaceDefaultConfig
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_access_interface import EthernetAccessInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_trunk_host_interface import EthernetTrunkHostInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

CLI_FIELDS = ("runningConfigs", "pendingConfigs", "expectedConfigs")
VERSIONS = ("4.2.1.10", "4.3.1.175")


def _row(name="Ethernet1/1", switch_id="S1"):
    row = InterfaceDefaultConfig.to_reset_payload(name, switch_id)
    row["configData"]["networkOS"]["policy"].update(description="configured", speed="auto", negotiateAuto=True)
    return row


def _unrelated(configs=None):
    return {"switchId": "UNRELATED", "status": "notApplicable", **{field: deepcopy(configs) for field in CLI_FIELDS}}


class _PreviewSender(Sender):
    """In-memory controller; unexpected requests fail before any network access."""

    def __init__(self, rows):
        super().__init__()
        self.rows = {(row["switchId"], row["interfaceName"]): deepcopy(row) for row in rows}
        self.calls = []
        self.extra_rows = [_unrelated()]
        self.fabric_overrides = {}
        self.unsafe_after_normalize = False

    def _cli(self, name, kind, *, fabric=False):
        if kind == "pending":
            normalized = any(call["path"].endswith("/interfaceActions/normalize") for call in self.calls)
            return f"interface {name}\n  no negotiate auto\n" if fabric and normalized and self.unsafe_after_normalize else ""
        return f"interface {name}\n  negotiate auto\n"

    def commit(self):
        path, verb, payload = self.path, self.verb, self.payload
        self.calls.append({"path": path, "verb": verb, "payload": deepcopy(payload)})
        code = 200
        if verb == HttpVerbEnum.GET and "/interfaces?" in path:
            switch_id = urlsplit(path).path.split("/")[-2]
            data = {"interfaces": [deepcopy(row) for (serial, _name), row in self.rows.items() if serial == switch_id]}
        elif verb == HttpVerbEnum.GET and path.endswith("/actions/preview"):
            items = []
            for serial in dict.fromkeys(serial for serial, _name in self.rows):
                row = {"switchId": serial, "status": "outOfSync"}
                for kind in ("running", "pending", "expected"):
                    row[kind + "Configs"] = [self._cli(name, kind, fabric=True) for switch, name in self.rows if switch == serial]
                row.update(deepcopy(self.fabric_overrides.get(serial, {})))
                items.append(row)
            data = {"items": items + deepcopy(self.extra_rows)}
        elif verb == HttpVerbEnum.POST and path.endswith("/interfaceActions/preview"):
            data = {"configurationDiffs": []}
            for item in payload["interfaces"]:
                configs = []
                for kind in ("running", "pending", "expected"):
                    cli = self._cli(item["interfaceName"], kind)
                    configs.append({"configType": kind, "config": cli, "lines": len(cli.splitlines())})
                data["configurationDiffs"].append({**item, "status": "success", "combinedConfigs": configs})
        elif verb == HttpVerbEnum.POST and path.endswith("/interfaceActions/normalize"):
            for item in payload["switchInterfaces"]:
                self.rows[(item["switchId"], item["interfaceName"])]["configData"] = deepcopy(payload["configData"])
            data = {"results": [{"name": item["interfaceName"], "status": "success"} for item in payload["switchInterfaces"]]}
            code = 207
        elif verb == HttpVerbEnum.GET and "/links?" in path:
            data = {"links": []}
        else:
            raise AssertionError(f"Unexpected offline request: {verb} {path}")
        self._response = {"RETURN_CODE": code, "DATA": data, "MESSAGE": "OK", "METHOD": verb.value, "REQUEST_PATH": path}

    @property
    def response(self):
        return deepcopy(self._response)


def _runtime(rows=None, version=VERSIONS[-1]):
    sender = _PreviewSender(rows if rows is not None else [_row()])
    rest = RestSend({"fabric_name": "F", "state": "deleted", "check_mode": False})
    rest.controller_version = version
    rest.sender, rest.response_handler = sender, ResponseHandler()
    rest.unit_test, rest.timeout = True, 1
    orchestrator = EthernetTrunkHostInterfaceOrchestrator(rest_send=rest, results=Results())
    context = orchestrator.fabric_context
    context._fabric_summary = {"local": True, "fabricStatus": "default"}
    context._switch_map = {"192.0.2.1": "S1", "192.0.2.2": "S2", "192.0.2.99": "UNRELATED"}
    context._switch_map_by_id = {serial: address for address, serial in context._switch_map.items()}
    context._switches = [
        {"switchId": serial, "fabricManagementIp": address, "platformType": "nx-os", "vpcConfigured": False, "vpcData": {}}
        for address, serial in context._switch_map.items()
    ]
    return orchestrator, sender


def _model(name="Ethernet1/1", switch_ip="192.0.2.1"):
    return EthernetTrunkHostInterfaceModel.from_config({"switch_ip": switch_ip, "interface_name": name}, context={"state": "deleted"})


def _register(orchestrator, name="Ethernet1/1", switch_id="S1"):
    orchestrator.state_snapshot.load_switch(switch_id)
    orchestrator.register_reset_negotiation_preview_scope([_model(name, orchestrator.fabric_context._switch_map_by_id[switch_id])])


def _counts(sender):
    return Counter(call["path"].rsplit("/", 1)[-1].split("?")[0] for call in sender.calls)


@pytest.mark.parametrize("status", ["inSync", "notApplicable"])
@pytest.mark.parametrize("configs", [None, []])
def test_unrelated_nullable_cli_does_not_block_registered_target(status, configs):
    orchestrator, sender = _runtime()
    sender.extra_rows = [{**_unrelated(configs), "status": status}]
    _register(orchestrator)
    rows = orchestrator._fabric_reset_negotiation_rows()
    assert rows["S1"]["status"] == "outOfSync"
    assert rows["UNRELATED"] == sender.extra_rows[0]
    assert orchestrator._reset_negotiation_preview("Ethernet1/1", "S1")["fabric_running"] == ["interface ethernet1/1", "negotiate auto"]
    assert _counts(sender)["preview"] == 2  # One fabric GET and one exact interface POST.


@pytest.mark.parametrize("bad_row", [None, {}, {"switchId": None}, {"switchId": ""}, {"switchId": " S2"}, {"switchId": "S2 "}, {"switchId": 2}])
def test_identity_checks_still_cover_unrelated_rows(bad_row):
    orchestrator, sender = _runtime()
    sender.extra_rows = [bad_row]
    _register(orchestrator)
    with pytest.raises(RuntimeError, match="malformed switch row|missing or duplicate switch identities"):
        orchestrator._fabric_reset_negotiation_rows()
    assert orchestrator._reset_negotiation_fabric_preview is None


@pytest.mark.parametrize("duplicate", ["S1", "UNRELATED"])
def test_duplicate_target_or_unrelated_identity_is_rejected(duplicate):
    orchestrator, sender = _runtime()
    sender.extra_rows.append({**_unrelated(), "switchId": duplicate})
    _register(orchestrator)
    with pytest.raises(RuntimeError, match="missing or duplicate switch identities"):
        orchestrator._fabric_reset_negotiation_rows()


@pytest.mark.parametrize("status", ["notApplicable", None, "success"])
def test_target_status_still_fails_before_reset(status):
    orchestrator, sender = _runtime()
    sender.fabric_overrides["S1"] = {"status": status}
    orchestrator.delete(_model())
    with pytest.raises(RuntimeError, match="unsupported status for S1"):
        orchestrator.remove_pending()
    assert _counts(sender)["normalize"] == 0
    assert orchestrator.pending_normalizes == (("Ethernet1/1", "S1"),)


@pytest.mark.parametrize("field", CLI_FIELDS)
@pytest.mark.parametrize("bad_cli", [None, "interface Ethernet1/1", [1]])
def test_target_cli_arrays_remain_strict(field, bad_cli):
    orchestrator, sender = _runtime()
    sender.fabric_overrides["S1"] = {field: bad_cli}
    orchestrator.delete(_model())
    with pytest.raises(RuntimeError, match=f"lacks valid {field} for S1"):
        orchestrator.remove_pending()
    assert _counts(sender)["normalize"] == 0


@pytest.mark.parametrize("field", ["runningConfigs", "expectedConfigs"])
@pytest.mark.parametrize("configs", [[], ["interface Ethernet1/10\n  negotiate auto\n"]])
def test_target_requires_exact_fabric_interface_proof(field, configs):
    orchestrator, sender = _runtime()
    sender.fabric_overrides["S1"] = {field: configs}
    orchestrator.delete(_model())
    with pytest.raises(RuntimeError, match="does not identify .* interface S1/Ethernet1/1"):
        orchestrator.remove_pending()
    assert _counts(sender)["normalize"] == 0


@pytest.mark.parametrize("bad_scope", [{"status": "notApplicable"}, {"runningConfigs": None}])
@pytest.mark.parametrize("shared", [False, True])
@pytest.mark.parametrize("exact", [False, True])
def test_cached_unrelated_row_is_revalidated_when_it_becomes_a_target(bad_scope, shared, exact):
    orchestrator, sender = _runtime([_row(), _row(switch_id="S2")])
    sender.fabric_overrides["S2"] = bad_scope
    _register(orchestrator)
    orchestrator._fabric_reset_negotiation_rows()
    consumer = orchestrator
    if shared:
        consumer = EthernetAccessInterfaceOrchestrator(rest_send=orchestrator.rest_send, interface_state_snapshot=orchestrator.state_snapshot)
        consumer.share_fabric_link_cache(orchestrator)
    _register(consumer, switch_id="S2")
    with pytest.raises(RuntimeError, match="unsupported status for S2|lacks valid runningConfigs for S2"):
        if exact:
            consumer._reset_negotiation_preview("Ethernet1/1", "S2")
        else:
            consumer._fabric_reset_negotiation_rows()
    assert sum(call["verb"] == HttpVerbEnum.GET and call["path"].endswith("/actions/preview") for call in sender.calls) == 1


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("configs", [None, []])
def test_standalone_reset_ignores_unrelated_not_applicable_switch(version, configs):
    orchestrator, sender = _runtime(version=version)
    sender.extra_rows = [_unrelated(configs)]
    orchestrator.delete(_model())
    orchestrator.remove_pending()
    assert not orchestrator.pending_normalizes
    assert not orchestrator.reset_auto_negotiation_deploy_blocks
    assert sender.rows[("S1", "Ethernet1/1")]["configData"]["networkOS"]["policy"]["extraConfig"] == "negotiate auto"
    assert _counts(sender) == {"interfaces": 3, "preview": 6, "normalize": 1}


@pytest.mark.parametrize("version", VERSIONS)
def test_workflow_shares_exact_reset_scope_across_ethernet_families(version):
    access = _row("Ethernet1/2")
    access["configData"]["mode"] = "access"
    access["configData"]["networkOS"]["policy"].update(policyType="accessHost", accessVlan=10)
    orchestrator, sender = _runtime([_row(), access], version)

    def factory(params):
        orchestrator.rest_send.params.update(params)
        return orchestrator.rest_send

    planner = InterfaceWorkflowPlanner(snapshot=orchestrator.state_snapshot, rest_send_factory=factory)
    plan = planner.plan(
        [
            {"type": family, "state": "deleted", "config": [{"switch_ip": "192.0.2.1", "interface_names": [name]}]}
            for family, name in (("ethernet_trunk_host", "Ethernet1/1"), ("ethernet_access", "Ethernet1/2"))
        ]
    )
    owner, consumer = (resource.orchestrator for resource in plan.resources)
    assert consumer._reset_negotiation_cache_owner() is owner
    assert set(owner._reset_negotiation_preview_scope) == {("S1", "ethernet1/1"), ("S1", "ethernet1/2")}
    assert plan.mutation_count == 2
    assert not any(call["verb"] != HttpVerbEnum.GET for call in sender.calls)
    outcome = InterfaceWorkflowExecutor(snapshot=planner.snapshot, deploy=False).execute(plan)
    assert not outcome.failed, outcome
    normalized = [item for call in sender.calls if call["path"].endswith("/interfaceActions/normalize") for item in call["payload"]["switchInterfaces"]]
    assert sorted((item["switchId"], item["interfaceName"]) for item in normalized) == [("S1", "Ethernet1/1"), ("S1", "Ethernet1/2")]
    assert all(row["configData"]["networkOS"]["policy"]["extraConfig"] == "negotiate auto" for row in sender.rows.values())
    assert not owner.reset_auto_negotiation_deploy_blocks
    assert not consumer.reset_auto_negotiation_deploy_blocks
    preview_batches = [call["payload"]["interfaces"] for call in sender.calls if call["path"].endswith("/interfaceActions/preview")]
    assert preview_batches[0] == [{"interfaceName": name, "switchId": "S1"} for name in ("Ethernet1/1", "Ethernet1/2")]


def test_fresh_post_reset_proof_still_blocks_unsafe_fabric_cli():
    orchestrator, sender = _runtime()
    sender.unsafe_after_normalize = True
    orchestrator.delete(_model())
    with pytest.raises(RuntimeError, match="preview remains unsafe for S1/Ethernet1/1"):
        orchestrator.remove_pending()
    assert _counts(sender)["normalize"] == 1
    assert orchestrator.reset_auto_negotiation_deploy_blocks == (("S1", "ethernet1/1"),)
    with pytest.raises(RuntimeError, match="refusing deployment"):
        orchestrator.deploy_targets([("Ethernet1/1", "S1")])


def test_missing_target_is_not_replaced_by_unrelated_proof():
    orchestrator, sender = _runtime()
    sender.fabric_overrides["S1"] = {"switchId": "OTHER"}
    orchestrator.delete(_model())
    with pytest.raises(RuntimeError, match="omits switch S1"):
        orchestrator.remove_pending()
    assert _counts(sender)["normalize"] == 0


@pytest.mark.parametrize("status", ["inSync", "notApplicable"])
def test_default_reset_fast_path_validates_only_its_exact_switch(status):
    current = _row()
    current["configData"]["networkOS"]["policy"]["description"] = ""
    orchestrator, sender = _runtime([current])
    sender.fabric_overrides["S1"] = {"status": status}
    assert orchestrator._is_absent_delete_reset_target(current)
    if status == "inSync":
        assert orchestrator._retain_reset_auto_negotiation("Ethernet1/1", "S1", current) is False
    else:
        with pytest.raises(RuntimeError, match="unsupported status for S1"):
            orchestrator._retain_reset_auto_negotiation("Ethernet1/1", "S1", current)
    assert len(sender.calls) == 1
    assert sender.calls[0]["verb"] == HttpVerbEnum.GET
    assert sender.calls[0]["path"].endswith("/actions/preview")


def test_fresh_epoch_uses_its_exact_subset_of_registered_targets():
    orchestrator, sender = _runtime([_row(), _row(switch_id="S2")])
    _register(orchestrator)
    _register(orchestrator, switch_id="S2")
    sender.fabric_overrides["S2"] = {"status": "notApplicable", **{field: None for field in CLI_FIELDS}}
    with orchestrator._fresh_reset_negotiation_previews([("Ethernet1/1", "S1")]):
        proof = orchestrator._reset_negotiation_preview("Ethernet1/1", "S1", refresh_fabric=True)
        assert "negotiate auto" in proof["fabric_expected"]
        with pytest.raises(RuntimeError, match="outside its fresh epoch"):
            orchestrator._reset_negotiation_preview("Ethernet1/1", "S2")
    assert orchestrator._reset_negotiation_fabric_preview is None
    assert not orchestrator._reset_negotiation_fabric_blocks
    assert not orchestrator._reset_negotiation_interface_preview
    assert orchestrator._reset_negotiation_preview_epoch is None
    assert len(orchestrator._reset_negotiation_preview_scope) == 2
    assert _counts(sender) == {"interfaces": 2, "preview": 2}


@pytest.mark.parametrize("fresh", [False, True])
def test_changed_target_is_revalidated_after_revision_or_explicit_refresh(fresh):
    orchestrator, sender = _runtime()
    _register(orchestrator)
    assert "negotiate auto" in orchestrator._reset_negotiation_preview("Ethernet1/1", "S1")["fabric_running"]
    sender.fabric_overrides["S1"] = {"status": "notApplicable"}
    if not fresh:
        snapshot = orchestrator.state_snapshot
        snapshot._revisions_by_switch["S1"] = snapshot.switch_revision("S1") + 1
    with pytest.raises(RuntimeError, match="unsupported status for S1"):
        orchestrator._reset_negotiation_preview("Ethernet1/1", "S1", refresh_fabric=fresh)
    assert sum(call["verb"] == HttpVerbEnum.GET and call["path"].endswith("/actions/preview") for call in sender.calls) == 2
    if fresh:
        assert orchestrator._reset_negotiation_fabric_preview is None
        assert orchestrator._reset_negotiation_preview_epoch is None


def test_registered_reset_batch_keeps_bounded_previews_and_shared_fabric_reads():
    rows = [_row(f"Ethernet1/{index}") for index in range(1, 102)]
    orchestrator, sender = _runtime(rows)
    orchestrator.enable_bounded_workflow_reset_evidence()
    models = [_model(row["interfaceName"]) for row in rows]
    orchestrator.state_snapshot.load_switch("S1")
    orchestrator.register_reset_negotiation_preview_scope(models)
    orchestrator.delete_bulk(models)
    orchestrator.remove_pending()
    assert not orchestrator.pending_normalizes
    assert not orchestrator.reset_auto_negotiation_deploy_blocks
    assert all(row["configData"]["networkOS"]["policy"]["extraConfig"] == "negotiate auto" for row in sender.rows.values())
    batches = [call["payload"]["interfaces"] for call in sender.calls if call["path"].endswith("/interfaceActions/preview")]
    assert [len(batch) for batch in batches] == [100, 1] * 3
    assert _counts(sender) == {"interfaces": 3, "preview": 9, "normalize": 1}
