"""Exercise creation/attachment sequencing through the real REST runtime."""

from copy import deepcopy
from urllib.parse import urlsplit

import pytest
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import network_module_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_workflow_coordinator import NetworkWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import VrfWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import StandaloneNetworkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_network import MultisiteParentNetworkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_network import MulticlusterParentNetworkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_vrf import MultisiteParentVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_vrf import MulticlusterParentVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError


class _Module:
    _verbosity = 3

    def __init__(self, config, state, check_mode):
        self.params = {"fabric_name": "FAB", "state": state, "config": deepcopy(config), "output_level": "debug"}
        self.check_mode = check_mode

    def fail_json(self, **kwargs):
        raise AssertionError(kwargs)


class _Controller:
    def __init__(self, resource):
        self.resource = resource
        self.name = resource + "Name"
        self.names = resource + "Names"
        self.collection = resource + "s"
        self.definitions = {}
        self.attachments = {}
        self.calls = []
        self.missing_queries = []
        self.query_error = None
        self.switch_response = {"switches": [{"switchId": "SW1", "fabricManagementIp": "192.0.2.10"}]}

    def request(self, verb, path, payload):
        path = urlsplit(path).path
        payload = deepcopy(payload or {})
        self.calls.append((verb, path, payload))
        if verb == "GET" and path.endswith("/switches"):
            return 200, deepcopy(self.switch_response)
        if verb == "GET" and path.endswith("/" + self.collection):
            rows = deepcopy(list(self.definitions.values()))
            return 200, {self.collection: rows, "meta": {"counts": {"remaining": 0, "total": len(rows)}}}
        if path.endswith("Attachments/query"):
            if self.query_error is not None:
                return self.query_error, {"code": self.query_error, "message": "attachment metadata unavailable"}
            names = payload.get(self.names) or list(self.definitions)
            missing = set(names) - self.definitions.keys()
            if missing:
                self.missing_queries.append(sorted(missing))
                message = (
                    f"Network '{sorted(missing)[0]}' doesn't exist in the fabric"
                    if self.resource == "network"
                    else f"VRF(s) {','.join(sorted(missing))} not found in fabric FAB"
                )
                return 400, {"code": 400, "message": message}
            rows = []
            for name in names:
                rows.append(deepcopy(self.attachments.get(name, {self.name: name, "switchId": "SW1", "vlanId": 3300, "attach": False})))
            return 200, {"attachments": rows, "meta": {"counts": {"remaining": 0, "total": len(rows)}}}
        if path.endswith("/validateInterfaces"):
            return 200, {"results": [{self.name: item[self.name], "status": "success"} for item in payload["attachments"]]}
        if verb == "POST" and path.endswith("/" + self.collection):
            for row in payload[self.collection]:
                row.setdefault(self.resource + "Id", 31000 if self.resource == "network" else 51000)
                self.definitions[row[self.name]] = row
            return 207, {"results": [{self.name: row[self.name], "status": "success"} for row in payload[self.collection]]}
        if verb == "POST" and path.endswith("Attachments"):
            for row in payload["attachments"]:
                self.attachments[row[self.name]] = {**self.attachments.get(row[self.name], {}), **row}
            return 200, {"results": [{self.name: row[self.name], "status": "success"} for row in payload["attachments"]]}
        if verb == "PUT" and path.rsplit("/", 2)[-2] == self.collection:
            self.definitions[payload[self.name]] = payload
            return 204, {}
        if verb == "POST" and path.endswith("Actions/deploy"):
            for name in payload[self.names]:
                self.attachments[name]["status"] = "deployed"
            return 202, {}
        raise AssertionError(f"Unexpected request: {verb} {path} {payload}")

    @property
    def writes(self):
        return [call for call in self.calls if call[0] != "GET" and not call[1].endswith(("/query", "/validateInterfaces"))]


@pytest.fixture
def workflow(monkeypatch):
    def build(resource, topology="standalone", version="4.3.1.135.51166"):
        controller = _Controller(resource)

        def commit(sender):
            status, data = controller.request(sender.verb.value, sender.path, sender.payload)
            sender.response = {"RETURN_CODE": status, "MESSAGE": "Bad Request" if status == 400 else "OK", "DATA": data}

        def get_version(_sender):
            return version

        monkeypatch.setattr(Sender, "commit", commit)
        monkeypatch.setattr(Sender, "get_version", get_version)
        strategies = {
            "network": (StandaloneNetworkStrategy, MultisiteParentNetworkStrategy, MulticlusterParentNetworkStrategy),
            "vrf": (StandaloneVrfStrategy, MultisiteParentVrfStrategy, MulticlusterParentVrfStrategy),
        }
        strategy_cls = strategies[resource][("standalone", "group", "multicluster").index(topology)]
        strategy = strategy_cls(
            fabric_name="FAB",
            fabric_data={
                "managementType": "vxlanIbgp" if topology == "standalone" else "vxlan",
                "members": [],
                "manageFabricDetails": {"management": {"type": "vxlanIbgp", "l3VniNoVlanDefaultOption": False}},
            },
        )

        def coordinator(config, state="merged", check=False):
            spec = network_module_argument_spec() if resource == "network" else strategy.get_argument_spec()
            validated = ArgumentSpecValidator({"config": {"type": "list", "elements": "dict", "options": spec}}).validate({"config": deepcopy(config)})
            assert not validated.error_messages
            module = _Module(validated.validated_parameters["config"], state, check)
            cls = NetworkWorkflowCoordinator if resource == "network" else VrfWorkflowCoordinator
            return cls(module=module, strategy=strategy)

        return controller, coordinator

    return build


def _entry(resource, name, identifier=31001):
    entry = {
        resource + "_name": name,
        resource + "_id": identifier,
        "deploy": False,
        "attach": [{"ip_address": "192.0.2.10", **({"deploy": False} if resource == "network" else {})}],
    }
    if resource == "network":
        entry["layer"] = "layer2"
    return entry


def _seed(controller, coordinator, entry):
    instance = coordinator([entry])
    args = instance.module.params
    if controller.resource == "network":
        orchestrator, _results = instance._new_network_orchestrator(args, instance.strategy)
    else:
        orchestrator, _results = instance._new_vrf_orchestrator(args, instance.strategy)
    parsed = instance._parse_config(args["config"], instance.strategy.config_model_cls, args["state"])
    model = orchestrator.model_class.from_config(orchestrator.prepare_config_data(parsed)[0])
    controller.definitions[entry[controller.resource + "_name"]] = orchestrator._create_or_update_payload(model)
    controller.attachments[entry[controller.resource + "_name"]] = {
        controller.name: entry[controller.resource + "_name"],
        "switchId": "SW1",
        "attach": True,
        "vlanId": 3300,
        "extraConfig": "! retained",
        "instanceValues": {},
        **({"interfaces": [{"mode": "access", "interfaceRange": "Ethernet1/7", "nativeVlan": False}]} if controller.resource == "network" else {}),
    }


@pytest.mark.parametrize("resource", ["network", "vrf"])
@pytest.mark.parametrize("topology", ["standalone", "group", "multicluster"])
@pytest.mark.parametrize("version", ["4.2.1.10", "4.3.1.135.51166"])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("shape", ["new", "existing-first", "new-first"])
def test_new_and_mixed_attachment_workflow_reuses_inventory(workflow, resource, topology, version, state, check, shape):
    controller, coordinator = workflow(resource, topology, version)
    entries = [_entry(resource, "NEW")]
    existing_attachment = None
    if shape != "new":
        existing = _entry(resource, "EXISTING", 31002)
        _seed(controller, coordinator, existing)
        existing_attachment = deepcopy(controller.attachments["EXISTING"])
        if state != "merged":
            existing["attach"][0]["freeform_config"] = "! retained"
            if resource == "network":
                existing["attach"][0]["interfaces"] = [{"mode": "access", "interface_range": "Ethernet1/7"}]
        entries.insert(0 if shape == "existing-first" else 1, existing)
    before = deepcopy((controller.definitions, controller.attachments))
    result = coordinator(entries, state, check).run()

    assert result["changed"] is True
    assert not result.get("failed")
    assert controller.missing_queries == []
    assert sum(verb == "GET" and path.endswith("/" + controller.collection) for verb, path, _payload in controller.calls) == 1
    queries = [call for call in controller.calls if call[1].endswith("Attachments/query")]
    assert len(queries) == (shape != "new") + (not check)
    if check:
        assert controller.writes == []
        assert (controller.definitions, controller.attachments) == before
    else:
        assert controller.attachments["NEW"]["attach"] is True
        assert [
            row[controller.name]
            for verb, path, payload in controller.calls
            if verb == "POST" and path.endswith("Attachments")
            for row in payload["attachments"]
        ] == ["NEW"]
        if existing_attachment is not None:
            assert controller.attachments["EXISTING"] == existing_attachment
        for repeat_check in (False, True):
            controller.calls.clear()
            repeated = coordinator(entries, state, repeat_check).run()
            assert repeated["changed"] is False, controller.writes
            assert controller.writes == []
            assert len([call for call in controller.calls if call[1].endswith("Attachments/query")]) == 1


@pytest.mark.parametrize("resource", ["network", "vrf"])
@pytest.mark.parametrize("check", [False, True])
def test_merged_definition_only_does_not_discover_attachments(workflow, resource, check):
    controller, coordinator = workflow(resource)
    entry = _entry(resource, "EXISTING")
    _seed(controller, coordinator, entry)
    entry.pop("attach")
    result = coordinator([entry], check=check).run()
    assert result["changed"] is False
    assert all(not path.endswith(("Attachments/query", "/switches")) for _verb, path, _payload in controller.calls)
    assert controller.writes == []


@pytest.mark.parametrize("resource", ["network", "vrf"])
@pytest.mark.parametrize("topology", ["standalone", "group", "multicluster"])
@pytest.mark.parametrize("version", ["4.2.1.10", "4.3.1.135.51166"])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("mixed", [False, True])
def test_definition_only_creation_with_default_deploy(workflow, resource, topology, version, state, check, mixed):
    controller, coordinator = workflow(resource, topology, version)
    new = _entry(resource, "NEW")
    new.pop("attach")
    new.pop("deploy")
    entries = [new]
    if mixed:
        existing = _entry(resource, "EXISTING", 31002)
        _seed(controller, coordinator, existing)
        controller.attachments["EXISTING"]["attach"] = False
        existing.pop("attach")
        existing.pop("deploy")
        entries.insert(0, existing)
        if resource == "network" and state != "merged":
            controller.attachments["EXISTING"]["interfaces"] = []
        controller.attachments["EXISTING"]["extraConfig"] = ""
    before = deepcopy((controller.definitions, controller.attachments))
    result = coordinator(entries, state, check).run()
    assert result["changed"] is True
    assert controller.missing_queries == []
    if check:
        assert controller.writes == []
        assert (controller.definitions, controller.attachments) == before
    else:
        assert "NEW" in controller.definitions
        assert "NEW" not in controller.attachments
        controller.calls.clear()
        assert coordinator(entries, state).run()["changed"] is False
        assert controller.writes == []


@pytest.mark.parametrize("resource", ["network", "vrf"])
@pytest.mark.parametrize("topology", ["standalone", "group", "multicluster"])
@pytest.mark.parametrize("check", [False, True])
def test_mixed_preview_retains_existing_pending_deployment(workflow, resource, topology, check):
    controller, coordinator = workflow(resource, topology)
    existing = _entry(resource, "EXISTING")
    _seed(controller, coordinator, existing)
    controller.attachments["EXISTING"]["status"] = "pending"
    new = _entry(resource, "NEW", 31002)
    for entry in (existing, new):
        entry.pop("attach")
        entry.pop("deploy")
    result = coordinator([existing, new], check=check).run()
    assert result["changed"] is True
    assert controller.missing_queries == []
    expected = {controller.names: ["EXISTING"], "switchIds": ["SW1"]}
    if check:
        assert result["check_mode_deploy_payloads"] == [expected]
        assert controller.writes == []
    else:
        assert [body for _verb, path, body in controller.writes if path.endswith("Actions/deploy")] == [expected]
        controller.calls.clear()
        assert coordinator([existing, new]).run()["changed"] is False
        assert controller.writes == []


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("response", [{"switches": []}, {"items": []}, {"switches": None}, {}, []])
def test_empty_switch_inventory_reports_unresolved_ip_before_creation(workflow, check, response):
    controller, coordinator = workflow("network")
    controller.switch_response = response
    with pytest.raises(AssertionError, match="Could not resolve switchId"):
        coordinator([_entry("network", "NEW")], check=check).run()
    assert controller.definitions == {}
    assert controller.writes == []


@pytest.mark.parametrize("resource", ["network", "vrf"])
@pytest.mark.parametrize("check", [False, True])
def test_merged_creation_without_allocated_ids_does_not_guess_metadata(workflow, resource, check):
    controller, coordinator = workflow(resource)
    entry = _entry(resource, "NEW")
    entry.pop(resource + "_id")
    result = coordinator([entry], check=check).run()
    assert result["changed"] is True
    assert controller.missing_queries == []
    if check:
        assert controller.writes == []
        assert "vlanId" not in result["check_mode_attachment_payloads"][0]
    else:
        assert controller.definitions["NEW"][resource + "Id"] > 0
        assert controller.attachments["NEW"]["attach"] is True
        controller.calls.clear()
        assert coordinator([entry]).run()["changed"] is False
        assert controller.writes == []


@pytest.mark.parametrize("resource", ["network", "vrf"])
@pytest.mark.parametrize("check", [False, True])
def test_merged_creation_batches_new_attachment_metadata(workflow, resource, check):
    controller, coordinator = workflow(resource)
    entries = [_entry(resource, f"NEW{index}", 31000 + index) for index in range(31)]
    result = coordinator(entries, check=check).run()
    assert result["changed"] is True
    assert controller.missing_queries == []
    queries = [call for call in controller.calls if call[1].endswith("Attachments/query")]
    assert len(queries) == (0 if check else 1)
    assert sum(verb == "GET" and path.endswith("/" + controller.collection) for verb, path, _payload in controller.calls) == 1
    assert len(controller.definitions) == (0 if check else 31)


@pytest.mark.parametrize("resource", ["network", "vrf"])
@pytest.mark.parametrize("topology", ["standalone", "group", "multicluster"])
@pytest.mark.parametrize("check", [False, True])
def test_merged_sparse_attachment_update_preserves_cached_bindings(workflow, resource, topology, check):
    controller, coordinator = workflow(resource, topology)
    entry = _entry(resource, "EXISTING")
    _seed(controller, coordinator, entry)
    definitions, attachments = deepcopy((controller.definitions, controller.attachments))
    sparse = {
        resource + "_name": "EXISTING",
        "deploy": False,
        "attach": [
            {
                "ip_address": "192.0.2.10",
                **({"deploy": False, "attachment_options": {"svi_enabled": True}} if resource == "network" else {"freeform_config": ""}),
            }
        ],
    }
    result = coordinator([sparse], check=check).run()
    assert result["changed"] is True
    assert controller.definitions == definitions
    assert len([call for call in controller.calls if call[1].endswith("Attachments/query")]) == 1
    payloads = (
        result["check_mode_attachment_payloads"]
        if check
        else [row for _verb, path, body in controller.writes if path.endswith("Attachments") for row in body["attachments"]]
    )
    assert len(payloads) == 1
    if resource == "network":
        assert payloads[0]["interfaces"] == attachments["EXISTING"]["interfaces"]
        assert payloads[0]["vlanId"] == attachments["EXISTING"]["vlanId"]
    if check:
        assert controller.writes == []
        assert controller.attachments == attachments
    else:
        controller.calls.clear()
        assert coordinator([sparse]).run()["changed"] is False
        assert controller.writes == []


@pytest.mark.parametrize("topology", ["standalone", "group", "multicluster"])
@pytest.mark.parametrize("state", ["merged", "replaced"])
@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("operation", ["attach", "deploy"])
def test_missing_operational_network_is_not_created(workflow, topology, state, check, operation):
    controller, coordinator = workflow("network", topology)
    entry = {"network_name": "MISSING", "deploy": operation == "deploy"}
    if operation == "attach":
        entry["attach"] = [{"ip_address": "192.0.2.10", "deploy": False}]
    with pytest.raises(NDStateMachineError, match="must already exist"):
        coordinator([entry], state, check).run()
    assert controller.definitions == {}
    assert controller.writes == []
    assert controller.missing_queries == []


@pytest.mark.parametrize("shape", ["switches", "items", "list"])
@pytest.mark.parametrize("check", [False, True])
def test_network_switch_resolution_retains_supported_response_shapes(workflow, shape, check):
    controller, coordinator = workflow("network")
    rows = controller.switch_response["switches"]
    controller.switch_response = rows if shape == "list" else {shape: rows}
    assert coordinator([_entry("network", "NEW")], check=check).run()["changed"] is True
    assert controller.missing_queries == []


@pytest.mark.parametrize("resource", ["network", "vrf"])
@pytest.mark.parametrize("topology", ["standalone", "group", "multicluster"])
@pytest.mark.parametrize("state", ["merged", "replaced"])
def test_existing_unattached_vpc_metadata_is_preserved_for_preview(workflow, resource, topology, state):
    controller, coordinator = workflow(resource, topology)
    entry = _entry(resource, "EXISTING")
    _seed(controller, coordinator, entry)
    controller.attachments["EXISTING"].update(attach=False, peerSwitchId="SW2")
    if resource == "network":
        entry["attach"][0]["interfaces"] = [{"mode": "access", "interface_range": "Ethernet1/7"}]
    result = coordinator([entry], state, check=True).run()
    assert result["changed"] is True
    assert {row["switchId"] for row in result["check_mode_attachment_payloads"]} == {"SW1", "SW2"}
    if resource == "network":
        peer = next(row for row in result["check_mode_attachment_payloads"] if row["switchId"] == "SW2")
        assert peer["interfaces"] == []
    assert controller.writes == []
    assert len([call for call in controller.calls if call[1].endswith("Attachments/query")]) == 1


@pytest.mark.parametrize("resource", ["network", "vrf"])
@pytest.mark.parametrize("status", [400, 403])
def test_new_attachment_metadata_errors_are_not_swallowed(workflow, resource, status):
    controller, coordinator = workflow(resource)
    controller.query_error = status
    with pytest.raises(Exception, match="attachment metadata unavailable"):
        coordinator([_entry(resource, "NEW")]).run()
    assert "NEW" in controller.definitions
    assert controller.attachments == {}
    assert len(controller.writes) == 1
    assert controller.writes[0][1].endswith("/" + controller.collection)
