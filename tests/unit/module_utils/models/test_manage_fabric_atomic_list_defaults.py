# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Fabric merged-list comparisons include the item defaults their payload sends."""

from __future__ import annotations

from copy import deepcopy
from typing import Annotated, ClassVar

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    FabricAiIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    KeychainKeyEntryModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import (
    FabricIbgpModel,
    VxlanIbgpManagementModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.release_metadata import (
    NDMinimumVersion,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ibgp_vxlan import (
    ManageAiIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ibgp_vxlan import (
    ManageIbgpFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import (
    MockAnsibleModule,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import (
    ResponseGenerator,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

FAMILIES = (
    pytest.param(FabricIbgpModel, ManageIbgpFabricOrchestrator, "vxlanIbgp", id="ibgp"),
    pytest.param(
        FabricAiIbgpVxlanModel,
        ManageAiIbgpVxlanFabricOrchestrator,
        "aimlVxlanIbgp",
        id="ai-ibgp",
    ),
)
NETFLOW_CASES = (
    pytest.param(
        "netflow_exporter_collection",
        "netflowExporterCollection",
        {
            "exporter_name": "exporterA",
            "exporter_ip": "192.0.2.10",
            "source_interface_name": "loopback0",
        },
        {
            "exporterName": "exporterA",
            "exporterIp": "192.0.2.10",
            "sourceInterfaceName": "loopback0",
            "vrf": "management",
        },
        "vrf",
        "vrf",
        "management",
        "auditVrf",
        id="exporter-vrf",
    ),
    pytest.param(
        "netflow_record_collection",
        "netflowRecordCollection",
        {"record_name": "recordA", "record_template": "netflowIpv4Record"},
        {
            "recordName": "recordA",
            "recordTemplate": "netflowIpv4Record",
            "layer2Record": False,
        },
        "layer2_record",
        "layer2Record",
        False,
        True,
        id="record-layer2",
    ),
    pytest.param(
        "netflow_monitor_collection",
        "netflowMonitorCollection",
        {
            "monitor_name": "monitorA",
            "record_name": "recordA",
            "exporter1_name": "exporterA",
        },
        {
            "monitorName": "monitorA",
            "recordName": "recordA",
            "exporter1Name": "exporterA",
            "exporter2Name": "",
        },
        "exporter2_name",
        "exporter2Name",
        "",
        "exporterB",
        id="monitor-exporter2",
    ),
)


def _rest(version, state):
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(iter(()))
    rest = RestSend({"check_mode": False, "state": state})
    rest.sender = sender
    rest.response_handler = ResponseHandler()
    rest.unit_test = True
    rest.controller_product_version = version
    return rest


def _backend(fabric_type, netflow=None, management=None):
    return {
        "response": {
            "name": "fabric1",
            "category": "fabric",
            "licenseTier": "essentials",
            "management": {
                "type": fabric_type,
                "bgpAsn": "65001",
                **({"netflowSettings": netflow} if netflow is not None else {}),
                **(management or {}),
            },
        },
        "updates": [],
    }


def _run(orchestrator, backend, version, management, state="merged"):
    class RecordingOrchestrator(orchestrator):
        def query_all(self, **kwargs):
            return [deepcopy(backend["response"])]

        def update(self, model_instance, **kwargs):
            payload = model_instance.to_payload()
            backend["updates"].append(deepcopy(payload))
            backend["response"] = deepcopy(payload)
            return {}

    module = MockAnsibleModule()
    module.no_log_values = set()
    module.params = {
        "state": state,
        "config": [{"fabric_name": "fabric1", "management": {"bgp_asn": "65001", **management}}],
        "output_level": "normal",
        "ignore_errors": False,
        "config_actions": {"save": False, "deploy": False},
    }
    machine = NDStateMachine(
        module=module,
        model_orchestrator=RecordingOrchestrator(rest_send=_rest(version, state)),
    )
    machine.manage_state()
    return machine


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize(
    "field,wire,config_item,response_item,leaf,wire_leaf,default,nondefault",
    NETFLOW_CASES,
)
def test_omitted_netflow_item_default_is_idempotent(
    model,
    orchestrator,
    fabric_type,
    version,
    field,
    wire,
    config_item,
    response_item,
    leaf,
    wire_leaf,
    default,
    nondefault,
):
    """A perfect controller echo with an item default must not cause a PUT."""
    backend = _backend(fabric_type, {"netflow": True, wire: [deepcopy(response_item)]})
    machine = _run(
        orchestrator,
        backend,
        version,
        {"netflow_settings": {"netflow": True, field: [deepcopy(config_item)]}},
    )
    assert machine.output.format()["changed"] is False
    assert backend["updates"] == []
    proposed = next(iter(machine.proposed))
    assert proposed.to_diff_dict(exclude_unset=True)["management"]["netflowSettings"][wire][0][wire_leaf] == default
    assert leaf not in getattr(proposed.management.netflow_settings, field)[0].model_fields_set


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("reset", ("omit-default", "explicit-default"))
@pytest.mark.parametrize(
    "field,wire,config_item,response_item,leaf,wire_leaf,default,nondefault",
    NETFLOW_CASES,
)
def test_supplied_list_changes_and_resets_item_default_once(
    model,
    orchestrator,
    fabric_type,
    version,
    reset,
    field,
    wire,
    config_item,
    response_item,
    leaf,
    wire_leaf,
    default,
    nondefault,
):
    """A supplied atomic list sends its defaults; omission of the list preserves it."""
    backend = _backend(fabric_type, {"netflow": True, wire: [deepcopy(response_item)]})
    changed_item = {**config_item, leaf: nondefault}
    changed = {"netflow_settings": {"netflow": True, field: [changed_item]}}
    assert _run(orchestrator, backend, version, changed).output.format()["changed"] is True
    assert backend["response"]["management"]["netflowSettings"][wire][0][wire_leaf] == nondefault
    assert _run(orchestrator, backend, version, changed).output.format()["changed"] is False
    assert _run(orchestrator, backend, version, {}).output.format()["changed"] is False
    assert backend["response"]["management"]["netflowSettings"][wire][0][wire_leaf] == nondefault
    reset_item = {
        **config_item,
        **({leaf: default} if reset == "explicit-default" else {}),
    }
    reset_config = {"netflow_settings": {"netflow": True, field: [reset_item]}}
    assert _run(orchestrator, backend, version, reset_config).output.format()["changed"] is True
    assert backend["response"]["management"]["netflowSettings"][wire][0][wire_leaf] == default
    assert _run(orchestrator, backend, version, reset_config).output.format()["changed"] is False
    assert len(backend["updates"]) == 2


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize(
    "field,wire",
    (("isis_keys", "isisKeys"), ("ospf_keys", "ospfKeys"), ("pim_keys", "pimKeys")),
)
def test_keychain_item_defaults_are_compared_without_revealing_secrets(model, orchestrator, fabric_type, field, wire):
    """Nested key defaults match while comparison data keeps key material masked."""
    item = {"key_id": 1, "key_string": "synthetic-input-key"}
    echoed = {
        "keyId": 1,
        "keyType": "7",
        "keyString": "synthetic-encrypted-key",
        "acceptLifetimeLocal": False,
        "sendLifetimeLocal": False,
    }
    backend = _backend(fabric_type, management={wire: [echoed]})
    machine = _run(orchestrator, backend, "4.3.1", {field: [item]})
    assert machine.output.format()["changed"] is False
    assert backend["updates"] == []
    proposed = next(iter(machine.proposed))
    dumped = proposed.to_diff_dict(exclude_unset=True)["management"][wire][0]
    assert dumped["keyType"] == "7"
    assert dumped["acceptLifetimeLocal"] is False
    assert dumped["sendLifetimeLocal"] is False
    assert dumped["keyString"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    assert "synthetic-input-key" not in str(proposed.to_diff_dict(exclude_unset=True))


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("field", ("isis_keys", "ospf_keys", "pim_keys"))
def test_populated_typed_list_parent_gate_still_rejects_older_controller(model, orchestrator, fabric_type, field):
    """Completing item defaults cannot bypass an unsupported collection's parent gate."""
    backend = _backend(fabric_type)
    with pytest.raises(NDStateMachineError, match="requires ND 4.3.1"):
        _run(
            orchestrator,
            backend,
            "4.2.1",
            {field: [{"key_id": 1, "key_string": "synthetic-input-key"}]},
        )
    assert backend["updates"] == []


@pytest.mark.parametrize("model,orchestrator,fabric_type", FAMILIES)
@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
def test_gathered_typed_lists_round_trip_through_ansible_argument_spec(model, orchestrator, fabric_type, version):
    """Public gathered defaults replay unchanged through Ansible and the real state machine."""
    response = _backend(
        fabric_type,
        {
            "netflow": True,
            "netflowMonitorCollection": [
                {
                    "monitorName": "monitorA",
                    "recordName": "recordA",
                    "exporter1Name": "exporterA",
                    "exporter2Name": "",
                }
            ],
        },
    )["response"]
    gathered = model.from_response(response).to_gathered_config()
    validator = ModuleArgumentSpecValidator(model.get_argument_spec()).validate({"state": "merged", "config": [gathered]})
    assert validator.error_messages == []
    assert not validator.unsupported_parameters
    replayed = model.from_config(validator.validated_parameters["config"][0])
    assert model.from_response(response).get_diff(replayed, exclude_unset=True)
    backend = {"response": response, "updates": []}
    assert _run(orchestrator, backend, version, gathered["management"]).output.format()["changed"] is False
    assert backend["updates"] == []


def test_outside_typed_lists_suppliedness_primitive_and_opaque_values_are_unchanged():
    """The fix never fills omitted scalars, whole lists, primitive lists or free-form dictionaries."""
    model = FabricIbgpModel.from_config(
        {
            "fabric_name": "fabric1",
            "management": {
                "bgp_asn": "65001",
                "ntp_server_collection": ["ntp.example.invalid"],
            },
            "external_streaming_settings": {"email": [{"name": "audit", "settings": {"enabled": True}}]},
        }
    )
    dump = model.to_diff_dict(exclude_unset=True)
    assert "fabricMtu" not in dump["management"]
    assert "netflowSettings" not in dump["management"]
    assert "isisKeys" not in dump["management"]
    assert dump["management"]["ntpServerCollection"] == ["ntp.example.invalid"]
    assert dump["externalStreamingSettings"] == {"email": [{"name": "audit", "settings": {"enabled": True}}]}


def test_future_item_default_remains_excluded_from_older_release_payload():
    """Comparison completion must not restore a future item value cleared by release preflight."""

    class FutureKey(KeychainKeyEntryModel):
        future_flag: Annotated[bool | None, NDMinimumVersion("4.4.1")] = Field(alias="futureFlag", default=False)

    class FutureManagement(VxlanIbgpManagementModel):
        isis_keys: Annotated[list[FutureKey] | None, NDMinimumVersion("4.3.1")] = Field(alias="isisKeys", default=None)

    class FutureFabric(FabricIbgpModel):
        management: FutureManagement | None = None

    class FutureOrchestrator(ManageIbgpFabricOrchestrator):
        model_class: ClassVar[type[NDBaseModel]] = FutureFabric

    backend = _backend(
        "vxlanIbgp",
        management={
            "isisKeys": [
                {
                    "keyId": 1,
                    "keyString": "synthetic-encrypted-key",
                    "keyType": "7",
                    "acceptLifetimeLocal": False,
                    "sendLifetimeLocal": False,
                }
            ]
        },
    )
    machine = _run(
        FutureOrchestrator,
        backend,
        "4.3.1",
        {"isis_keys": [{"key_id": 1, "key_string": "synthetic-input-key"}]},
    )
    assert machine.output.format()["changed"] is False
    proposed = next(iter(machine.proposed))
    assert "futureFlag" not in proposed.to_payload()["management"]["isisKeys"][0]
    assert proposed.management.isis_keys[0].future_flag is None
    assert "future_flag" not in proposed.management.isis_keys[0].model_fields_set
    assert backend["updates"] == []
    with pytest.raises(NDStateMachineError, match="requires ND 4.4.1"):
        _run(
            FutureOrchestrator,
            backend,
            "4.3.1",
            {
                "isis_keys": [
                    {
                        "key_id": 1,
                        "key_string": "synthetic-input-key",
                        "future_flag": False,
                    }
                ]
            },
        )
    assert backend["updates"] == []
