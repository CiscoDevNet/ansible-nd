# -*- coding: utf-8 -*-

"""Unit tests for network config and payload orchestration."""

from __future__ import annotations

import pytest

from types import SimpleNamespace
from unittest.mock import patch
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import (
    NETWORK_DEFINITION_INTENT_FIELDS,
    NetworkConfigModel,
    NetworkParentConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.enums import (
    ConfigurationStatus,
    VlanNetworkType,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import (
    network_base_argument_spec,
    network_module_argument_spec,
    network_parent_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_attachment_manager import (
    NetworkAttachmentManager,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_config_utils import (
    network_name_filter,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.networks import (
    NDNetworkOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_workflow_coordinator import (
    NetworkWorkflowCoordinator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators import network_workflow_coordinator as coordinator_mod
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_state_machine import (
    NetworkStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.staged_state_helpers import crud_module_args
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import (
    StandaloneNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.child_network import (
    ChildNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_network import (
    MulticlusterParentNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_network import (
    MultisiteParentNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError


class _Module:
    def __init__(self, params):
        self.params = params
        self.check_mode = False
        self._verbosity = 3

    def fail_json(self, **kwargs):
        raise AssertionError(kwargs)


class _NetworkAttachmentCoordinator:
    def __init__(self):
        self.traces = []

    def _trace(self, event, **details):
        self.traces.append((event, details))


class _RecordingNetworkAttachmentManager(NetworkAttachmentManager):
    def __init__(self, coordinator):
        super().__init__(coordinator)
        self.posts = []

    def post_network_attachments(self, _module_args, _strategy, payloads, deploy_targets, operation_type):
        self.posts.append((payloads, deploy_targets, operation_type))
        return {"changed": True, "payloads": payloads, "deploy_targets": deploy_targets}


class _ParentStrategy:
    config_model_cls = NetworkParentConfigModel
    fabric_data = {"members": [{"fabricName": "child1"}]}
    fabric_name = "msd_p"

    @property
    def fabric_type(self):
        return "multisite_parent"

    @property
    def is_child(self):
        return False

    @property
    def is_parent(self):
        return True

    @property
    def is_multicluster(self):
        return False

    def child_fabric_members(self):
        return ["child1"]

    def get_argument_spec(self):
        return network_parent_argument_spec()

    def build_child_task_args(self, child_fabric_name, network_configs, state):
        return {
            "fabric_name": child_fabric_name,
            "state": state,
            "config": network_configs,
        }


class _FakeStateMachine:
    existing = []

    def __init__(self, calls, existing=None):
        self.calls = calls
        self.existing = existing or []
        self.state = None

    def manage_state(self):
        self.calls.append(("manage_state", self.state))


class _MergedNetworkCoordinatorStub:
    """Adapt focused merged-flow doubles to the single pre-CRUD inventory query."""

    def _new_state_machine(self, module_args, strategy):
        coordinator = self

        class StateMachine:
            before = {"BLUE_NET": object()}

            def manage_state(self):
                self.result = coordinator._run_state_machine(module_args, strategy)

        return StateMachine(), None, None

    @staticmethod
    def _configured_network_names(config):
        return [item["network_name"] for item in config]

    @staticmethod
    def _current_attachment_details_ignore_missing(*_args):
        return []

    @staticmethod
    def _attachment_map_from_details(*_args):
        return {}

    @staticmethod
    def _preflight_fabric_features(*_args, **_kwargs):
        pass

    @staticmethod
    def _format_state_machine_output(sm):
        return sm.result

    @staticmethod
    def _restore_state_machine_params(*_args):
        pass


class _ExistingNetwork:
    def __init__(self, network_name):
        self.network_name = network_name


class _ReplacedNetworkCoordinator:
    def __init__(self):
        self.module = _Module({"state": "replaced"})
        self.calls = []
        self.state_machine = _FakeStateMachine(self.calls)
        self.post_attachment_details = [
            {
                "networkName": "BLUE_NET",
                "switchId": "SW1",
                "peerSwitchId": "SW2",
                "attach": False,
            },
            {
                "networkName": "BLUE_NET",
                "switchId": "SW2",
                "peerSwitchId": "SW1",
                "attach": False,
            },
        ]

    @staticmethod
    def _desired_attachment_map(_module_args, _strategy):
        return {("BLUE_NET", "SW1"): {"networkName": "BLUE_NET", "switchId": "SW1", "attach": True}}

    @staticmethod
    def _configured_network_names(_config):
        return ["BLUE_NET"]

    @staticmethod
    def _deploy_enabled_by_network(_config):
        return {"BLUE_NET": True}

    def _new_state_machine(self, module_args, _strategy):
        self.state_machine.state = module_args["state"]
        self.calls.append(("new_state_machine",))
        return self.state_machine, "original-config", "original-state"

    @staticmethod
    def _preflight_fabric_features(*_args, **_kwargs):
        pass

    def _current_attachment_details_ignore_missing(self, *_args, **_kwargs):
        raise AssertionError("first-create replaced must not query missing Network attachments")

    @staticmethod
    def _attachment_map_from_details(attachments, network_names=None):
        return NetworkAttachmentManager.attachment_map_from_details(attachments, network_names)

    def _current_attachment_details(self, _module_args, _strategy, network_names):
        self.calls.append(("post_query", network_names))
        return list(self.post_attachment_details)

    def _apply_attachment_phase(
        self,
        _module_args,
        _strategy,
        phase,
        desired=None,
        current_network_names=None,
        current=None,
        attachment_details=None,
    ):
        self.calls.append((phase, current_network_names, current, attachment_details))
        if phase == "pre":
            assert current_network_names == []
            assert current == {}
            assert attachment_details == []
            return {"current": current, "payloads": [], "desired": desired, "deploy_targets": {}}
        assert phase == "post"
        assert current_network_names == ["BLUE_NET"]
        assert current == {}
        assert attachment_details == self.post_attachment_details
        desired = NetworkAttachmentManager.expand_desired_attachments_with_vpc_peers(desired, attachment_details)
        return {
            "payloads": [desired[("BLUE_NET", "SW1")], desired[("BLUE_NET", "SW2")]],
            "deploy_targets": {"BLUE_NET": {"SW1", "SW2"}},
        }

    @staticmethod
    def _attachment_map_after_detach(current, _payloads):
        return current

    @staticmethod
    def _format_state_machine_output(_state_machine):
        return {"changed": True, "failed": False, "after": [{"network_name": "BLUE_NET"}]}

    @staticmethod
    def _merge_api_trace(result, trace, prepend=False):
        if prepend:
            result.setdefault("prepended", []).append(trace)
        if trace.get("changed"):
            result["changed"] = True

    @staticmethod
    def _build_deploy_payloads(_config, *_target_maps):
        return []

    @staticmethod
    def _build_pending_network_deploy_payloads(_result, _config, _module_args, _strategy):
        return []

    def _restore_state_machine_params(self, original_config, original_state):
        self.calls.append(("restore", original_config, original_state))

    def _trace(self, event, **_details):
        self.calls.append(("trace", event))


class _StagedNetworkCoordinator:
    def __init__(self):
        self.module = _Module({"state": "staged"})
        self.calls = []
        self.state_machine = _FakeStateMachine(self.calls, existing=[_ExistingNetwork("BLUE_NET"), _ExistingNetwork("OMIT_NET")])
        self.current_attachment_details = [
            {"networkName": "BLUE_NET", "switchId": "SERIAL1", "attach": True},
            {"networkName": "BLUE_NET", "switchId": "SERIAL2", "attach": True},
            {"networkName": "OMIT_NET", "switchId": "SERIAL3", "attach": True},
        ]

    @staticmethod
    def _desired_attachment_map(_module_args, _strategy):
        return {("BLUE_NET", "SERIAL1"): {"networkName": "BLUE_NET", "switchId": "SERIAL1", "attach": True}}

    @staticmethod
    def _configured_network_names(config):
        return [network["network_name"] for network in config]

    @staticmethod
    def _deploy_enabled_by_network(config):
        return {network["network_name"]: network.get("deploy", True) for network in config}

    def _new_state_machine(self, module_args, _strategy):
        self.state_machine.state = module_args["state"]
        self.calls.append(("new_state_machine", module_args["state"], list(module_args.get("config") or [])))
        return self.state_machine, "original-config", "original-state"

    @staticmethod
    def _preflight_fabric_features(*_args, **_kwargs):
        pass

    def _current_attachment_details_ignore_missing(self, _module_args, _strategy, network_names):
        self.calls.append(("attachment_query", network_names))
        return list(self.current_attachment_details)

    @staticmethod
    def _attachment_map_from_details(attachments, network_names=None):
        return NetworkAttachmentManager.attachment_map_from_details(attachments, network_names)

    @staticmethod
    def _filter_attachment_details_by_network(attachments, network_names):
        return NetworkAttachmentManager.filter_attachment_details_by_network(attachments, network_names)

    def _ensure_networks_have_no_networks(self, _module_args, _strategy, network_names):
        raise AssertionError(f"staged must not run Network deletion dependency checks: {network_names}")

    def _apply_deleted_attachment_phase(self, _module_args, _strategy, network_names, attachment_details=None):
        self.calls.append(("omitted_detach", network_names, attachment_details))
        return {"changed": True, "payloads": [{"networkName": network_names[0], "switchId": "SERIAL3", "attach": False}], "deploy_targets": {}}

    def _apply_attachment_phase(
        self,
        module_args,
        _strategy,
        phase,
        desired=None,
        current_network_names=None,
        current=None,
        attachment_details=None,
    ):
        self.calls.append(("attachment_phase", phase, module_args["state"], current_network_names, current, attachment_details))
        if phase == "pre":
            return {
                "changed": True,
                "payloads": NetworkAttachmentManager(self).planned_detach_payloads(
                    module_args["state"],
                    module_args.get("config") or [],
                    current,
                    desired,
                ),
                "current": current,
                "desired": desired,
                "deploy_targets": {},
            }
        return {"changed": False, "payloads": [], "current": current, "desired": desired, "deploy_targets": {}}

    @staticmethod
    def _attachment_map_after_detach(current, payloads):
        return NetworkAttachmentManager.attachment_map_after_detach(current, payloads)

    @staticmethod
    def _format_state_machine_output(_state_machine):
        return {"changed": True, "failed": False, "after": [{"network_name": "BLUE_NET"}]}

    @staticmethod
    def _merge_api_trace(result, trace, prepend=False):
        if prepend:
            result.setdefault("prepended", []).append(trace)
        if trace.get("changed"):
            result["changed"] = True

    @staticmethod
    def _build_delete_deploy_payloads(_config, *_target_maps):
        raise AssertionError("staged must not build delete deploy payloads")

    @staticmethod
    def _build_deploy_payloads(_config, *_target_maps):
        raise AssertionError("staged must not build deploy payloads")

    @staticmethod
    def _build_pending_network_deploy_payloads(_result, _config, _module_args, _strategy):
        raise AssertionError("staged must not build pending deploy payloads")

    def _query_current_networks_with_trace(self, *_args):
        raise AssertionError("staged test should not need the fallback pending Network query")

    def _wait_for_network_attachments_delete_ready(self, _module_args, _strategy, network_names):
        raise AssertionError(f"staged must not wait for attachment delete readiness: {network_names}")

    def _wait_for_networks_delete_ready(self, _module_args, _strategy, network_names):
        raise AssertionError(f"staged must not wait for Network delete readiness: {network_names}")

    def _restore_state_machine_params(self, original_config, original_state):
        self.calls.append(("restore", original_config, original_state))

    def _trace(self, event, **_details):
        self.calls.append(("trace", event))


def _orchestrator():
    strategy = StandaloneNetworkStrategy(
        fabric_name="fab1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    return NDNetworkOrchestrator(
        rest_send=RestSend({"state": "merged", "config": [], "check_mode": False}),
        strategy=strategy,
    )


def _validated_network_config(config):
    validator = ArgumentSpecValidator({"config": {"type": "list", "elements": "dict", "options": network_module_argument_spec()}})
    result = validator.validate({"config": config})
    assert not result.error_messages
    return result.validated_parameters["config"]


def test_network_payload_model_defaults_exposed_false_flags_for_standalone_vxlan():
    orchestrator = _orchestrator()

    payload_data = orchestrator._transform_config_to_payload_model_data(
        {
            "network_name": "BLUE_NET",
            "layer": "layer3",
            "network_id": 30001,
            "vlan_id": 2301,
            "vrf_name": "BLUE_VRF",
        },
        "fab1",
    )

    model = orchestrator.model_class.from_config(payload_data)
    payload = orchestrator._create_or_update_payload(model)
    assert payload["l2Data"]["xConnect"] is False
    assert payload["l3Data"]["fabricData"]["gatewayOnBorder"] is False
    assert payload["l3Data"]["fabricData"]["ipv4Trm"] is False
    assert payload["l3Data"]["fabricData"]["ipv6Trm"] is False


def test_network_attachment_manager_staged_detaches_like_overridden():
    manager = NetworkAttachmentManager(coordinator=object())
    current = {
        ("BLUE_NET", "SERIAL1"): {"networkName": "BLUE_NET", "switchId": "SERIAL1", "attach": True},
        ("BLUE_NET", "SERIAL2"): {"networkName": "BLUE_NET", "switchId": "SERIAL2", "attach": True},
    }
    desired = {("BLUE_NET", "SERIAL1"): {"networkName": "BLUE_NET", "switchId": "SERIAL1", "attach": True}}

    assert manager.planned_detach_payloads("staged", [{"network_name": "BLUE_NET"}], current, desired) == [
        {"networkName": "BLUE_NET", "switchId": "SERIAL2", "attach": False}
    ]


def test_network_attachment_manager_staged_pre_phase_posts_detach():
    coordinator = _NetworkAttachmentCoordinator()
    manager = _RecordingNetworkAttachmentManager(coordinator)

    trace = manager.apply_phase(
        {"state": "staged", "config": [{"network_name": "BLUE_NET"}]},
        StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"}),
        phase="pre",
        desired={},
        current_network_names=["BLUE_NET"],
        current={("BLUE_NET", "SERIAL1"): {"networkName": "BLUE_NET", "switchId": "SERIAL1", "attach": True, "vlanId": 100}},
        attachment_details=[{"networkName": "BLUE_NET", "switchId": "SERIAL1", "attach": True, "vlanId": 100}],
    )

    assert trace["payloads"] == [{"networkName": "BLUE_NET", "switchId": "SERIAL1", "vlanId": 100, "attach": False}]
    assert manager.posts[0][0] == trace["payloads"]
    assert ("network_attachment_phase_skip", {"phase": "pre", "reason": "state_not_pre_detach"}) not in coordinator.traces


def test_network_attachment_manager_staged_post_phase_posts_attach():
    coordinator = _NetworkAttachmentCoordinator()
    manager = _RecordingNetworkAttachmentManager(coordinator)
    desired = {
        ("BLUE_NET", "SERIAL1"): {
            "networkName": "BLUE_NET",
            "switchId": "SERIAL1",
            "interfaces": [{"interfaceRange": "Ethernet1/1", "mode": "trunk"}],
            "attach": True,
        }
    }

    trace = manager.apply_phase(
        {"state": "staged", "config": [{"network_name": "BLUE_NET", "attach": [{"switch_id": "SERIAL1"}]}]},
        StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"}),
        phase="post",
        desired=desired,
        current_network_names=["BLUE_NET"],
        current={},
        attachment_details=[{"networkName": "BLUE_NET", "switchId": "SERIAL1", "attach": False}],
    )

    assert trace["payloads"] == [desired[("BLUE_NET", "SERIAL1")]]
    assert manager.posts[0][0] == trace["payloads"]
    assert ("network_attachment_phase_skip", {"phase": "post", "reason": "state_not_post_attach"}) not in coordinator.traces


def test_network_staged_detaches_omitted_networks_without_running_overridden_crud_delete():
    coordinator = _StagedNetworkCoordinator()
    state_machine = NetworkStateMachine(coordinator)

    config = [{"network_name": "BLUE_NET", "attach": [{"switch_id": "SERIAL1"}]}]

    result = state_machine.run(
        {"state": "staged", "config": config}, StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    )

    assert result["changed"] is True
    assert coordinator.calls.count(("new_state_machine", "staged", config)) == 1
    assert not any(call[0] == "new_state_machine" and call[1] == "overridden" for call in coordinator.calls)
    assert not any(call[0] == "new_state_machine" and call[1] == "replaced" for call in coordinator.calls)
    assert ("manage_state", "replaced") in coordinator.calls
    assert ("attachment_query", ["BLUE_NET", "OMIT_NET"]) in coordinator.calls
    assert (
        "omitted_detach",
        ["OMIT_NET"],
        [{"networkName": "OMIT_NET", "switchId": "SERIAL3", "attach": True}],
    ) in coordinator.calls


def test_network_replaced_first_create_with_attachment_skips_missing_pre_query():
    """
    # Summary

    Verify first-create state=replaced does not query attachments for a Network
    that is absent before CRUD creation.
    """
    coordinator = _ReplacedNetworkCoordinator()
    state_machine = NetworkStateMachine(coordinator)

    result = state_machine.run(
        {
            "state": "replaced",
            "config": [
                {
                    "network_name": "BLUE_NET",
                    "attach": [
                        {
                            "ip_address": "192.0.2.10",
                            "interfaces": [{"interface_range": "Ethernet1/1", "mode": "trunk"}],
                        }
                    ],
                }
            ],
        },
        StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"}),
    )

    assert result["changed"] is True
    assert ("pre", [], {}, []) in coordinator.calls
    assert ("manage_state", "replaced") in coordinator.calls
    assert ("post_query", ["BLUE_NET"]) in coordinator.calls
    assert ("post", ["BLUE_NET"], {}, coordinator.post_attachment_details) in coordinator.calls


@pytest.mark.parametrize("check_mode", [False, True])
def test_network_feature_preflight_rejects_before_replaced_attachment_or_crud(check_mode):
    coordinator = _ReplacedNetworkCoordinator()
    coordinator.module.check_mode = check_mode

    def reject_feature(*_args, **_kwargs):
        raise ValueError("fabric feature disabled")

    coordinator._preflight_fabric_features = reject_feature

    with pytest.raises(ValueError, match="fabric feature disabled"):
        NetworkStateMachine(coordinator).run(
            {"state": "replaced", "config": [{"network_name": "BLUE_NET", "attach": [{"switch_id": "SW1"}]}]},
            StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"}),
        )

    assert not any(call[0] in ("pre", "post", "manage_state") for call in coordinator.calls)


def test_network_attachment_manager_expands_desired_vpc_peer_with_empty_interfaces():
    desired = {
        ("BLUE_NET", "SW1"): {
            "networkName": "BLUE_NET",
            "switchId": "SW1",
            "vlanId": 3001,
            "interfaces": [{"interfaceRange": "Ethernet1/29", "mode": "trunk"}],
            "attach": True,
        },
        ("BLUE_NET", "SW3"): {
            "networkName": "BLUE_NET",
            "switchId": "SW3",
            "vlanId": 3001,
            "interfaces": [{"interfaceRange": "Ethernet1/29", "mode": "trunk"}],
            "attach": True,
        },
    }
    attachment_details = [
        {"networkName": "BLUE_NET", "switchId": "SW1", "peerSwitchId": "SW2", "attach": False},
        {"networkName": "BLUE_NET", "switchId": "SW2", "peerSwitchId": "SW1", "attach": False},
        {"networkName": "BLUE_NET", "switchId": "SW3", "attach": False},
    ]

    expanded = NetworkAttachmentManager.expand_desired_attachments_with_vpc_peers(desired, attachment_details)

    assert sorted(expanded) == [
        ("BLUE_NET", "SW1"),
        ("BLUE_NET", "SW2"),
        ("BLUE_NET", "SW3"),
    ]
    assert expanded[("BLUE_NET", "SW2")] == {
        "networkName": "BLUE_NET",
        "switchId": "SW2",
        "vlanId": 3001,
        "interfaces": [],
        "attach": True,
    }


def test_network_attachment_replaced_pre_phase_keeps_controller_added_vpc_peer():
    class Module:
        check_mode = False

    class Coordinator:
        module = Module()

        def __init__(self):
            self.posted_payloads = []

        @staticmethod
        def _new_network_orchestrator(_module_args, _strategy):
            raise AssertionError("idempotent pre-phase must not post attachments")

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    current = {
        ("BLUE_NET", "SW1"): {"networkName": "BLUE_NET", "switchId": "SW1", "peerSwitchId": "SW2", "attach": True},
        ("BLUE_NET", "SW2"): {"networkName": "BLUE_NET", "switchId": "SW2", "peerSwitchId": "SW1", "attach": True},
        ("BLUE_NET", "SW3"): {"networkName": "BLUE_NET", "switchId": "SW3", "attach": True},
    }
    desired = {
        ("BLUE_NET", "SW1"): {"networkName": "BLUE_NET", "switchId": "SW1", "attach": True},
        ("BLUE_NET", "SW3"): {"networkName": "BLUE_NET", "switchId": "SW3", "attach": True},
    }
    attachment_details = list(current.values())

    trace = manager.apply_phase(
        {
            "state": "replaced",
            "config": [{"network_name": "BLUE_NET"}],
        },
        StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"}),
        phase="pre",
        desired=desired,
        current_network_names=["BLUE_NET"],
        current=current,
        attachment_details=attachment_details,
    )

    assert trace == {"current": current}


def test_network_workflow_coordinator_resolves_strategy_with_gen3_restsend():
    events = []
    module = _Module({"fabric_name": "fab1", "state": "gathered", "config": []})
    module.check_mode = True

    class FakeResolver:
        def __init__(self, rest_send, fabric_name):
            events.append(("NetworkFabricResolver", rest_send, fabric_name))
            self.workflow_trace = [{"event": "fabric_resolver_start"}]

        def resolve(self):
            events.append(("resolve",))
            return StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})

    with patch.object(coordinator_mod, "NetworkFabricResolver", FakeResolver):
        coordinator = NetworkWorkflowCoordinator(module=module)
        strategy = coordinator._resolve_strategy(dict(module.params))

    resolver_rest_send = events[0][1]
    assert strategy.fabric_type == "standalone"
    assert resolver_rest_send.params["check_mode"] is False
    assert resolver_rest_send.timeout == 1
    assert resolver_rest_send.send_interval == 1
    assert events == [("NetworkFabricResolver", resolver_rest_send, "fab1"), ("resolve",)]
    assert coordinator.workflow_trace[0]["event"] == "fabric_resolver_start"


def _mcfg_parent_orchestrator():
    strategy = MulticlusterParentNetworkStrategy(
        fabric_name="MCFG_FAB",
        fabric_data={
            "managementType": "vxlan",
            "onemanageProxyPath": "/onemanage",
            "manageFabricDetails": {
                "management": {
                    "networkTemplate": "Default_Network_Universal",
                    "networkExtensionTemplate": "Default_Network_Extension_Universal",
                }
            },
        },
    )
    return NDNetworkOrchestrator(
        rest_send=RestSend({"state": "merged", "config": [], "check_mode": False}),
        strategy=strategy,
    )


def test_network_config_model_defaults_missing_attachment_interfaces_to_empty_list():
    model = NetworkConfigModel.from_config(
        {
            "network_name": "BLUE_NET",
            "layer": "layer2",
            "vlan_id": 2301,
            "attach": [
                {
                    "ip_address": "10.1.1.11",
                }
            ],
        }
    )

    assert model.to_config()["attach"][0]["interfaces"] == []


def test_network_parent_child_task_args_use_merged_for_mutating_partial_child_overrides():
    """
    # Summary

    Verify generated child tasks use merged semantics for parent mutating
    states because child_fabric_config carries partial per-child overrides, not
    full child Network definitions.
    """
    strategy = MulticlusterParentNetworkStrategy(
        fabric_name="MCFG_R",
        fabric_data={"members": [{"fabricName": "AK-VXLAN", "clusterName": "ND42-REL"}]},
    )

    for state in ("merged", "replaced", "overridden"):
        args = strategy.build_child_task_args(
            child_fabric_name="AK-VXLAN",
            network_configs=[{"network_name": "BLUE_NET", "multicast_group_address": "239.1.1.10"}],
            state=state,
        )
        assert args["state"] == "merged"

    args = strategy.build_child_task_args(
        child_fabric_name="AK-VXLAN",
        network_configs=[{"network_name": "BLUE_NET"}],
        state="gathered",
    )
    assert args["state"] == "gathered"


def test_network_parent_argument_spec_includes_child_config():
    spec = network_parent_argument_spec()
    child_spec = spec["child_fabric_config"]["options"]

    assert "child_fabric_config" in spec
    assert spec["attach"]["options"]["interfaces"]["options"]["mode"]["choices"]
    assert spec["attach"]["options"]["interfaces"]["options"]["mode"]["required"] is True
    assert spec["attach"]["options"]["interfaces"]["options"]["interface_range"]["required"] is True
    assert spec["attach"]["options"]["interfaces"]["default"] == []
    assert spec["attach"]["options"]["deploy"]["default"] is True
    assert "ports" not in spec["attach"]["options"]
    assert "tor_ports" not in spec["attach"]["options"]
    assert "attachment_options" in spec["attach"]["options"]
    assert spec["attach"]["options"]["attachment_options"]["options"]["svi_enabled"]["type"] == "bool"
    assert spec["attach"]["options"]["attachment_options"]["options"]["dpu_affinity"]["choices"] == ["dynamic", "dpu1", "dpu2", "dpu3", "dpu4"]
    assert spec["attach"]["options"]["attachment_options"]["options"]["switch_route_target_import"]["elements"] == "str"
    assert "instance_values" not in spec["attach"]["options"]
    assert "freeform_config" in spec["attach"]["options"]
    assert "extra_config" not in spec["attach"]["options"]
    assert "net_name" not in spec
    assert "net_id" not in spec
    assert "network_type" not in spec
    assert "l2_fabric_data" not in spec
    assert "gw_ip_subnet" not in spec
    assert spec["deploy_type"]["choices"] == ["switch", "network"]
    assert spec["vlan_network_type"]["choices"] == ["normal", "primary", "community", "isolated"]
    assert "network_id" not in child_spec
    assert child_spec["x_connect"] == network_module_argument_spec()["x_connect"]
    for field in (
        "gateway_ipv4_address",
        "gateway_ipv6_address",
        "secondary_gateway_ipv6_collection",
        "vlan_intf_desc",
        "mtu",
        "routing_tag",
    ):
        assert field in spec
        assert field not in child_spec
    assert "ds_vni" not in spec
    assert "ds_vni" not in child_spec
    assert "vrf_name" not in child_spec
    assert "layer" not in child_spec
    assert "network_name" not in child_spec
    assert "vlan_id" not in child_spec
    assert "vlan_name" not in child_spec
    assert "secondary_gateway_ipv4_collection" not in child_spec
    assert "arp_suppression" not in child_spec
    assert "attach" not in child_spec
    assert "enable_ir" not in child_spec
    assert "l2_fabric_data" not in child_spec
    assert "netflow_enable" in child_spec
    assert "gateway_on_border" in child_spec


@pytest.mark.parametrize(
    "field,value",
    [
        ("network_name", "OTHER"),
        ("layer", "layer2"),
        ("vrf_name", "OTHER"),
        ("network_id", 901031),
        ("vlan_id", 3131),
        ("vlan_name", "CHILD_VLAN"),
        ("secondary_gateway_ipv4_collection", ["192.0.2.2/24"]),
        ("arp_suppression", True),
        ("gateway_ipv4_address", "192.0.2.1/24"),
        ("gateway_ipv6_address", "2001:db8::1/64"),
        ("secondary_gateway_ipv6_collection", ["2001:db8::2/64"]),
        ("vlan_intf_desc", "Child SVI"),
        ("mtu", 9000),
        ("routing_tag", 77),
    ],
)
def test_network_child_argument_spec_rejects_parent_owned_fields(field, value):
    validator = ArgumentSpecValidator({"config": {"type": "list", "elements": "dict", "options": network_parent_argument_spec()}})
    result = validator.validate({"config": [{"network_name": "BLUE_NET", "child_fabric_config": [{"fabric_name": "child1", field: value}]}]})
    assert result.error_messages
    assert field in str(result.error_messages)


def test_network_downstream_vni_is_not_in_argument_spec():
    standalone = ArgumentSpecValidator({"config": {"type": "list", "elements": "dict", "options": network_base_argument_spec()}})
    rejected = standalone.validate({"config": [{"network_name": "BLUE_NET", "ds_vni": 901031}]})
    assert rejected.error_messages
    assert "ds_vni" in str(rejected.error_messages)

    parent = ArgumentSpecValidator({"config": {"type": "list", "elements": "dict", "options": network_parent_argument_spec()}})
    rejected = parent.validate({"config": [{"network_name": "BLUE_NET", "ds_vni": 901031}]})
    assert rejected.error_messages
    assert "ds_vni" in str(rejected.error_messages)
    rejected = parent.validate({"config": [{"network_name": "BLUE_NET", "child_fabric_config": [{"fabric_name": "child1", "ds_vni": 901031}]}]})
    assert rejected.error_messages
    assert "ds_vni" in str(rejected.error_messages)


def test_network_config_model_accepts_user_facing_pvlan_types_only():
    primary = NetworkConfigModel.from_config({"network_name": "PVLAN_PRIMARY", "vlan_network_type": "primary"})
    community = NetworkConfigModel.from_config(
        {
            "network_name": "PVLAN_COMMUNITY",
            "vlan_network_type": "community",
            "primary_network_id": 50100,
        }
    )
    isolated = NetworkConfigModel.from_config(
        {
            "network_name": "PVLAN_ISOLATED",
            "vlan_network_type": "isolated",
            "primary_network_id": 50100,
        }
    )

    assert primary.vlan_network_type == "privatePrimary"
    assert community.vlan_network_type == "privateSecondaryCommunity"
    assert isolated.vlan_network_type == "privateSecondaryIsolated"

    with pytest.raises(ValueError, match="vlan_network_type must be one of"):
        NetworkConfigModel.from_config({"network_name": "OLD_PRIMARY", "vlan_network_type": "private_primary"})


@pytest.mark.parametrize("vlan_network_type", ["community", "isolated"])
def test_private_secondary_network_requires_primary_id_and_rejects_l3_fields(vlan_network_type):
    with pytest.raises(ValueError, match="requires primary_network_id"):
        NetworkConfigModel.from_config({"network_name": "PVLAN_SECONDARY", "vlan_network_type": vlan_network_type})

    with pytest.raises(ValueError, match="do not support layer3 intent"):
        NetworkConfigModel.from_config(
            {
                "network_name": "PVLAN_COMMUNITY",
                "vlan_network_type": vlan_network_type,
                "primary_network_id": 50100,
                "layer": "layer3",
                "vrf_name": "VRF_BLUE",
            }
        )

    with pytest.raises(ValueError, match="support only PVLAN secondary fields"):
        NetworkConfigModel.from_config(
            {
                "network_name": "PVLAN_COMMUNITY",
                "vlan_network_type": vlan_network_type,
                "primary_network_id": 50100,
                "gateway_ipv4_address": "192.0.2.1/24",
            }
        )


def test_private_secondary_network_payload_is_generated_from_primary_id():
    orchestrator = _orchestrator()
    transformed = orchestrator.prepare_config_data(
        _validated_network_config(
            [
                {
                    "network_name": "PVLAN_COMMUNITY",
                    "network_id": 50101,
                    "vlan_id": 2101,
                    "vlan_network_type": "community",
                    "primary_network_id": 50100,
                    "multicast_group_address": "239.1.1.101",
                    "vlan_name": "PVLAN_COMMUNITY_VLAN",
                }
            ]
        )
    )[0]
    model = orchestrator.model_class.from_config(transformed)
    payload = orchestrator._create_or_update_payload(model)

    assert payload["networkType"] == "userDefined"
    assert payload["vlanNetworkType"] == "privateSecondaryCommunity"
    assert payload["primaryNetworkId"] == 50100
    assert "primaryNetworkName" not in payload
    assert "vlanId" not in payload
    assert payload["networkTemplateName"] == "Pvlan_Secondary_Network"
    assert payload["networkExtensionTemplateName"] == "Pvlan_Secondary_Network"
    assert payload["networkTemplateConfig"] == {
        "enableIR": "true",
        "isLayer2Only": "true",
        "networkMode": "layer2",
        "networkName": "PVLAN_COMMUNITY",
        "networkType": "userDefined",
        "nveId": "1",
        "segmentId": "50101",
        "type": "Community",
        "vlanId": "2101",
        "vrfName": "NA",
        "vlanName": "PVLAN_COMMUNITY_VLAN",
        "mcastGroup": "239.1.1.101",
    }
    assert "l2Data" not in payload
    assert "l3Data" not in payload
    assert model.to_config()["vlan_network_type"] == "community"


def test_private_secondary_readback_is_idempotent_after_template_defaults():
    orchestrator = _orchestrator()

    existing = orchestrator.model_class.from_response(
        orchestrator._normalize_query_network_item(
            {
                "networkName": "PVLAN_COMMUNITY",
                "displayName": "PVLAN_COMMUNITY",
                "networkType": "userDefined",
                "vlanNetworkType": "privateSecondaryCommunity",
                "vrfName": "NA",
                "primaryNetworkId": 50100,
                "primaryNetworkName": "PVLAN_PRIMARY",
                "networkTemplateName": "Pvlan_Secondary_Network",
                "networkExtensionTemplateName": "Pvlan_Secondary_Network",
                "networkTemplateConfig": {
                    "networkMode": "layer2",
                    "isLayer2Only": "true",
                    "vlanId": "2101",
                    "segmentId": "50101",
                    "networkName": "PVLAN_COMMUNITY",
                    "vlanName": "PVLAN_COMMUNITY_VLAN",
                    "type": "Community",
                    "networkType": "userDefined",
                    "enableIR": "true",
                    "nveId": "1",
                    "vrfName": "NA",
                },
            }
        )
    )
    proposed = orchestrator.model_class.from_config(
        orchestrator.prepare_config_data(
            [
                {
                    "network_name": "PVLAN_COMMUNITY",
                    "display_name": "PVLAN_COMMUNITY",
                    "network_id": 50101,
                    "vlan_id": 2101,
                    "vlan_network_type": "community",
                    "primary_network_id": 50100,
                    "vlan_name": "PVLAN_COMMUNITY_VLAN",
                }
            ]
        )[0]
    )

    assert existing.get_diff(proposed, exclude_unset=True) is True
    assert existing.get_diff(proposed, exclude_unset=False) is True
    payload = orchestrator._create_or_update_payload(proposed)
    assert "vlanId" not in payload
    assert "l2Data" not in payload
    assert payload["networkTemplateConfig"]["vlanId"] == "2101"
    assert payload["networkTemplateConfig"]["enableIR"] == "true"


def test_private_primary_l2_readback_defaults_do_not_force_update():
    orchestrator = _orchestrator()

    existing = orchestrator.model_class.from_response(
        orchestrator._normalize_query_network_item(
            {
                "displayName": "PVLAN_PRIMARY",
                "fabricName": "fab1",
                "l2Data": {
                    "disableRtAuto": False,
                    "fabricData": {"enableIr": True},
                    "vlanName": "PVLAN_PRIMARY_VLAN",
                    "xConnect": False,
                },
                "l3Data": {
                    "arpSuppression": False,
                    "fabricData": {
                        "gatewayOnBorder": False,
                        "ipv4Trm": False,
                        "ipv6Trm": False,
                        "netflow": False,
                    },
                },
                "networkId": 50100,
                "networkMode": "layer2",
                "networkName": "PVLAN_PRIMARY",
                "networkStatus": "notApplicable",
                "networkType": "vxlanIbgp",
                "vlanId": 2100,
                "vlanNetworkType": "privatePrimary",
                "vrfName": "NA",
            }
        )
    )
    proposed = orchestrator.model_class.from_config(
        orchestrator.prepare_config_data(
            [
                {
                    "network_name": "PVLAN_PRIMARY",
                    "display_name": "PVLAN_PRIMARY",
                    "network_id": 50100,
                    "vlan_id": 2100,
                    "vlan_network_type": "primary",
                    "vlan_name": "PVLAN_PRIMARY_VLAN",
                    "layer": "layer2",
                }
            ]
        )[0]
    )

    assert existing.get_diff(proposed, exclude_unset=True) is True
    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_private_secondary_query_infers_vlan_type_from_template_config_for_manage_read():
    orchestrator = _orchestrator()

    normalized = orchestrator._normalize_query_network_item(
        {
            "networkName": "PVLAN_COMMUNITY",
            "networkTemplateConfig": '{"segmentId":"50101","vlanId":"2101","isLayer2Only":"true","type":"Community"}',
        }
    )

    assert normalized["vlanNetworkType"] == "privateSecondaryCommunity"
    assert normalized["networkId"] == 50101
    assert normalized["vlanId"] == 2101
    assert orchestrator.model_class.from_response(normalized).to_config()["vlan_network_type"] == "community"


@pytest.mark.parametrize("spec_factory", [network_base_argument_spec, network_parent_argument_spec])
@pytest.mark.parametrize("model_cls", [NetworkConfigModel, NetworkParentConfigModel])
@pytest.mark.parametrize(
    "field,value",
    [
        ("network_template_name", "Custom_Network"),
        ("networkTemplateName", "Custom_Network"),
        ("network_extension_template_name", "Custom_Extension"),
        ("networkExtensionTemplateName", "Custom_Extension"),
        ("service_network_template_name", "Custom_Service"),
        ("serviceNetworkTemplateName", "Custom_Service"),
        ("network_template_config", {"segmentId": "50100"}),
        ("networkTemplateConfig", {"segmentId": "50100"}),
    ],
)
def test_custom_template_fields_are_not_public_network_options(spec_factory, model_cls, field, value):
    spec = spec_factory()
    assert field not in spec
    validator = ArgumentSpecValidator({"config": {"type": "list", "elements": "dict", "options": spec}})
    rejected = validator.validate({"config": [{"network_name": "N", field: value}]})
    assert rejected.error_messages
    assert field in str(rejected.error_messages)

    model = model_cls.from_config({"network_name": "N", field: value})
    assert model.network_type is None
    assert model.layer is None
    assert field not in model.to_config(exclude_unset=True)


def test_l2_fabric_data_raw_override_is_not_supported():
    with pytest.raises(ValueError):
        NetworkConfigModel.from_config(
            {
                "network_name": "RAW_L2_OVERRIDE",
                "layer": "layer2",
                "l2_fabric_data": {"customL2Key": "custom-l2-value"},
            }
        )


def test_parent_config_accepts_child_fabric_overrides():
    model = NetworkParentConfigModel.from_config(
        {
            "network_name": "BLUE_NET",
            "layer": "layer2",
            "child_fabric_config": [
                {
                    "fabric_name": "child1",
                    "multicast_group_address": "239.1.1.53",
                    "x_connect": True,
                }
            ],
        }
    )

    assert model.to_config()["child_fabric_config"][0]["fabric_name"] == "child1"
    assert model.to_config()["child_fabric_config"][0]["multicast_group_address"] == "239.1.1.53"
    assert model.to_config()["child_fabric_config"][0]["x_connect"] is True


def test_child_task_inherits_parent_network_name_and_layer_context():
    orchestrator = _mcfg_parent_orchestrator()
    coordinator = NetworkWorkflowCoordinator(module=object(), strategy=orchestrator.strategy)

    child_tasks = coordinator._accumulate_child_task(
        parent_network={
            "network_name": "BLUE_NET",
            "network_id": 901030,
            "vlan_id": 3130,
            "vlan_name": "BLUE_VLAN",
            "vrf_name": "NA",
            "layer": "layer2",
        },
        child_cfg={"fabric_name": "child1"},
        child_tasks_dict={},
        child_fabric_data={"fabricName": "child1", "fabricState": "member", "clusterName": "cluster1"},
        state="merged",
    )

    child_config = child_tasks["child1"]["module_args"]["config"][0]
    assert child_config["network_name"] == "BLUE_NET"
    assert child_config["layer"] == "layer2"
    assert "network_id" not in child_config
    assert "vlan_id" not in child_config
    assert "vlan_name" not in child_config
    assert "vrf_name" not in child_config


@pytest.mark.parametrize("network_type", ["vxlanIbgp", "vxlanCampus"])
def test_child_override_preserves_read_back_parent_owned_identity(network_type):
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend({"state": "merged", "config": [], "check_mode": False}),
        strategy=ChildNetworkStrategy(fabric_name="child1", fabric_data={"fabricType": network_type, "fabricState": "member"}),
    )
    desired = orchestrator.model_class.from_config(
        orchestrator.prepare_config_data([{"network_name": "BLUE_NET", "layer": "layer3", "multicast_group_address": "239.1.1.53"}])[0]
    )
    current = orchestrator.model_class.from_response(
        {
            "fabricName": "child1",
            "networkName": "BLUE_NET",
            "networkType": network_type,
            "networkMode": "layer3",
            "networkId": 901030,
            "vrfName": "BLUE_VRF",
            "vlanId": 3130,
            "l2Data": {"vlanName": "PARENT_VLAN", "fabricData": {"multicastGroup": "239.1.1.0", "dsVni": 60050}},
            "l3Data": {"arpSuppression": True, "secondaryGatewayIpv4Collection": ["192.0.2.2/24"]},
        }
    )
    payload = orchestrator._create_or_update_payload(current.merge(desired))
    assert payload["networkType"] == network_type
    assert payload["networkId"] == 901030
    assert payload["vrfName"] == "BLUE_VRF"
    assert payload["networkMode"] == "layer3"
    assert payload["vlanId"] == 3130
    assert payload["l3Data"]["arpSuppression"] is True
    assert payload["l3Data"]["secondaryGatewayIpv4Collection"] == ["192.0.2.2/24"]
    assert payload["l2Data"]["vlanName"] == "PARENT_VLAN"
    assert payload["l2Data"]["fabricData"]["multicastGroup"] == "239.1.1.53"
    assert payload["l2Data"]["fabricData"]["dsVni"] == 60050


@pytest.mark.parametrize(
    "fabric_data,expected",
    [
        ({"fabricType": "MSD"}, "vxlanIbgp"),
        ({"fabricType": "vxlanCampus"}, "vxlanCampus"),
        ({"type": "vxlanEbgp"}, "vxlanEbgp"),
        ({"fabricType": "vxlanCampus", "managementType": "vxlanIbgp"}, "vxlanIbgp"),
    ],
)
def test_network_default_type_uses_valid_member_discriminator(fabric_data, expected):
    assert NDNetworkOrchestrator.default_network_type(fabric_data) == expected


@pytest.mark.parametrize("parent_type", ["msd", "mcfg"])
def test_parent_child_network_ui_overrides_reach_child_manage_payload(parent_type):
    parent = {
        "network_name": "BLUE_NET",
        "layer": "layer3",
        "vrf_name": "BLUE_VRF",
        "network_id": 901030,
        "vlan_id": 3130,
        "arp_suppression": True,
        "gateway_ipv4_address": "192.0.2.1/24",
        "gateway_ipv6_address": "2001:db8::1/64",
        "secondary_gateway_ipv6_collection": ["2001:db8::2/64"],
        "vlan_intf_desc": "Parent SVI",
        "mtu": 9000,
        "routing_tag": 77,
        "child_fabric_config": [
            {
                "fabric_name": "child1",
                "multicast_group_address": "239.1.1.53",
                "dhcp_servers": [{"server_address": "198.51.100.1", "server_vrf": "management"}],
                "loopback_id": 101,
                "igmp_version": 3,
                "trm_enable": True,
                "ipv6_trm": True,
                "netflow_enable": True,
                "vlan_netflow_monitor": "VLAN_MON",
                "interface_netflow_monitor": "INTF_MON",
                "gateway_on_border": True,
            }
        ],
    }
    validated = _validated_network_config([parent])[0]
    strategy = _ParentStrategy()
    if parent_type == "mcfg":
        strategy = MulticlusterParentNetworkStrategy(
            fabric_name="MCFG_P",
            fabric_data={"members": [{"fabricName": "child1", "clusterName": "cluster1"}]},
        )
    coordinator = NetworkWorkflowCoordinator(_Module({"state": "merged", "config": [validated]}), strategy)
    parsed = coordinator._parse_config([validated], NetworkParentConfigModel, "merged")[0]
    parent_strategy = strategy if parent_type == "mcfg" else MultisiteParentNetworkStrategy(fabric_name="msd_p", fabric_data={"managementType": "vxlanIbgp"})
    parent_orchestrator = NDNetworkOrchestrator(rest_send=RestSend({"state": "replaced"}), strategy=parent_strategy)
    parent_model = parent_orchestrator.model_class.from_config(parent_orchestrator.prepare_config_data([parsed])[0])
    parent_requests = []
    object.__setattr__(parent_orchestrator, "_request", lambda **kwargs: parent_requests.append(kwargs) or {})
    parent_orchestrator.create_bulk([parent_model])
    parent_payload = parent_requests[0]["data"]["networks"][0]
    expected_prefix = "/api/v1/oneManage/manage" if parent_type == "mcfg" else "/api/v1/manage"
    assert parent_requests[0]["path"].startswith(expected_prefix)
    assert "xConnect" not in parent_payload.get("l2Data", {})
    assert "multicastGroup" not in parent_payload.get("l2Data", {}).get("fabricData", {})
    assert "fabricData" not in parent_payload.get("l3Data", {})
    for field in ("gateway_ipv4_address", "gateway_ipv6_address", "secondary_gateway_ipv6_collection", "vlan_intf_desc", "mtu", "routing_tag"):
        assert parsed[field] == parent[field]
    child = parsed["child_fabric_config"][0]
    assert not {"gateway_ipv4_address", "gateway_ipv6_address", "secondary_gateway_ipv6_collection", "vlan_intf_desc", "mtu", "routing_tag"} & child.keys()
    tasks = coordinator._accumulate_child_task(
        parsed,
        child,
        {},
        {"fabricName": "child1", "fabricState": "member", "clusterName": "cluster1", "fabricType": "vxlanCampus"},
        "merged",
    )
    child_task = tasks["child1"]
    assert child_task["module_args"]["state"] == "merged"
    child_config = child_task["module_args"]["config"][0]
    assert not {"network_id", "vrf_name", "vlan_id", "secondary_gateway_ipv4_collection", "arp_suppression", "attach", "deploy"} & child_config.keys()
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend({"state": "merged", "config": [], "check_mode": False}),
        strategy=ChildNetworkStrategy(fabric_name="child1", fabric_data={"fabricType": "vxlanCampus", "fabricState": "member"}),
    )
    prepared = orchestrator.prepare_config_data([child_config])[0]
    child_requests = []
    object.__setattr__(orchestrator, "_request", lambda **kwargs: child_requests.append(kwargs) or {})
    orchestrator.update(orchestrator.model_class.from_config(prepared))
    payload = child_requests[0]["data"]
    assert child_requests[0]["path"].startswith("/api/v1/manage/")
    assert payload["networkType"] == "vxlanCampus"
    assert "vlanName" not in payload.get("l2Data", {})
    assert payload["l2Data"]["fabricData"] == {"multicastGroup": "239.1.1.53"}
    assert payload["l3Data"]["fabricData"] == {
        "dhcpServers": [{"serverAddress": "198.51.100.1", "serverVrf": "management"}],
        "loopbackId": 101,
        "igmpVersion": 3,
        "ipv4Trm": True,
        "ipv6Trm": True,
        "netflow": True,
        "l2NetflowMonitor": "VLAN_MON",
        "l3NetflowMonitor": "INTF_MON",
        "gatewayOnBorder": True,
    }


def test_msd_parent_owned_network_fields_remain_in_parent_manage_payload():
    strategy = MultisiteParentNetworkStrategy(fabric_name="msd_p", fabric_data={"managementType": "vxlanIbgp"})
    orchestrator = NDNetworkOrchestrator(rest_send=RestSend({"state": "merged", "config": [], "check_mode": False}), strategy=strategy)
    config = {
        "network_name": "BLUE_NET",
        "layer": "layer3",
        "vrf_name": "BLUE_VRF",
        "network_id": 901030,
        "gateway_ipv4_address": "192.0.2.1/24",
        "gateway_ipv6_address": "2001:db8::1/64",
        "secondary_gateway_ipv6_collection": ["2001:db8::2/64"],
        "vlan_intf_desc": "Parent SVI",
        "mtu": 9000,
        "routing_tag": 77,
    }
    parent = NetworkParentConfigModel.from_config(config).to_config(exclude_unset=True)
    prepared = orchestrator.prepare_config_data([parent])[0]
    payload = orchestrator._create_or_update_payload(orchestrator.model_class.from_config(prepared))

    assert "dsVni" not in payload.get("l2Data", {}).get("fabricData", {})
    assert payload["l3Data"]["gatewayIpv4Address"] == "192.0.2.1/24"
    assert payload["l3Data"]["gatewayIpv6Address"] == "2001:db8::1/64"
    assert payload["l3Data"]["secondaryGatewayIpv6Collection"] == ["2001:db8::2/64"]
    assert payload["l3Data"]["vlanInterfaceDescription"] == "Parent SVI"
    assert payload["l3Data"]["mtu"] == 9000
    assert payload["l3Data"]["routingTag"] == 77


def test_parent_child_network_explicit_clears_remain_in_sparse_payload():
    parent = NetworkParentConfigModel.from_config(
        {
            "network_name": "BLUE_NET",
            "layer": "layer3",
            "vrf_name": "BLUE_VRF",
            "arp_suppression": False,
            "child_fabric_config": [
                {
                    "fabric_name": "child1",
                    "netflow_enable": False,
                    "dhcp_servers": [],
                }
            ],
        }
    )
    child = parent.to_config(exclude_unset=True)["child_fabric_config"][0]
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend({"state": "merged", "config": [], "check_mode": False}),
        strategy=ChildNetworkStrategy(fabric_name="child1", fabric_data={"managementType": "vxlanIbgp"}),
    )
    child["network_name"] = "BLUE_NET"
    child["layer"] = "layer3"
    child.pop("fabric_name")
    prepared = orchestrator.prepare_config_data([child])[0]
    payload = orchestrator._create_or_update_payload(orchestrator.model_class.from_config(prepared))
    assert payload["l3Data"]["fabricData"]["netflow"] is False
    assert payload["l3Data"]["fabricData"]["dhcpServers"] == []


def test_sparse_parent_child_override_validates_against_cached_child_mode(monkeypatch):
    coordinator = NetworkWorkflowCoordinator(_Module({"state": "merged", "config": []}), _ParentStrategy())
    child_task = {
        "fabric": "child1",
        "module_args": {"config": [{"network_name": "BLUE_NET", "dhcp_servers": [{"server_address": "192.0.2.10"}]}]},
    }

    def use_cached_snapshot(tasks, *_args):
        tasks["child1"]["preflight_state_machine"] = SimpleNamespace(existing={"BLUE_NET": SimpleNamespace(layer="layer2")})

    monkeypatch.setattr(coordinator_mod, "preflight_child_feature_tasks", use_cached_snapshot)
    with pytest.raises(NDStateMachineError, match=r"child_fabric_config\[child1\] layer2 networks do not support L3 properties"):
        coordinator._preflight_child_feature_tasks({"child1": child_task}, "merged")


def test_child_network_config_without_fabric_options_does_not_require_child_task():
    assert NetworkWorkflowCoordinator._has_child_network_options({"fabric_name": "child1"}) is False
    assert NetworkWorkflowCoordinator._has_child_network_options({"fabric_name": "child1", "multicast_group_address": "239.1.1.53"}) is True


@pytest.mark.parametrize("undeploy", [False, True])
def test_network_workflow_coordinator_parent_deploy_deferred_after_child_tasks(undeploy):
    """
    Verify parent attach/deploy fields stay on the parent task, are stripped
    from child tasks, and parent deploy runs after child processing.
    """
    module_args = {
        "fabric_name": "msd_p",
        "state": "merged",
        "output_level": "debug",
        "config": [
            {
                "network_name": "ansible-msd-net",
                "network_id": 30101,
                "vlan_id": 2301,
                "layer": "layer3",
                "vrf_name": "ansible-msd-vrf",
                "deploy": True,
                "attach": [
                    {
                        "ip_address": "192.168.1.224",
                        "interfaces": [{"interface_range": "Ethernet1/1", "mode": "trunk"}],
                    }
                ],
                "child_fabric_config": [
                    {
                        "fabric_name": "child1",
                        "multicast_group_address": "239.1.1.53",
                    }
                ],
            }
        ],
    }
    coordinator = NetworkWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_ParentStrategy(),
    )
    object.__setattr__(coordinator, "_preflight_child_feature_tasks", lambda *_args: call_order.append("preflight"))
    call_order = []

    def run_parent(args, defer_deploy=False):
        call_order.append("parent")
        parent_network = args["config"][0]
        assert defer_deploy is True
        assert parent_network["attach"][0]["ip_address"] == "192.168.1.224"
        assert parent_network["attach"][0]["interfaces"][0]["interface_range"] == "Ethernet1/1"
        assert parent_network["attach"][0]["interfaces"][0]["mode"] == "trunk"
        assert parent_network["deploy"] is True
        assert "child_fabric_config" not in parent_network
        return {
            "changed": True,
            "output_level": "debug",
            "before": [],
            "after": [],
            "diff": [],
            "_deferred_deploy_payload": {
                **({"_undeploy": True} if undeploy else {}),
                "networkNames": ["ansible-msd-net"],
                "switchIds": ["SERIAL1"],
            },
        }

    def run_child(child_task):
        call_order.append("child")
        child_network = child_task["module_args"]["config"][0]
        assert "attach" not in child_network
        assert "deploy" not in child_network
        assert "deploy_type" not in child_network
        assert child_network["network_name"] == "ansible-msd-net"
        assert child_network["multicast_group_address"] == "239.1.1.53"
        return {
            "changed": False,
            "output_level": "debug",
            "before": [],
            "after": [],
            "diff": [],
            "fabric_type": "multisite_child",
        }

    def deploy_parent(_args, _strategy, payload, undeploy=False):
        call_order.append("deploy")
        assert undeploy is expected_undeploy
        assert payload == {
            "networkNames": ["ansible-msd-net"],
            "switchIds": ["SERIAL1"],
        }
        return {}

    expected_undeploy = undeploy
    object.__setattr__(coordinator, "_run_state_machine_with_attachments", run_parent)
    object.__setattr__(coordinator, "_run_child_task", run_child)
    object.__setattr__(coordinator, "_deploy_network_attachments", deploy_parent)

    result = coordinator._handle_parent_workflow(dict(module_args), "multisite_parent")

    assert call_order == ["preflight", "parent", "child", "deploy"]
    assert result["changed"] is True
    assert result["fabric_type"] == "multisite_parent"


def test_network_child_reuses_preflight_inventory_when_parent_is_unchanged():
    coordinator = NetworkWorkflowCoordinator(module=_Module({"output_level": "normal"}), strategy=_ParentStrategy())
    prepared = object()
    calls = []

    class StateMachineWrapper:
        @staticmethod
        def run_basic(module_args, strategy, prebuilt_sm):
            calls.append((module_args, strategy, prebuilt_sm))
            return {"changed": False, "failed": False}

    def unexpected_query(*_args, **_kwargs):
        raise AssertionError("second GET")

    object.__setattr__(coordinator, "_network_state_machine", StateMachineWrapper)
    object.__setattr__(coordinator, "_run_state_machine", unexpected_query)
    strategy = ChildNetworkStrategy(fabric_name="CHILD", fabric_data={})
    module_args = {"state": "merged", "config": []}
    result = coordinator._run_child_task({"fabric": "CHILD", "strategy": strategy, "module_args": module_args, "preflight_state_machine": prepared})

    assert result["failed"] is False
    assert calls == [(module_args, strategy, prepared)]


def test_child_network_update_payload_is_limited_to_fabric_instance_data():
    strategy = ChildNetworkStrategy(
        fabric_name="child1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend({"state": "merged", "config": [], "check_mode": False}),
        strategy=strategy,
    )
    transformed = orchestrator.prepare_config_data(
        [
            {
                "network_name": "BLUE_NET",
                "network_id": 901030,
                "vlan_id": 3130,
                "vlan_name": "BLUE_VLAN",
                "vrf_name": "VRF_BLUE",
                "layer": "layer3",
                "gateway_ipv4_address": "192.0.2.1/24",
                "routing_tag": 12345,
                "multicast_group_address": "239.1.1.1",
                "gateway_on_border": True,
            }
        ]
    )[0]
    model = orchestrator.model_class.from_config(transformed)

    payload = orchestrator._create_or_update_payload(model)

    assert payload["fabricName"] == "child1"
    assert payload["networkName"] == "BLUE_NET"
    assert payload["displayName"] == "BLUE_NET"
    assert payload["networkType"] == "vxlanIbgp"
    assert payload["networkMode"] == "layer3"
    assert payload["vlanNetworkType"] == "normal"
    assert payload["networkId"] == 901030
    assert payload["vlanId"] == 3130
    assert payload["vrfName"] == "VRF_BLUE"
    assert payload["l2Data"]["vlanName"] == "BLUE_VLAN"
    assert "enableIr" not in payload["l2Data"]["fabricData"]
    assert payload["l2Data"]["fabricData"]["multicastGroup"] == "239.1.1.1"
    assert payload["l3Data"]["gatewayIpv4Address"] == "192.0.2.1/24"
    assert payload["l3Data"]["routingTag"] == 12345
    assert payload["l3Data"]["fabricData"]["gatewayOnBorder"] is True


def test_child_network_update_payload_uses_manage_schema_for_sparse_child_options():
    strategy = ChildNetworkStrategy(
        fabric_name="child1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend({"state": "merged", "config": [], "check_mode": False}),
        strategy=strategy,
    )
    transformed = orchestrator.prepare_config_data(
        [
            {
                "network_name": "BLUE_NET",
                "layer": "layer3",
                "multicast_group_address": "239.1.1.1",
            }
        ]
    )[0]
    model = orchestrator.model_class.from_config(transformed)

    payload = orchestrator._create_or_update_payload(model)

    assert payload["fabricName"] == "child1"
    assert payload["networkName"] == "BLUE_NET"
    assert payload["displayName"] == "BLUE_NET"
    assert payload["networkType"] == "vxlanIbgp"
    assert payload["networkMode"] == "layer3"
    assert payload["vlanNetworkType"] == "normal"
    assert "layer" not in payload
    assert payload["l2Data"]["fabricData"]["multicastGroup"] == "239.1.1.1"


def test_layer2_with_vrf_requires_vrf_name():
    with pytest.raises(ValueError, match="vrf_name is required for layer3 and layer2WithVrf networks"):
        NetworkConfigModel.from_config(
            {
                "network_name": "SHARED_SERVICES",
                "layer": "layer2WithVrf",
                "network_id": 50001,
                "vlan_id": 1001,
            }
        )


def test_layer2_with_vrf_payload_includes_vrf_name():
    orchestrator = _orchestrator()
    transformed = orchestrator.prepare_config_data(
        [
            {
                "network_name": "SHARED_SERVICES",
                "layer": "layer2WithVrf",
                "vrf_name": "TENANT_BLUE",
                "network_id": 50001,
                "vlan_id": 1001,
            }
        ]
    )[0]
    model = orchestrator.model_class.from_config(transformed)

    payload = orchestrator._create_or_update_payload(model)

    assert payload["networkMode"] == "layer2WithVrf"
    assert payload["vrfName"] == "TENANT_BLUE"


def test_layer2_with_vrf_payload_includes_l3_data():
    orchestrator = _orchestrator()
    transformed = orchestrator.prepare_config_data(
        [
            {
                "network_name": "SHARED_SERVICES",
                "layer": "layer2WithVrf",
                "vrf_name": "TENANT_BLUE",
                "network_id": 50001,
                "vlan_id": 1001,
                "gateway_ipv4_address": "192.0.2.21/24",
                "gateway_ipv6_address": "2001:db8:622:8::1/64",
                "secondary_gateway_ipv4_collection": ["192.0.2.22/24"],
                "secondary_gateway_ipv6_collection": ["2001:db8:622:8::2/64"],
                "vlan_intf_desc": "layer2-with-vrf-svi",
                "mtu": 9100,
                "arp_suppression": True,
                "routing_tag": 12346,
                "dhcp_servers": [{"server_address": "198.51.100.10", "server_vrf": "TENANT_BLUE"}],
                "loopback_id": 101,
                "gateway_on_border": True,
            }
        ]
    )[0]
    model = orchestrator.model_class.from_config(transformed)

    payload = orchestrator._create_or_update_payload(model)

    assert payload["networkMode"] == "layer2WithVrf"
    assert payload["vrfName"] == "TENANT_BLUE"
    assert payload["l3Data"]["gatewayIpv4Address"] == "192.0.2.21/24"
    assert payload["l3Data"]["gatewayIpv6Address"] == "2001:db8:622:8::1/64"
    assert payload["l3Data"]["secondaryGatewayIpv4Collection"] == ["192.0.2.22/24"]
    assert payload["l3Data"]["secondaryGatewayIpv6Collection"] == ["2001:db8:622:8::2/64"]
    assert payload["l3Data"]["vlanInterfaceDescription"] == "layer2-with-vrf-svi"
    assert payload["l3Data"]["mtu"] == 9100
    assert payload["l3Data"]["arpSuppression"] is True
    assert payload["l3Data"]["routingTag"] == 12346
    assert payload["l3Data"]["fabricData"]["dhcpServers"] == [{"serverAddress": "198.51.100.10", "serverVrf": "TENANT_BLUE"}]
    assert payload["l3Data"]["fabricData"]["loopbackId"] == 101
    assert payload["l3Data"]["fabricData"]["gatewayOnBorder"] is True


def test_child_network_update_payload_maps_all_child_fabric_options_to_manage_schema():
    strategy = ChildNetworkStrategy(
        fabric_name="child1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend({"state": "merged", "config": [], "check_mode": False}),
        strategy=strategy,
    )
    transformed = orchestrator.prepare_config_data(
        [
            {
                "network_name": "BLUE_NET",
                "layer": "layer3",
                "multicast_group_address": "239.1.1.53",
                "dhcp_servers": [{"server_address": "192.0.2.10", "server_vrf": "management"}],
                "loopback_id": 101,
                "igmp_version": 3,
                "trm_enable": True,
                "ipv6_trm": True,
                "netflow_enable": True,
                "gateway_on_border": True,
            }
        ]
    )[0]
    model = orchestrator.model_class.from_config(transformed)

    payload = orchestrator._create_or_update_payload(model)

    assert payload["networkMode"] == "layer3"
    assert "layer" not in payload
    assert payload["l2Data"]["fabricData"] == {"multicastGroup": "239.1.1.53"}
    assert payload["l3Data"]["fabricData"] == {
        "dhcpServers": [{"serverAddress": "192.0.2.10", "serverVrf": "management"}],
        "loopbackId": 101,
        "igmpVersion": 3,
        "netflow": True,
        "gatewayOnBorder": True,
        "ipv4Trm": True,
        "ipv6Trm": True,
    }


def test_child_network_update_payload_uses_sparse_source_after_state_machine_merge():
    strategy = ChildNetworkStrategy(
        fabric_name="child1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend({"state": "merged", "config": [], "check_mode": False}),
        strategy=strategy,
    )
    transformed = orchestrator.prepare_config_data(
        [
            {
                "network_name": "BLUE_NET",
                "layer": "layer2",
                "multicast_group_address": "239.1.1.1",
            }
        ]
    )[0]
    proposed = orchestrator.model_class.from_config(transformed)
    existing = orchestrator.model_class.from_response(
        {
            "fabricName": "child1",
            "networkName": "BLUE_NET",
            "networkType": "vxlanIbgp",
            "networkMode": "layer2",
            "vrfName": "NA",
            "l2Data": {
                "vlanName": "BLUE_VLAN",
                "fabricData": {
                    "enableIr": False,
                    "multicastGroup": "239.1.1.0",
                },
            },
            "l3Data": {
                "fabricData": {
                    "gatewayOnBorder": False,
                    "ipv4Trm": False,
                    "ipv6Trm": False,
                    "netflow": False,
                }
            },
        }
    )
    merged = existing.merge(proposed)

    payload = orchestrator._create_or_update_payload(merged)

    assert payload["fabricName"] == "child1"
    assert payload["networkName"] == "BLUE_NET"
    assert payload["displayName"] == "BLUE_NET"
    assert payload["networkType"] == "vxlanIbgp"
    assert payload["networkMode"] == "layer2"
    assert payload["vlanNetworkType"] == "normal"
    assert payload["vrfName"] == "NA"
    assert "layer" not in payload
    assert payload["l2Data"]["vlanName"] == "BLUE_VLAN"
    assert "enableIr" not in payload["l2Data"]["fabricData"]
    assert payload["l2Data"]["fabricData"]["multicastGroup"] == "239.1.1.1"
    assert payload["l3Data"] == {"fabricData": {"netflow": False}}


def test_attachment_only_network_config_does_not_generate_definition_defaults():
    orchestrator = _orchestrator()

    transformed = orchestrator.prepare_config_data(
        _validated_network_config(
            [
                {
                    "network_name": "BLUE_NET",
                    "deploy": True,
                    "deploy_type": "switch",
                    "attach": [
                        {
                            "ip_address": "192.0.2.11",
                            "vlan_id": 2300,
                            "interfaces": [{"interface_range": "Ethernet1/1", "mode": "trunk"}],
                        }
                    ],
                }
            ]
        )
    )[0]

    assert transformed == {
        "fabric_name": "fab1",
        "network_name": "BLUE_NET",
    }


def test_parse_config_preserves_attachment_only_shape_before_transform():
    class Module:
        check_mode = False
        params = {"output_level": "normal"}

        def fail_json(self, **kwargs):
            raise AssertionError(kwargs)

    strategy = StandaloneNetworkStrategy(
        fabric_name="fab1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    coordinator = NetworkWorkflowCoordinator(module=Module(), strategy=strategy)

    parsed = coordinator._parse_config(
        _validated_network_config(
            [
                {
                    "network_name": "BLUE_NET",
                    "deploy": True,
                    "deploy_type": "switch",
                    "attach": [
                        {
                            "ip_address": "192.0.2.11",
                            "vlan_id": 2300,
                            "interfaces": [{"interface_range": "Ethernet1/1", "mode": "trunk"}],
                        }
                    ],
                }
            ]
        ),
        strategy.config_model_cls,
        "merged",
    )

    assert parsed == [
        {
            "network_name": "BLUE_NET",
            "attach": [
                {
                    "ip_address": "192.0.2.11",
                    "vlan_id": 2300,
                    "interfaces": [
                        {
                            "mode": "trunk",
                            "interface_range": "Ethernet1/1",
                            "native_vlan": False,
                        }
                    ],
                    "deploy": True,
                }
            ],
            "deploy": True,
            "deploy_type": "switch",
        }
    ]


def test_parse_config_defers_layer_for_sparse_merged_l2_update():
    class Module:
        check_mode = False
        params = {"output_level": "normal"}

        def fail_json(self, **kwargs):
            raise AssertionError(kwargs)

    strategy = StandaloneNetworkStrategy(
        fabric_name="fab1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    coordinator = NetworkWorkflowCoordinator(module=Module(), strategy=strategy)

    parsed = coordinator._parse_config(
        [{"network_name": "USERS", "vlan_name": "USERS_NEW"}],
        strategy.config_model_cls,
        "merged",
    )

    assert parsed == [{"network_name": "USERS", "vlan_name": "USERS_NEW"}]


def test_prepare_config_data_defers_layer_for_sparse_merged_update():
    orchestrator = _orchestrator()

    prepared = orchestrator.prepare_config_data([{"network_name": "USERS", "vlan_name": "USERS_NEW"}])[0]

    assert prepared["network_name"] == "USERS"
    assert prepared["l2_data"]["vlanName"] == "USERS_NEW"
    assert "layer" not in prepared
    assert "vrf_name" not in prepared


def test_sparse_merged_update_inherits_existing_layer_before_payload():
    orchestrator = _orchestrator()
    existing = NDNetworkOrchestrator.model_class.from_response(
        {
            "fabricName": "fab1",
            "networkName": "USERS",
            "networkType": "vxlanIbgp",
            "networkMode": "layer2",
            "vrfName": "NA",
            "vlanId": 100,
            "l2Data": {"vlanName": "USERS_OLD"},
        }
    )
    proposed = NDNetworkOrchestrator.model_class.from_config(
        orchestrator.prepare_config_data([{"network_name": "USERS", "vlan_name": "USERS_NEW"}])[0],
        context={"state": "merged"},
    )

    merged = existing.merge(proposed)
    payload = orchestrator._create_or_update_payload(merged)

    assert payload["networkMode"] == "layer2"
    assert payload["vrfName"] == "NA"
    assert payload["l2Data"]["vlanName"] == "USERS_NEW"
    assert "l3Data" not in payload


@pytest.mark.parametrize("layer", ["layer3", "layer2WithVrf"])
@pytest.mark.parametrize("strategy_cls", [StandaloneNetworkStrategy, MultisiteParentNetworkStrategy, MulticlusterParentNetworkStrategy])
@pytest.mark.parametrize(
    "field_name,value,payload_field",
    [
        ("gateway_ipv4_address", "192.0.2.9/24", "gatewayIpv4Address"),
        ("mtu", 9000, "mtu"),
        ("routing_tag", 77, "routingTag"),
        ("secondary_gateway_ipv4_collection", [], "secondaryGatewayIpv4Collection"),
    ],
)
def test_sparse_merged_l3_update_inherits_existing_layer_before_payload(layer, strategy_cls, field_name, value, payload_field):
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend({"state": "merged", "config": [], "check_mode": False}),
        strategy=strategy_cls(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"}),
    )
    existing = NDNetworkOrchestrator.model_class.from_response(
        {
            "fabricName": "fab1",
            "networkName": "USERS",
            "networkType": "vxlanIbgp",
            "networkMode": layer,
            "vrfName": "Tenant_A",
            "vlanId": 100,
            "l2Data": {"vlanName": "USERS_OLD"},
            "l3Data": {
                "gatewayIpv4Address": "192.0.2.1/24",
                "mtu": 9216,
                "routingTag": 12345,
                "arpSuppression": True,
                "secondaryGatewayIpv4Collection": ["198.51.100.1/24"],
                "fabricData": {"netflow": True, "ipv4Trm": True, "gatewayOnBorder": True},
            },
        }
    )
    coordinator = NetworkWorkflowCoordinator(module=_Module({"output_level": "normal"}), strategy=orchestrator.strategy)
    parsed = coordinator._parse_config([{"network_name": "USERS", field_name: value}], orchestrator.strategy.config_model_cls, "merged")
    proposed = NDNetworkOrchestrator.model_class.from_config(
        orchestrator.prepare_config_data(parsed)[0],
        context={"state": "merged"},
    )

    assert not existing.get_diff(proposed, exclude_unset=True)
    merged = existing.merge(proposed)
    payload = orchestrator._create_or_update_payload(merged)

    assert payload["networkMode"] == layer
    assert payload["vrfName"] == "Tenant_A"
    if not orchestrator.strategy.is_multicluster:
        assert payload["l2Data"]["vlanName"] == "USERS_OLD"
    assert payload["l3Data"][payload_field] == value
    if orchestrator.strategy.is_parent:
        assert "fabricData" not in payload["l3Data"]
    else:
        assert payload["l3Data"]["fabricData"]["netflow"] is True
        assert payload["l3Data"]["fabricData"]["ipv4Trm"] is True
        assert payload["l3Data"]["fabricData"]["gatewayOnBorder"] is True
    if field_name != "mtu":
        assert payload["l3Data"]["mtu"] == 9216
    assert payload["l3Data"]["arpSuppression"] is True
    assert merged.get_diff(proposed, exclude_unset=True)


def test_sparse_merged_l3_update_preserves_explicit_false_and_nested_fields():
    orchestrator = _orchestrator()
    existing = orchestrator.model_class.from_response(
        {
            "fabricName": "fab1",
            "networkName": "USERS",
            "networkType": "vxlanIbgp",
            "networkMode": "layer3",
            "vrfName": "Tenant_A",
            "l3Data": {
                "gatewayIpv4Address": "192.0.2.1/24",
                "mtu": 9000,
                "arpSuppression": True,
                "fabricData": {"netflow": True, "ipv4Trm": True},
            },
        }
    )
    prepared = orchestrator.prepare_config_data(
        [{"network_name": "USERS", "gateway_ipv4_address": "192.0.2.9/24", "arp_suppression": False, "netflow_enable": False}]
    )[0]
    assert prepared["l3_data"] == {"gatewayIpv4Address": "192.0.2.9/24", "arpSuppression": False, "fabricData": {"netflow": False}}
    proposed = orchestrator.model_class.from_config(prepared, context={"state": "merged"})
    assert not existing.get_diff(proposed, exclude_unset=True)
    merged = existing.merge(proposed)
    payload = orchestrator._create_or_update_payload(merged)
    assert payload["l3Data"]["mtu"] == 9000
    assert payload["l3Data"]["arpSuppression"] is False
    assert payload["l3Data"]["fabricData"]["netflow"] is False
    assert payload["l3Data"]["fabricData"]["ipv4Trm"] is True
    assert merged.get_diff(proposed, exclude_unset=True)


def test_sparse_merged_create_without_layer_is_rejected():
    orchestrator = _orchestrator()
    model = NDNetworkOrchestrator.model_class.from_config(
        orchestrator.prepare_config_data([{"network_name": "USERS", "vlan_name": "USERS_NEW"}])[0],
        context={"state": "merged"},
    )

    with pytest.raises(ValueError, match="layer is required when creating new networks: USERS"):
        orchestrator.preflight_create([model])


@pytest.mark.parametrize(
    "strategy_cls,field,value,payload_field",
    [
        (strategy_cls, field, value, payload_field)
        for strategy_cls in (StandaloneNetworkStrategy, MultisiteParentNetworkStrategy, MulticlusterParentNetworkStrategy)
        for field, value, payload_field in (
            ("arp_suppression", False, "arpSuppression"),
            ("mtu", 9216, "mtu"),
            ("netflow_enable", False, "netflow"),
            ("secondary_gateway_ipv4_collection", [], "secondaryGatewayIpv4Collection"),
            ("dhcp_servers", [], "dhcpServers"),
        )
        if strategy_cls is StandaloneNetworkStrategy or field not in ("netflow_enable", "dhcp_servers")
    ],
)
def test_explicit_definition_defaults_and_empty_lists_reconcile_existing_network(strategy_cls, field, value, payload_field):
    strategy = strategy_cls(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    orchestrator = NDNetworkOrchestrator(rest_send=RestSend({"state": "merged"}), strategy=strategy)
    coordinator = NetworkWorkflowCoordinator(module=_Module({"output_level": "normal"}), strategy=strategy)
    validated = _validated_network_config([{"network_name": "USERS", field: value}])
    parsed = coordinator._parse_config(validated, strategy.config_model_cls, "merged")
    assert parsed[0][field] == value
    assert "layer" not in parsed[0]
    prepared = orchestrator.prepare_config_data(parsed)[0]
    proposed = orchestrator.model_class.from_config(prepared, context={"state": "merged"})
    existing = orchestrator.model_class.from_response(
        {
            "fabricName": "fab1",
            "networkName": "USERS",
            "networkType": "vxlanIbgp",
            "networkMode": "layer3",
            "vrfName": "Tenant_A",
            "l3Data": {
                "gatewayIpv4Address": "192.0.2.1/24",
                "mtu": 9000,
                "arpSuppression": True,
                "secondaryGatewayIpv4Collection": ["198.51.100.1/24"],
                "fabricData": {
                    "netflow": True,
                    "ipv4Trm": True,
                    "dhcpServers": [{"serverAddress": "192.0.2.10", "serverVrf": "management"}],
                },
            },
        }
    )
    assert not existing.get_diff(proposed, exclude_unset=True)
    payload = orchestrator._create_or_update_payload(existing.merge(proposed))
    l3_data = payload["l3Data"]
    target = l3_data["fabricData"] if field in ("netflow_enable", "dhcp_servers") else l3_data
    assert target[payload_field] == value
    assert l3_data["gatewayIpv4Address"] == "192.0.2.1/24"
    if orchestrator.strategy.is_parent:
        assert "fabricData" not in l3_data
    else:
        assert l3_data["fabricData"]["ipv4Trm"] is True
    if field != "mtu":
        assert l3_data["mtu"] == 9000
    if field != "arp_suppression":
        assert l3_data["arpSuppression"] is True
    if field != "netflow_enable" and not orchestrator.strategy.is_parent:
        assert l3_data["fabricData"]["netflow"] is True
    assert orchestrator.model_class.from_response(payload).get_diff(proposed, exclude_unset=True)


@pytest.mark.parametrize("explicit_layer", [False, True])
def test_merged_omitted_definition_defaults_preserve_existing_values(explicit_layer):
    orchestrator = _orchestrator()
    coordinator = NetworkWorkflowCoordinator(module=_Module({"output_level": "normal"}), strategy=orchestrator.strategy)
    config = {"network_name": "USERS", "vlan_name": "USERS_NEW"}
    if explicit_layer:
        config.update(layer="layer3", vrf_name="Tenant_A")
    parsed = coordinator._parse_config(_validated_network_config([config]), orchestrator.strategy.config_model_cls, "merged")
    for field in ("arp_suppression", "mtu", "netflow_enable", "dhcp_servers"):
        assert field not in parsed[0]
    proposed = orchestrator.model_class.from_config(orchestrator.prepare_config_data(parsed)[0])
    existing = orchestrator.model_class.from_response(
        {
            "fabricName": "fab1",
            "networkName": "USERS",
            "networkType": "vxlanIbgp",
            "networkMode": "layer3",
            "vrfName": "Tenant_A",
            "l2Data": {"vlanName": "USERS_OLD", "xConnect": True},
            "l3Data": {"mtu": 9000, "arpSuppression": True, "fabricData": {"netflow": True}},
        }
    )
    assert not existing.get_diff(proposed, exclude_unset=True)
    payload = orchestrator._create_or_update_payload(existing.merge(proposed))
    assert payload["l2Data"]["vlanName"] == "USERS_NEW"
    assert payload["l2Data"]["xConnect"] is True
    assert payload["l3Data"]["mtu"] == 9000
    assert payload["l3Data"]["arpSuppression"] is True
    assert payload["l3Data"]["fabricData"]["netflow"] is True
    assert existing.get_diff(proposed, exclude_unset=True)


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
def test_creation_and_authoritative_network_defaults_are_owned_by_models(state):
    args = crud_module_args({"state": state})
    orchestrator = _orchestrator()
    orchestrator.rest_send.params["state"] = args["state"]
    coordinator = NetworkWorkflowCoordinator(module=_Module({"output_level": "normal"}), strategy=orchestrator.strategy)
    config = _validated_network_config([{"network_name": "USERS", "layer": "layer3", "vrf_name": "Tenant_A", "network_id": 30001}])
    parsed = coordinator._parse_config(config, orchestrator.strategy.config_model_cls, state)
    proposed = orchestrator.model_class.from_config(orchestrator.prepare_config_data(parsed)[0], context={"state": args["state"]})
    orchestrator.preflight_create([proposed])
    payload = orchestrator._create_or_update_payload(proposed)
    assert payload["l2Data"]["xConnect"] is False
    assert payload["l3Data"]["mtu"] == 9216
    assert payload["l3Data"]["arpSuppression"] is False
    assert payload["l3Data"]["fabricData"]["netflow"] is False
    readback = orchestrator.model_class.from_response(payload)
    assert readback.get_diff(proposed, exclude_unset=state == "merged")
    if state != "merged":
        existing_payload = dict(payload)
        existing_payload["l3Data"] = {"mtu": 9000, "arpSuppression": True, "fabricData": {"netflow": True}}
        existing = orchestrator.model_class.from_response(existing_payload)
        assert not existing.get_diff(proposed, exclude_unset=False)


def test_sparse_merged_identity_update_defers_layer_until_existing_merge():
    class Module:
        check_mode = False
        params = {"output_level": "normal"}

        def fail_json(self, **kwargs):
            raise AssertionError(kwargs)

    strategy = StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    coordinator = NetworkWorkflowCoordinator(module=Module(), strategy=strategy)

    parsed = coordinator._parse_config(
        [
            {
                "network_name": "BLUE_NET",
                "network_id": 30001,
                "vlan_id": 2301,
            }
        ],
        strategy.config_model_cls,
        "merged",
    )

    assert parsed == [{"network_name": "BLUE_NET", "network_id": 30001, "vlan_id": 2301}]


@pytest.mark.parametrize("state", ["deleted", "gathered"])
@pytest.mark.parametrize("field_name, value", [("network_id", 30001), ("vlan_id", 2301), ("arp_suppression", False), ("mtu", 9216)])
def test_parse_config_defers_omitted_layer_for_non_write_states(state, field_name, value):
    class Module:
        check_mode = False
        params = {"output_level": "normal"}

        def fail_json(self, **kwargs):
            raise AssertionError(kwargs)

    strategy = StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    coordinator = NetworkWorkflowCoordinator(module=Module(), strategy=strategy)

    parsed = coordinator._parse_config(
        _validated_network_config([{"network_name": "BLUE_NET", field_name: value}]),
        strategy.config_model_cls,
        state,
    )

    assert parsed[0][field_name] == value
    assert "layer" not in parsed[0]
    for default_field in {"mtu", "arp_suppression", "netflow_enable"} - {field_name}:
        assert default_field not in parsed[0]


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize(
    "strategy",
    [
        StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"}),
        _mcfg_parent_orchestrator().strategy,
    ],
)
def test_authoritative_states_reject_implicit_layer3_without_vrf_name(check_mode, strategy):
    class Module:
        params = {"output_level": "normal"}

        def __init__(self):
            self.check_mode = check_mode

        def fail_json(self, **kwargs):
            raise AssertionError(kwargs)

    coordinator = NetworkWorkflowCoordinator(module=Module(), strategy=strategy)

    with pytest.raises(AssertionError, match="vrf_name is required for layer3 and layer2WithVrf networks"):
        coordinator._parse_config(
            [
                {
                    "network_name": "BLUE_NET",
                    "network_id": 30001,
                    "vlan_id": 2301,
                }
            ],
            strategy.config_model_cls,
            "replaced",
        )


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("explicit_layer", [False, True])
@pytest.mark.parametrize("strategy_cls", [StandaloneNetworkStrategy])
def test_primary_network_l3_fields_survive_validation_and_payload(state, explicit_layer, strategy_cls):
    args = crud_module_args({"state": state})
    strategy = strategy_cls(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    orchestrator = NDNetworkOrchestrator(rest_send=RestSend({"state": args["state"]}), strategy=strategy)
    coordinator = NetworkWorkflowCoordinator(module=_Module({"output_level": "normal"}), strategy=strategy)
    config = {
        "network_name": "PVLAN_PRIMARY",
        "network_id": 30001,
        "vlan_id": 2301,
        "vlan_network_type": "primary",
        "vrf_name": "Tenant_A",
        "gateway_ipv4_address": "192.0.2.1/24",
        "gateway_ipv6_address": "2001:db8::1/64",
        "mtu": 9000,
    }
    if explicit_layer:
        config["layer"] = "layer3"
    parsed = coordinator._parse_config(_validated_network_config([config]), strategy.config_model_cls, state)
    assert parsed[0].get("layer") == (None if state == "merged" and not explicit_layer else "layer3")
    proposed = orchestrator.model_class.from_config(orchestrator.prepare_config_data(parsed)[0], context={"state": args["state"]})
    if state == "merged":

        class Snapshot:
            existing = NDConfigCollection(model_class=orchestrator.model_class)
            proposed = NDConfigCollection(model_class=orchestrator.model_class)

        snapshot = Snapshot()
        snapshot.proposed.add(proposed)
        coordinator._resolve_proposed_networks(snapshot, parsed, state, strategy)
    orchestrator.preflight_create([proposed])
    payload = orchestrator._create_or_update_payload(proposed)
    assert payload["vlanNetworkType"] == "privatePrimary"
    assert payload["networkMode"] == "layer3"
    assert payload["vrfName"] == "Tenant_A"
    assert payload["l3Data"]["gatewayIpv4Address"] == "192.0.2.1/24"
    assert payload["l3Data"]["gatewayIpv6Address"] == "2001:db8::1/64"
    assert payload["l3Data"]["mtu"] == 9000
    assert orchestrator.model_class.from_response(payload).get_diff(proposed, exclude_unset=state == "merged")


def test_primary_network_l2_definition_without_l3_intent_derives_layer2():
    config = NetworkConfigModel.from_config({"network_name": "PVLAN_PRIMARY", "vlan_network_type": "primary", "network_id": 30001})
    assert config.layer == "layer2"
    orchestrator = _orchestrator()
    proposed = orchestrator.model_class.from_config(orchestrator.prepare_config_data([config.to_config(exclude_unset=True)])[0])
    payload = orchestrator._create_or_update_payload(proposed)
    assert payload["networkMode"] == "layer2"
    assert payload["vrfName"] == "NA"
    assert "l3Data" not in payload


@pytest.mark.parametrize("explicit_layer", [False, True])
def test_primary_network_with_l3_requires_vrf(explicit_layer):
    config = {
        "network_name": "PVLAN_PRIMARY",
        "network_id": 30001,
        "vlan_id": 2301,
        "vlan_network_type": "primary",
        "gateway_ipv4_address": "192.0.2.1/24",
    }
    if explicit_layer:
        config["layer"] = "layer3"
    with pytest.raises(ValueError, match="vrf_name is required for layer3"):
        NetworkConfigModel.from_config(config)


def test_primary_network_sparse_l3_update_inherits_existing_layer_and_vrf():
    orchestrator = _orchestrator()
    coordinator = NetworkWorkflowCoordinator(module=_Module({"output_level": "normal"}), strategy=orchestrator.strategy)
    config = [{"network_name": "PVLAN_PRIMARY", "vlan_network_type": "primary", "gateway_ipv4_address": "192.0.2.9/24"}]
    parsed = coordinator._parse_config(_validated_network_config(config), orchestrator.strategy.config_model_cls, "merged")
    assert "layer" not in parsed[0]
    proposed = orchestrator.model_class.from_config(orchestrator.prepare_config_data(parsed)[0])
    existing = orchestrator.model_class.from_response(
        {
            "networkName": "PVLAN_PRIMARY",
            "networkType": "vxlanIbgp",
            "networkMode": "layer3",
            "vlanNetworkType": "privatePrimary",
            "vrfName": "Tenant_A",
            "l3Data": {"gatewayIpv4Address": "192.0.2.1/24", "mtu": 9000},
        }
    )
    assert not existing.get_diff(proposed, exclude_unset=True)
    payload = orchestrator._create_or_update_payload(existing.merge(proposed))
    assert payload["networkMode"] == "layer3"
    assert payload["vrfName"] == "Tenant_A"
    assert payload["l3Data"]["gatewayIpv4Address"] == "192.0.2.9/24"
    assert payload["l3Data"]["mtu"] == 9000
    assert orchestrator.model_class.from_response(payload).get_diff(proposed, exclude_unset=True)


def test_sparse_merged_network_keeps_existing_pvlan_type_when_omitted():
    orchestrator = _orchestrator()
    proposed = orchestrator.model_class.from_config(orchestrator.prepare_config_data([{"network_name": "PVLAN_PRIMARY", "display_name": "UPDATED"}])[0])
    existing = orchestrator.model_class.from_response(
        {"networkName": "PVLAN_PRIMARY", "networkType": "vxlanIbgp", "vlanNetworkType": "privatePrimary", "networkMode": "layer2", "vrfName": "NA"}
    )

    assert "vlan_network_type" not in proposed.model_fields_set
    assert existing.model_copy(deep=True).merge(proposed).vlan_network_type == VlanNetworkType.PRIVATE_PRIMARY


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("strategy_cls", [StandaloneNetworkStrategy, MultisiteParentNetworkStrategy])
@pytest.mark.parametrize("layer", ["layer2", "layer3"])
def test_sparse_primary_vlan_name_update_preserves_omitted_pvlan_type(check_mode, strategy_cls, layer):
    inventory = [
        {
            "fabricName": "fab1",
            "networkName": "PRIMARY",
            "networkType": "vxlanIbgp",
            "networkMode": layer,
            "vlanNetworkType": "privatePrimary",
            "vrfName": "T" if layer == "layer3" else "NA",
            "networkId": 30001,
            "l2Data": {"vlanName": "OLD"},
        }
    ]
    config = [{"network_name": "PRIMARY", "vlan_name": "NEW"}]
    coordinator, sm, parsed, orchestrator = _layer_validation_state_machine(config, inventory, check_mode, strategy_cls)
    assert "vlan_network_type" not in parsed[0]
    coordinator._resolve_proposed_networks(sm, parsed, "merged", orchestrator.strategy)
    assert "vlan_network_type" not in sm.proposed.get("PRIMARY").model_fields_set
    sm.manage_state()

    assert sm.output.format()["changed"] is True
    assert len(orchestrator.written_payloads) == (0 if check_mode else 1)
    payload = orchestrator._create_or_update_payload(sm.sent.get("PRIMARY"))
    assert payload["vlanNetworkType"] == "privatePrimary"
    assert payload["l2Data"]["vlanName"] == "NEW"
    assert payload["networkMode"] == layer

    repeat_coordinator, repeat_sm, repeat_parsed, repeat_orchestrator = _layer_validation_state_machine(config, [payload], check_mode, strategy_cls)
    repeat_coordinator._resolve_proposed_networks(repeat_sm, repeat_parsed, "merged", repeat_orchestrator.strategy)
    repeat_sm.manage_state()
    assert repeat_sm.output.format()["changed"] is False
    assert repeat_orchestrator.written_payloads == []


class _LayerValidationNetworkOrchestrator(NDNetworkOrchestrator):
    """Exercise real state-machine planning with an in-memory controller boundary."""

    inventory: list[dict] = []
    query_count: int = 0
    written_payloads: list[dict] = []

    def query_all(self, **kwargs):
        self.query_count += 1
        return self.inventory

    def update(self, model_instance, **kwargs):
        self.written_payloads.append(self._create_or_update_payload(model_instance))
        return {}

    def create_bulk(self, model_instances, **kwargs):
        self.written_payloads.extend(self._create_or_update_payload(model) for model in model_instances)
        return {}


def _layer_validation_state_machine(config, inventory, check_mode, strategy_cls=StandaloneNetworkStrategy, network_type="vxlanIbgp"):
    strategy = strategy_cls(fabric_name="fab1", fabric_data={"managementType": network_type})
    module = _Module({"state": "merged", "config": config, "output_level": "normal"})
    module.check_mode = check_mode
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=strategy)
    parsed = coordinator._parse_config(_validated_network_config(config), strategy.config_model_cls, "merged")
    orchestrator = _LayerValidationNetworkOrchestrator(rest_send=RestSend({"state": "merged"}), strategy=strategy, inventory=inventory)
    sm = NDStateMachine(module=module, model_orchestrator=orchestrator, config=orchestrator.prepare_config_data(parsed))
    return coordinator, sm, parsed, orchestrator


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_external_network_three_field_definition_defaults_to_layer2(state, check_mode):
    entry = {"network_name": "EXTERNAL_NET", "vlan_id": 2984, "vlan_name": "EXTERNAL_VLAN"}
    strategy = StandaloneNetworkStrategy(fabric_name="external", fabric_data={"managementType": "externalConnectivity"})
    module = _Module({"state": state, "config": [entry], "output_level": "normal"})
    module.check_mode = check_mode
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=strategy)
    parsed = coordinator._parse_config(_validated_network_config([entry]), strategy.config_model_cls, state)
    orchestrator = _LayerValidationNetworkOrchestrator(rest_send=RestSend({"state": state}), strategy=strategy, inventory=[])
    sm = NDStateMachine(module=module, model_orchestrator=orchestrator, config=orchestrator.prepare_config_data(parsed))
    if state == "merged":
        coordinator._resolve_proposed_networks(sm, parsed, state, strategy)
    sm.manage_state()

    payload = orchestrator._create_or_update_payload(sm.sent.get("EXTERNAL_NET"))
    assert payload["networkType"] == "externalConnectivity"
    assert payload["networkMode"] == "layer2"
    assert payload["vrfName"] == "NA"
    assert payload["vlanId"] == 2984
    assert payload["l2Data"]["vlanName"] == "EXTERNAL_VLAN"
    assert "networkId" not in payload
    assert sm.output.format()["changed"] is True
    assert len(orchestrator.written_payloads) == (0 if check_mode else 1)


def test_external_sparse_merged_update_preserves_existing_layer3():
    entry = {"network_name": "EXTERNAL_NET", "vlan_name": "UPDATED"}
    existing = {
        "fabricName": "fab1",
        "networkName": "EXTERNAL_NET",
        "networkType": "externalConnectivity",
        "networkMode": "layer3",
        "vrfName": "TENANT",
        "l2Data": {"vlanName": "OLD"},
    }
    coordinator, sm, parsed, orchestrator = _layer_validation_state_machine([entry], [existing], False, network_type="externalConnectivity")
    coordinator._resolve_proposed_networks(sm, parsed, "merged", orchestrator.strategy)
    assert sm.proposed.get("EXTERNAL_NET").layer == "layer3"
    sm.manage_state()
    payload = orchestrator.written_payloads[0]
    assert payload["networkMode"] == "layer3"
    assert payload["vrfName"] == "TENANT"
    assert payload["l2Data"]["vlanName"] == "UPDATED"


def test_external_network_three_field_repeat_is_idempotent():
    entry = {"network_name": "EXTERNAL_NET", "vlan_id": 2984, "vlan_name": "EXTERNAL_VLAN"}
    inventory = [
        {
            "fabricName": "fab1",
            "networkName": "EXTERNAL_NET",
            "networkType": "externalConnectivity",
            "networkMode": "layer2",
            "networkId": 30001,
            "vlanId": 2984,
            "vrfName": "NA",
            "l2Data": {"vlanName": "EXTERNAL_VLAN"},
        }
    ]
    coordinator, sm, parsed, orchestrator = _layer_validation_state_machine([entry], inventory, False, network_type="externalConnectivity")
    coordinator._resolve_proposed_networks(sm, parsed, "merged", orchestrator.strategy)
    sm.manage_state()

    assert sm.output.format()["changed"] is False
    assert orchestrator.written_payloads == []
    assert orchestrator.query_count == 1


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("strategy_cls", [StandaloneNetworkStrategy, MultisiteParentNetworkStrategy])
@pytest.mark.parametrize("layer", ["layer3", "layer2WithVrf"])
@pytest.mark.parametrize("update", [{"vlan_name": "NEW_NAME"}, {"mtu": 9100}, {"arp_suppression": False}])
def test_sparse_primary_update_keeps_existing_mode_through_real_state_machine(check_mode, strategy_cls, layer, update):
    inventory = [
        {
            "fabricName": "fab1",
            "networkName": "PRIMARY",
            "networkType": "vxlanIbgp",
            "networkMode": layer,
            "vlanNetworkType": "privatePrimary",
            "vrfName": "T",
            "networkId": 30001,
            "l2Data": {"vlanName": "OLD_NAME"},
            "l3Data": {"gatewayIpv4Address": "192.0.2.1/24", "mtu": 9000, "arpSuppression": True},
        }
    ]
    config = [{"network_name": "PRIMARY", "vlan_network_type": "primary", **update}]
    coordinator, sm, parsed, orchestrator = _layer_validation_state_machine(config, inventory, check_mode, strategy_cls)
    assert "layer" not in parsed[0]
    coordinator._resolve_proposed_networks(sm, parsed, "merged", orchestrator.strategy)
    assert sm.before.get("PRIMARY").layer == layer
    sm.manage_state()
    payload = orchestrator._create_or_update_payload(sm.sent.get("PRIMARY"))
    assert payload["networkMode"] == layer
    assert payload["vrfName"] == "T"
    assert payload["l3Data"]["gatewayIpv4Address"] == "192.0.2.1/24"
    if "mtu" in update:
        assert payload["l3Data"]["mtu"] == update["mtu"]
    if "arp_suppression" in update:
        assert payload["l3Data"]["arpSuppression"] is False
    if "vlan_name" in update:
        assert payload["l2Data"]["vlanName"] == "NEW_NAME"
    assert len(orchestrator.written_payloads) == (0 if check_mode else 1)
    assert orchestrator.query_count == 1
    repeat = orchestrator.model_class.from_response(payload)
    if strategy_cls is StandaloneNetworkStrategy:
        assert repeat.get_diff(sm.proposed.get("PRIMARY"), exclude_unset=True)


@pytest.mark.parametrize("state", ["replaced", "overridden", "staged"])
@pytest.mark.parametrize("with_vrf", [False, True])
def test_authoritative_primary_mtu_intent_uses_l3_and_requires_vrf(state, with_vrf):
    orchestrator = _orchestrator()
    orchestrator.rest_send.params["state"] = crud_module_args({"state": state})["state"]
    coordinator = NetworkWorkflowCoordinator(module=_Module({"output_level": "normal"}), strategy=orchestrator.strategy)
    entry = {"network_name": "PRIMARY", "vlan_network_type": "primary", "network_id": 30001, "mtu": 9000}
    if not with_vrf:
        with pytest.raises(AssertionError, match="vrf_name is required"):
            coordinator._parse_config(_validated_network_config([entry]), orchestrator.strategy.config_model_cls, state)
    else:
        entry["vrf_name"] = "T"
        parsed = coordinator._parse_config(_validated_network_config([entry]), orchestrator.strategy.config_model_cls, state)
        proposed = orchestrator.model_class.from_config(orchestrator.prepare_config_data(parsed)[0])
        payload = orchestrator._create_or_update_payload(proposed)
        assert payload["networkMode"] == "layer3"
        assert payload["l3Data"]["mtu"] == 9000
        assert payload["vrfName"] == "T"


def test_sparse_l2_primary_rename_preserves_layer2_without_l3_defaults():
    inventory = [
        {
            "networkName": "PRIMARY",
            "networkType": "vxlanIbgp",
            "networkMode": "layer2",
            "vlanNetworkType": "privatePrimary",
            "vrfName": "NA",
            "l2Data": {"vlanName": "OLD_NAME"},
        }
    ]
    coordinator, sm, parsed, orchestrator = _layer_validation_state_machine(
        [{"network_name": "PRIMARY", "vlan_network_type": "primary", "vlan_name": "NEW_NAME"}], inventory, False
    )
    coordinator._resolve_proposed_networks(sm, parsed, "merged", orchestrator.strategy)
    sm.manage_state()
    assert orchestrator.written_payloads[0]["networkMode"] == "layer2"
    assert orchestrator.written_payloads[0]["l2Data"]["vlanName"] == "NEW_NAME"
    assert "l3Data" not in orchestrator.written_payloads[0]
    assert orchestrator.query_count == 1


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("update", [{"gateway_ipv4_address": "192.0.2.9/24"}, {"mtu": 9216}, {"arp_suppression": False}])
def test_sparse_primary_l3_fields_on_existing_l2_fail_before_writes(check_mode, update):
    inventory = [{"networkName": "PRIMARY", "networkType": "vxlanIbgp", "networkMode": "layer2", "vlanNetworkType": "privatePrimary", "vrfName": "NA"}]
    coordinator, sm, parsed, orchestrator = _layer_validation_state_machine(
        [{"network_name": "PRIMARY", "vlan_network_type": "primary", **update}], inventory, check_mode
    )
    with pytest.raises(ValueError, match="layer2 networks do not support L3 properties"):
        coordinator._resolve_proposed_networks(sm, parsed, "merged", orchestrator.strategy)
    assert orchestrator.written_payloads == []
    assert orchestrator.query_count == 1
    assert sm.before.get("PRIMARY").layer == "layer2"


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("with_vrf", [False, True])
def test_new_primary_mtu_intent_resolves_to_l3_or_fails_before_create(check_mode, with_vrf):
    config = {"network_name": "PRIMARY", "vlan_network_type": "primary", "network_id": 30001, "mtu": 9000}
    if with_vrf:
        config["vrf_name"] = "T"
    coordinator, sm, parsed, orchestrator = _layer_validation_state_machine([config], [], check_mode)
    if not with_vrf:
        with pytest.raises(ValueError, match="vrf_name is required"):
            coordinator._resolve_proposed_networks(sm, parsed, "merged", orchestrator.strategy)
        assert orchestrator.written_payloads == []
    else:
        coordinator._resolve_proposed_networks(sm, parsed, "merged", orchestrator.strategy)
        sm.manage_state()
        payload = orchestrator._create_or_update_payload(sm.sent.get("PRIMARY"))
        assert payload["networkMode"] == "layer3"
        assert payload["vrfName"] == "T"
        assert payload["l3Data"]["mtu"] == 9000
        assert len(orchestrator.written_payloads) == (0 if check_mode else 1)
    assert orchestrator.query_count == 1


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("field,value", [("gateway_ipv4_address", "192.0.2.1/24"), ("mtu", 9216), ("arp_suppression", False)])
def test_explicit_l2_primary_rejects_l3_fields_in_all_write_states(state, field, value):
    coordinator = NetworkWorkflowCoordinator(module=_Module({"output_level": "normal"}), strategy=_orchestrator().strategy)
    with pytest.raises(AssertionError, match="layer2 networks do not support L3 properties"):
        coordinator._parse_config(
            _validated_network_config([{"network_name": "PRIMARY", "vlan_network_type": "primary", "layer": "layer2", field: value}]),
            coordinator.strategy.config_model_cls,
            state,
        )


@pytest.mark.parametrize("state", ["deleted", "gathered"])
@pytest.mark.parametrize("layer", [None, "layer2", "layer3", "layer2WithVrf"])
def test_primary_read_delete_selectors_do_not_require_create_layer_bindings(state, layer):
    coordinator = NetworkWorkflowCoordinator(module=_Module({"output_level": "normal"}), strategy=_orchestrator().strategy)
    entry = {"network_name": "PRIMARY", "vlan_network_type": "primary", "network_id": 30001, "gateway_ipv4_address": "192.0.2.1/24"}
    if layer is not None:
        entry["layer"] = layer
    parsed = coordinator._parse_config(_validated_network_config([entry]), coordinator.strategy.config_model_cls, state)
    assert parsed[0]["network_id"] == 30001
    assert parsed[0].get("layer") == layer


def test_network_definition_intent_fields_are_shared_with_orchestrator():
    assert NDNetworkOrchestrator.definition_intent_fields is NETWORK_DEFINITION_INTENT_FIELDS


def test_parent_child_only_config_defers_omitted_layer():
    class Module:
        check_mode = False
        params = {"output_level": "normal"}

        def fail_json(self, **kwargs):
            raise AssertionError(kwargs)

    strategy = _mcfg_parent_orchestrator().strategy
    coordinator = NetworkWorkflowCoordinator(module=Module(), strategy=strategy)

    parsed = coordinator._parse_config(
        [
            {
                "network_name": "BLUE_NET",
                "child_fabric_config": [
                    {
                        "fabric_name": "child1",
                        "multicast_group_address": "239.1.1.10",
                    }
                ],
            }
        ],
        strategy.config_model_cls,
        "merged",
    )

    assert parsed == [
        {
            "network_name": "BLUE_NET",
            "child_fabric_config": [
                {
                    "fabric_name": "child1",
                    "multicast_group_address": "239.1.1.10",
                }
            ],
        }
    ]


def test_mcfg_parent_workflow_validates_but_skips_child_network_crud():
    class Module:
        check_mode = False
        params = {"output_level": "normal"}

        def fail_json(self, **kwargs):
            raise AssertionError(kwargs)

    strategy = MulticlusterParentNetworkStrategy(
        fabric_name="MCFG_FAB",
        fabric_data={
            "managementType": "vxlan",
            "members": [{"fabricName": "child1", "fabricState": "member", "clusterName": "cluster1"}],
        },
    )
    coordinator = NetworkWorkflowCoordinator(module=Module(), strategy=strategy)
    parent_args_seen = {}

    def run_parent(module_args, strategy=None, defer_deploy=False):
        parent_args_seen.update(module_args)
        return {"changed": True, "failed": False, "before": [], "after": [], "diff": []}

    def run_child(_child_task):
        raise AssertionError("MCFG Network parent workflow should not run child CRUD tasks")

    object.__setattr__(coordinator, "_run_state_machine_with_attachments", run_parent)
    object.__setattr__(coordinator, "_run_child_task", run_child)

    result = coordinator._handle_parent_workflow(
        {
            "fabric_name": "MCFG_FAB",
            "state": "merged",
            "config": [
                {
                    "network_name": "BLUE_NET",
                    "layer": "layer2",
                    "child_fabric_config": [{"fabric_name": "child1"}],
                }
            ],
        },
        "multicluster_parent",
    )

    assert result["changed"] is True
    assert result["workflow"] == "Multicluster Parent without Child Fabric Processing"
    assert parent_args_seen["config"][0]["network_name"] == "BLUE_NET"
    assert "child_fabric_config" not in parent_args_seen["config"][0]


def test_child_task_exception_returns_structured_network_failure():
    class Module:
        params = {"output_level": "debug"}
        _verbosity = 3

    class ChildStrategy:
        fabric_type = "multicluster_child"

    coordinator = NetworkWorkflowCoordinator(module=Module(), strategy=_mcfg_parent_orchestrator().strategy)

    def raise_child(*_args, **_kwargs):
        raise RuntimeError("child network route failed")

    object.__setattr__(coordinator, "_run_state_machine", raise_child)
    child_result = coordinator._run_child_task(
        {
            "module_args": {"config": [{"network_name": "BLUE_NET"}]},
            "strategy": ChildStrategy(),
        }
    )
    child_result["child_fabric"] = "nac-msd-fabric2"

    result = coordinator._build_structured_result(
        {"changed": True, "failed": False, "before": [], "after": [], "diff": []},
        [child_result],
        "MCFG_FAB",
        "multicluster_parent",
        "multicluster",
    )

    assert result["changed"] is True
    assert result["failed"] is True
    assert "nac-msd-fabric2" in result["msg"]
    child = result["child_fabrics"][0]
    assert child["fabric_name"] == "nac-msd-fabric2"
    assert child["fabric_type"] == "multicluster_child"
    assert child["failed"] is True
    assert child["msg"] == "child network route failed"
    assert child["exception"] == "RuntimeError"
    assert child["proposed"] == [{"network_name": "BLUE_NET"}]
    assert child["workflow_trace"][-1]["event"] == "child_task_error"
    assert child["workflow_trace"][-1]["exception"] == "RuntimeError"


def test_argument_spec_leaves_definition_defaults_to_models():
    spec = network_module_argument_spec()

    for field in ("mtu", "arp_suppression", "netflow_enable"):
        assert "default" not in spec[field]
    assert "mtu_l3intf" not in spec
    assert "arp_suppress" not in spec
    assert "default" not in spec["trm_enable"]
    assert "default" not in spec["ipv6_trm"]
    assert "enable_ir" not in spec
    assert "rt_auto" not in spec
    assert "route_target_both" not in spec
    assert "route_target_both" not in spec["child_fabric_config"]["options"]
    assert spec["dhcp_servers"]["options"]["server_address"]["required"] is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("x_connect", False),
        ("multicast_group_address", "239.1.1.53"),
        ("dhcp_servers", [{"server_address": "192.0.2.10", "server_vrf": "management"}]),
        ("loopback_id", 101),
        ("trm_enable", True),
        ("igmp_version", 3),
        ("ipv6_trm", True),
        ("netflow_enable", False),
        ("vlan_netflow_monitor", "VLAN_MON"),
        ("interface_netflow_monitor", "INT_MON"),
        ("gateway_on_border", False),
    ],
)
def test_network_msd_child_only_options_remain_in_module_union(field, value):
    parent_spec = network_parent_argument_spec()
    module_spec = network_module_argument_spec()
    standalone_spec = network_base_argument_spec()
    mcfg_spec = MulticlusterParentNetworkStrategy(fabric_name="MCFG_P", fabric_data={}).get_argument_spec()

    assert field not in parent_spec
    assert field in parent_spec["child_fabric_config"]["options"]
    assert field in module_spec
    assert field in standalone_spec
    assert field not in mcfg_spec

    validator = ArgumentSpecValidator({"config": {"type": "list", "elements": "dict", "options": module_spec}})
    accepted = validator.validate({"config": [{"network_name": "N", field: value}]})
    assert not accepted.error_messages
    assert accepted.validated_parameters["config"][0][field] == value


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("fabric_type", ["multisite_parent", "multicluster_parent"])
def test_parent_trm_input_is_filtered_before_network_write(state, fabric_type):
    strategy_cls = MultisiteParentNetworkStrategy if fabric_type == "multisite_parent" else MulticlusterParentNetworkStrategy
    strategy = strategy_cls(fabric_name="PARENT", fabric_data={"managementType": "vxlanIbgp", "members": []})
    module = _Module(
        {
            "fabric_name": "PARENT",
            "state": state,
            "config": [{"network_name": "N", "layer": "layer3", "vrf_name": "BLUE", "trm_enable": True, "igmp_version": 3, "ipv6_trm": False}],
        }
    )
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=strategy)
    received = []

    def record_parent_config(args, **_kwargs):
        received.extend(args["config"])
        return {"changed": False}

    coordinator._run_state_machine_with_attachments = record_parent_config

    result = coordinator._handle_parent_workflow(dict(module.params), fabric_type)

    assert result["changed"] is False
    assert received == [{"network_name": "N", "layer": "layer3", "vrf_name": "BLUE"}]


@pytest.mark.parametrize("fabric_type", ["multisite_parent", "multicluster_parent"])
def test_parent_trm_only_merged_entry_has_no_definition_intent(fabric_type):
    strategy_cls = MultisiteParentNetworkStrategy if fabric_type == "multisite_parent" else MulticlusterParentNetworkStrategy
    strategy = strategy_cls(fabric_name="PARENT", fabric_data={"managementType": "vxlanIbgp", "members": []})
    coordinator = NetworkWorkflowCoordinator(_Module({"state": "merged", "config": []}), strategy)

    parsed = coordinator._parse_config(
        [{"network_name": "N", "trm_enable": True, "igmp_version": 3, "ipv6_trm": False}],
        NetworkParentConfigModel,
        "merged",
    )

    assert parsed == [{"network_name": "N"}]
    assert not NDNetworkOrchestrator.has_network_definition_intent(parsed[0])


def test_parent_gathered_output_omits_child_only_trm_options():
    module = _Module({"fabric_name": "msd_p", "state": "gathered", "config": []})
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=_ParentStrategy())
    coordinator._run_state_machine_with_attachments = lambda *_args, **_kwargs: {
        "changed": False,
        "gathered": [{"network_name": "N", "arp_suppression": True, "trm_enable": False, "ipv6_trm": False, "igmp_version": 3}],
    }

    result = coordinator._handle_parent_workflow(dict(module.params), "multisite_parent")

    assert result["gathered"] == [{"network_name": "N", "arp_suppression": True}]


def test_network_query_all_scopes_targeted_state_reads_with_batch_filter():
    strategy = StandaloneNetworkStrategy(
        fabric_name="fab1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend(
            {
                "state": "replaced",
                "config": [
                    {"network_name": "BLUE_NET"},
                    {"network_name": "GREEN_NET"},
                    {"network_name": "BLUE_NET"},
                ],
                "check_mode": False,
            }
        ),
        strategy=strategy,
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {
            "networks": [
                {"networkName": "BLUE_NET"},
                {"networkName": "GREEN_NET"},
            ]
        }

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [
        {"networkName": "BLUE_NET", "fabricName": "fab1"},
        {"networkName": "GREEN_NET", "fabricName": "fab1"},
    ]
    assert requested_paths == [
        "/api/v1/manage/fabrics/fab1/networks?max=10000&filter=%28BLUE_NET%20OR%20GREEN_NET%29",
    ]


def test_network_filter_builders_return_raw_expressions_for_endpoint_encoding():
    names = ["GREEN/NET", "BLUE NET&50%"]

    assert network_name_filter(names) == "(networkName:BLUE NET&50% OR networkName:GREEN/NET)"
    assert NDNetworkOrchestrator._network_name_filter(names) == "(networkName:BLUE NET&50% OR networkName:GREEN/NET)"
    assert NDNetworkOrchestrator._network_names_unfielded_filter(names) == "(BLUE NET&50% OR GREEN/NET)"


def test_network_query_all_encodes_reserved_filter_characters_once():
    network_name = "BLUE NET&50%"
    strategy = StandaloneNetworkStrategy(
        fabric_name="fab1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend(
            {
                "state": "replaced",
                "config": [{"network_name": network_name}],
                "check_mode": False,
            }
        ),
        strategy=strategy,
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {"networks": [{"networkName": network_name}]}

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [{"networkName": network_name, "fabricName": "fab1"}]
    assert requested_paths == [
        "/api/v1/manage/fabrics/fab1/networks?filter=networkName%3ABLUE%20NET%2650%25",
    ]


def test_network_query_all_scoped_falls_back_to_unfiltered_when_batch_query_fails():
    strategy = StandaloneNetworkStrategy(
        fabric_name="fab1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend(
            {
                "state": "replaced",
                "config": [
                    {"network_name": "BLUE_NET"},
                    {"network_name": "GREEN_NET"},
                ],
                "check_mode": False,
            }
        ),
        strategy=strategy,
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        if len(requested_paths) == 1:
            raise RuntimeError("batch filter rejected")
        return {
            "networks": [
                {"networkName": "BLUE_NET"},
                {"networkName": "GREEN_NET"},
            ]
        }

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [
        {"networkName": "BLUE_NET", "fabricName": "fab1"},
        {"networkName": "GREEN_NET", "fabricName": "fab1"},
    ]
    assert requested_paths == [
        "/api/v1/manage/fabrics/fab1/networks?max=10000&filter=%28BLUE_NET%20OR%20GREEN_NET%29",
        "/api/v1/manage/fabrics/fab1/networks?offset=0&max=10000",
    ]


def test_network_query_all_scoped_filters_unfielded_batch_query_locally():
    strategy = StandaloneNetworkStrategy(
        fabric_name="fab1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend(
            {
                "state": "merged",
                "config": [
                    {"network_name": "BLUE_NET"},
                    {"network_name": "GREEN_NET"},
                ],
                "check_mode": False,
            }
        ),
        strategy=strategy,
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {
            "networks": [
                {"networkName": "BLUE_NET"},
                {"networkName": "GREEN_NET"},
                {"networkName": "OTHER_NET"},
            ]
        }

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [
        {"networkName": "BLUE_NET", "fabricName": "fab1"},
        {"networkName": "GREEN_NET", "fabricName": "fab1"},
    ]
    assert requested_paths == [
        "/api/v1/manage/fabrics/fab1/networks?max=10000&filter=%28BLUE_NET%20OR%20GREEN_NET%29",
    ]


def test_network_query_all_uses_unfiltered_read_at_scoped_threshold():
    strategy = StandaloneNetworkStrategy(
        fabric_name="fab1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend(
            {
                "state": "merged",
                "config": [{"network_name": f"NET_{index}"} for index in range(5)],
                "check_mode": False,
            }
        ),
        strategy=strategy,
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {"networks": [{"networkName": "NET_0"}]}

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [{"networkName": "NET_0", "fabricName": "fab1"}]
    assert requested_paths == ["/api/v1/manage/fabrics/fab1/networks?offset=0&max=10000"]


def test_network_query_all_unfiltered_reads_500_networks_with_explicit_page_size():
    orchestrator = _orchestrator()
    requested_paths = []
    networks = [{"networkName": f"NET_{index:03d}"} for index in range(500)]

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {
            "networks": networks,
            "metadata": {
                "counts": {
                    "total": 500,
                    "remaining": 0,
                }
            },
        }

    object.__setattr__(orchestrator, "_request", request)

    result = orchestrator.query_all()

    assert len(result) == 500
    assert result[0]["networkName"] == "NET_000"
    assert result[-1]["networkName"] == "NET_499"
    assert requested_paths == ["/api/v1/manage/fabrics/fab1/networks?offset=0&max=10000"]


def test_network_query_all_unfiltered_walks_paginated_results():
    orchestrator = _orchestrator()
    original_page_size = NDNetworkOrchestrator.unfiltered_query_page_size
    NDNetworkOrchestrator.unfiltered_query_page_size = 200
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        if "offset=0" in kwargs["path"]:
            return {
                "networks": [{"networkName": f"NET_{index:03d}"} for index in range(200)],
                "metadata": {"counts": {"total": 500, "remaining": 300}},
            }
        if "offset=200" in kwargs["path"]:
            return {
                "networks": [{"networkName": f"NET_{index:03d}"} for index in range(200, 400)],
                "metadata": {"counts": {"total": 500, "remaining": 100}},
            }
        return {
            "networks": [{"networkName": f"NET_{index:03d}"} for index in range(400, 500)],
            "metadata": {"counts": {"total": 500, "remaining": 0}},
        }

    object.__setattr__(orchestrator, "_request", request)

    try:
        result = orchestrator.query_all()
    finally:
        NDNetworkOrchestrator.unfiltered_query_page_size = original_page_size

    assert len(result) == 500
    assert requested_paths == [
        "/api/v1/manage/fabrics/fab1/networks?offset=0&max=200",
        "/api/v1/manage/fabrics/fab1/networks?offset=200&max=200",
        "/api/v1/manage/fabrics/fab1/networks?offset=400&max=200",
    ]


def test_attachment_shape_rejects_ports_and_defaults_missing_interfaces():
    model = NetworkConfigModel.from_config(
        {
            "network_name": "ATTACH_SHAPE",
            "layer": "layer2",
            "attach": [
                {
                    "ip_address": "10.1.1.11",
                    "interfaces": [
                        {
                            "mode": "access",
                            "interface_range": "Ethernet1/1",
                        }
                    ],
                    "deploy": False,
                }
            ],
        }
    )
    attach = model.to_config()["attach"][0]

    assert attach["deploy"] is False
    assert attach["interfaces"][0]["interface_range"] == "Ethernet1/1"

    omitted = NetworkConfigModel.from_config(
        {
            "network_name": "ATTACH_NO_INTERFACES",
            "layer": "layer2",
            "attach": [
                {
                    "ip_address": "10.1.1.11",
                }
            ],
        }
    )

    assert omitted.to_config()["attach"][0]["interfaces"] == []

    with pytest.raises(ValueError, match="ports"):
        NetworkConfigModel.from_config(
            {
                "network_name": "ATTACH_PORTS",
                "layer": "layer2",
                "attach": [
                    {
                        "ip_address": "10.1.1.11",
                        "ports": ["Ethernet1/1"],
                    }
                ],
            }
        )

    with pytest.raises(ValueError, match="mode"):
        NetworkConfigModel.from_config(
            {
                "network_name": "MISSING_MODE",
                "layer": "layer2",
                "attach": [
                    {
                        "ip_address": "10.1.1.11",
                        "interfaces": [{"interface_range": "Ethernet1/1"}],
                    }
                ],
            }
        )

    with pytest.raises(ValueError, match="interface_range|interfaceRange"):
        NetworkConfigModel.from_config(
            {
                "network_name": "MISSING_RANGE",
                "layer": "layer2",
                "attach": [
                    {
                        "ip_address": "10.1.1.11",
                        "interfaces": [{"mode": "access"}],
                    }
                ],
            }
        )


def test_attachment_options_replace_instance_values():
    model = NetworkConfigModel.from_config(
        {
            "network_name": "ATTACH_OPTIONS",
            "layer": "layer2",
            "attach": [
                {
                    "ip_address": "10.1.1.11",
                    "interfaces": [
                        {
                            "mode": "access",
                            "interface_range": "Ethernet1/1",
                        }
                    ],
                    "attachment_options": {
                        "svi_enabled": True,
                        "dpu_secure": False,
                        "switch_route_target_import": ["65000:100"],
                    },
                    "freeform_config": "interface Ethernet1/1\n  description attached by test",
                }
            ],
        }
    )
    config = model.to_config()

    assert config["attach"][0]["attachment_options"] == {
        "dpu_secure": False,
        "svi_enabled": True,
        "switch_route_target_import": ["65000:100"],
    }

    orchestrator = _orchestrator()
    manager = NetworkAttachmentManager(coordinator=None)
    module_args = {"config": [config]}
    manager.resolve_switch_ids = lambda *_args: {"10.1.1.11": "FDO123"}
    desired = manager.desired_attachment_map(module_args, orchestrator.strategy)

    assert desired[("ATTACH_OPTIONS", "FDO123")]["instanceValues"] == {
        "dpuSecure": False,
        "sviEnabled": True,
        "switchRouteTargetImport": ["65000:100"],
    }
    assert desired[("ATTACH_OPTIONS", "FDO123")]["extraConfig"] == "interface Ethernet1/1\n  description attached by test"


def test_attachment_options_do_not_emit_dpu_secure_default():
    model = NetworkConfigModel.from_config(
        {
            "network_name": "ATTACH_OPTIONS",
            "layer": "layer2",
            "attach": [
                {
                    "ip_address": "10.1.1.11",
                    "interfaces": [
                        {
                            "mode": "access",
                            "interface_range": "Ethernet1/1",
                        }
                    ],
                    "attachment_options": {
                        "svi_enabled": True,
                    },
                }
            ],
        }
    )
    orchestrator = _orchestrator()
    manager = NetworkAttachmentManager(coordinator=None)
    module_args = {"config": [model.to_config()]}
    manager.resolve_switch_ids = lambda *_args: {"10.1.1.11": "FDO123"}
    desired = manager.desired_attachment_map(module_args, orchestrator.strategy)

    assert desired[("ATTACH_OPTIONS", "FDO123")]["instanceValues"] == {
        "sviEnabled": True,
    }


def test_empty_attachment_interfaces_are_preserved_in_payload():
    model = NetworkConfigModel.from_config(
        {
            "network_name": "EMPTY_ATTACH",
            "layer": "layer2",
            "attach": [
                {
                    "ip_address": "10.1.1.11",
                    "interfaces": [],
                }
            ],
        }
    )
    manager = NetworkAttachmentManager(coordinator=None)
    manager.resolve_switch_ids = lambda *_args: {"10.1.1.11": "FDO123"}

    desired = manager.desired_attachment_map({"config": [model.to_config()]}, _orchestrator().strategy)

    assert desired[("EMPTY_ATTACH", "FDO123")]["interfaces"] == []


def test_attachment_interface_modes_remain_canonical_until_controller_payload():
    model = NetworkConfigModel.from_config(
        {
            "network_name": "PVLAN_SECONDARY",
            "layer": "layer2",
            "vlan_network_type": "community",
            "primary_network_id": 30000,
            "attach": [
                {
                    "ip_address": "10.1.1.11",
                    "interfaces": [
                        {
                            "mode": "pvlan_host",
                            "interface_range": "Ethernet1/1",
                        },
                        {
                            "mode": "trunk_secondary",
                            "interface_range": "Ethernet1/2",
                        },
                    ],
                }
            ],
        }
    )
    manager = NetworkAttachmentManager(coordinator=None)
    manager.resolve_switch_ids = lambda *_args: {"10.1.1.11": "FDO123"}

    desired = manager.desired_attachment_map({"config": [model.to_config()]}, _orchestrator().strategy)
    interfaces = desired[("PVLAN_SECONDARY", "FDO123")]["interfaces"]

    assert interfaces == [
        {"mode": "pvlan_host", "interfaceRange": "Ethernet1/1"},
        {"mode": "trunk_secondary", "interfaceRange": "Ethernet1/2"},
    ]


def test_attachment_interface_modes_map_to_controller_version_payloads():
    payloads = [
        {
            "networkName": "PVLAN_SECONDARY",
            "switchId": "FDO123",
            "attach": True,
            "interfaces": [
                {"mode": "pvlan_host", "interfaceRange": "Ethernet1/1"},
                {"mode": "trunk_secondary", "interfaceRange": "Ethernet1/2"},
                {"mode": "dot1q_tunnel", "interfaceRange": "Ethernet1/3"},
                {"mode": "trunk_promiscuous", "interfaceRange": "Ethernet1/4"},
            ],
        }
    ]

    nd42_payload = NetworkAttachmentManager._payloads_for_controller(payloads, "4.2.1.10")
    nd43_payload = NetworkAttachmentManager._payloads_for_controller(payloads, "4.3.1.10")

    assert [item["mode"] for item in nd42_payload[0]["interfaces"]] == ["host", "trunkSecondary", "dot1qTunnel", "trunkPromiscuous"]
    assert [item["mode"] for item in nd43_payload[0]["interfaces"]] == ["pvlanHost", "trunkSecondary", "dot1qTunnel", "trunkPromiscuous"]
    assert payloads[0]["interfaces"][0]["mode"] == "pvlan_host"


def test_planned_attach_payloads_treat_pvlan_host_api_spellings_as_idempotent():
    current_nd42 = {
        ("PVLAN_SECONDARY", "FDO123"): {
            "networkName": "PVLAN_SECONDARY",
            "switchId": "FDO123",
            "attach": True,
            "interfaces": [
                {
                    "mode": "host",
                    "interfaceRange": "Ethernet1/1",
                }
            ],
        }
    }
    current_nd43 = {
        ("PVLAN_SECONDARY", "FDO123"): {
            "networkName": "PVLAN_SECONDARY",
            "switchId": "FDO123",
            "attach": True,
            "interfaces": [
                {
                    "mode": "pvlanHost",
                    "interfaceRange": "Ethernet1/1",
                }
            ],
        }
    }
    desired = {
        ("PVLAN_SECONDARY", "FDO123"): {
            "networkName": "PVLAN_SECONDARY",
            "switchId": "FDO123",
            "attach": True,
            "interfaces": [
                {
                    "mode": "pvlan_host",
                    "interfaceRange": "Ethernet1/1",
                }
            ],
        }
    }

    assert NetworkAttachmentManager.planned_attach_payloads(current_nd42, desired) == []
    assert NetworkAttachmentManager.planned_attach_payloads(current_nd43, desired) == []


def test_attachment_config_rejects_camelcase_aliases():
    with pytest.raises(ValueError, match="ipAddress|interfaceRange|sviEnabled|Extra inputs"):
        NetworkConfigModel.from_config(
            {
                "network_name": "ATTACH_ALIAS_REJECT",
                "layer": "layer2",
                "attach": [
                    {
                        "ipAddress": "10.1.1.11",
                        "interfaces": [
                            {
                                "mode": "access",
                                "interfaceRange": "Ethernet1/1",
                            }
                        ],
                        "attachmentOptions": {
                            "sviEnabled": True,
                        },
                        "extra_config": "unsupported",
                    }
                ],
            }
        )


def test_resolve_switch_ids_accepts_fabric_management_ip():
    class Module:
        def fail_json(self, **kwargs):
            raise AssertionError(kwargs)

    class Coordinator:
        module = Module()

        def _new_network_orchestrator(self, module_args, strategy):
            class Orchestrator:
                def _make_endpoint(self, endpoint_cls):
                    endpoint = endpoint_cls()
                    endpoint.fabric_name = "fab1"
                    return endpoint

                def _request(self, **kwargs):
                    return {
                        "switches": [
                            {
                                "fabricManagementIp": "10.1.1.11",
                                "switchId": "FDO123",
                            }
                        ]
                    }

            return Orchestrator(), {}

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    config = [
        {
            "network_name": "BLUE_NET",
            "attach": [{"ip_address": "10.1.1.11"}],
        }
    ]

    assert manager.resolve_switch_ids({"config": config}, _orchestrator().strategy, config) == {
        "10.1.1.11": "FDO123",
    }


def test_network_attachment_query_walks_paginated_results():
    strategy = _orchestrator().strategy
    responses = [
        {
            "attachments": [{"networkName": "BLUE_NET", "switchId": "SW1"}],
            "meta": {"counts": {"remaining": 1, "total": 2}},
        },
        {
            "attachments": [{"networkName": "BLUE_NET", "switchId": "SW2"}],
            "meta": {"counts": {"remaining": 0, "total": 2}},
        },
    ]
    requests = []

    class Orchestrator:
        def _make_endpoint(self, endpoint_cls):
            endpoint = endpoint_cls()
            endpoint.fabric_name = strategy.fabric_name
            return endpoint

        def _request(self, **kwargs):
            requests.append(kwargs)
            return responses.pop(0)

    class Coordinator:
        def _new_network_orchestrator(self, _module_args, _strategy):
            return Orchestrator(), {}

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.attachment_query_page_size = 1

    assert manager.current_attachment_details({}, strategy, ["BLUE_NET"]) == [
        {"networkName": "BLUE_NET", "switchId": "SW1"},
        {"networkName": "BLUE_NET", "switchId": "SW2"},
    ]
    assert requests[0]["path"].endswith("/networkAttachments/query?offset=0&max=1&includeAll=true")
    assert requests[1]["path"].endswith("/networkAttachments/query?offset=1&max=1&includeAll=true")
    assert requests[0]["data"] == {"networkNames": ["BLUE_NET"]}


def test_network_attachment_query_chunks_large_network_name_sets():
    class RecordingManager(NetworkAttachmentManager):
        def __init__(self):
            super().__init__(coordinator=None)
            self.queried_chunks = []

        def current_attachment_details(self, _module_args, _strategy, network_names=None):
            self.queried_chunks.append(network_names)
            return []

    manager = RecordingManager()
    manager.wait_chunk_size = 2

    assert manager.current_attachment_details_ignore_missing({}, _orchestrator().strategy, [f"net-{index}" for index in range(5)]) == []
    assert manager.queried_chunks == [["net-0", "net-1"], ["net-2", "net-3"], ["net-4"]]


def test_network_attachment_query_missing_network_falls_back_to_unscoped_read():
    class RecordingManager(NetworkAttachmentManager):
        def __init__(self):
            super().__init__(coordinator=None)
            self.queried_names = []

        def current_attachment_details(self, _module_args, _strategy, network_names=None):
            self.queried_names.append(network_names)
            if network_names == ["BLUE_NET", "MISSING_NET"]:
                raise RuntimeError("Network(s) [MISSING_NET] not found in fabric")
            return [
                {"networkName": "BLUE_NET", "switchId": "SW1"},
                {"networkName": "GREEN_NET", "switchId": "SW2"},
            ]

    manager = RecordingManager()

    assert manager.current_attachment_details_ignore_missing({}, _orchestrator().strategy, ["BLUE_NET", "MISSING_NET"]) == [
        {"networkName": "BLUE_NET", "switchId": "SW1"}
    ]
    assert manager.queried_names == [["BLUE_NET", "MISSING_NET"], None]


def test_tor_is_modeled_as_normal_attachment_payload():
    model = NetworkConfigModel.from_config(
        {
            "network_name": "TOR_ATTACH",
            "layer": "layer2",
            "attach": [
                {
                    "ip_address": "10.1.1.11",
                    "interfaces": [
                        {
                            "mode": "trunk",
                            "interface_range": "Ethernet1/1",
                        }
                    ],
                },
                {
                    "ip_address": "10.1.1.12",
                    "interfaces": [
                        {
                            "mode": "trunk",
                            "interface_range": "Ethernet1/2",
                        }
                    ],
                },
            ],
        }
    )
    config = model.to_config()

    manager = NetworkAttachmentManager(coordinator=None)
    manager.resolve_switch_ids = lambda *_args: {"10.1.1.11": "LEAF123", "10.1.1.12": "TOR123"}
    desired = manager.desired_attachment_map({"config": [config]}, _orchestrator().strategy)

    assert desired[("TOR_ATTACH", "LEAF123")]["interfaces"] == [
        {
            "mode": "trunk",
            "interfaceRange": "Ethernet1/1",
            "nativeVlan": False,
        }
    ]
    assert desired[("TOR_ATTACH", "TOR123")]["interfaces"] == [
        {
            "mode": "trunk",
            "interfaceRange": "Ethernet1/2",
            "nativeVlan": False,
        }
    ]


def test_network_deploy_type_network_builds_network_level_payload():
    model = NetworkConfigModel.from_config(
        {
            "network_name": "BLUE_NET",
            "layer": "layer2",
            "deploy_type": "network",
        }
    )

    assert model.to_config()["deploy_type"] == "network"
    assert NetworkAttachmentManager.build_deploy_payloads([model.to_config()], {"BLUE_NET": {"FDO123"}}) == [{"networkNames": ["BLUE_NET"]}]


def test_transform_l2_network_payload_uses_manage_schema_shape():
    payload = _orchestrator().prepare_config_data(
        [
            {
                "network_name": "BLUE_NET",
                "layer": "layer2",
                "vlan_id": 2301,
                "vlan_name": "BLUE_VLAN",
                "multicast_group_address": "239.1.1.2",
            }
        ]
    )[0]

    assert payload["network_name"] == "BLUE_NET"
    assert payload["network_type"] == "vxlanIbgp"
    assert payload["layer"] == "layer2"
    assert payload["vrf_name"] == "NA"
    assert payload["l2_data"]["vlanName"] == "BLUE_VLAN"
    assert "rtAuto" not in payload["l2_data"]
    assert "enableIr" not in payload["l2_data"]["fabricData"]
    assert payload["l2_data"]["fabricData"]["multicastGroup"] == "239.1.1.2"
    assert "l3_data" not in payload


def test_network_create_result_failures_raise():
    with pytest.raises(Exception, match="Network create failed"):
        NDNetworkOrchestrator._raise_on_failed_results(
            {"results": [{"networkName": "BLUE_NET", "status": "failed", "message": "Invalid VRF"}]},
            "Network create failed",
        )


def test_network_bulk_create_uses_single_networks_payload():
    orchestrator = _orchestrator()
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {
            "results": [
                {"networkName": "BLUE_NET", "status": "success"},
                {"networkName": "GREEN_NET", "status": "success"},
            ]
        }

    object.__setattr__(orchestrator, "_request", request)
    models = [
        NDNetworkOrchestrator.model_class.from_config(
            {
                "fabric_name": "fab1",
                "network_name": "BLUE_NET",
                "network_type": "vxlanIbgp",
                "layer": "layer2",
                "vrf_name": "NA",
                "vlan_id": 2301,
            }
        ),
        NDNetworkOrchestrator.model_class.from_config(
            {
                "fabric_name": "fab1",
                "network_name": "GREEN_NET",
                "network_type": "vxlanIbgp",
                "layer": "layer3",
                "vrf_name": "Tenant_A",
                "vlan_id": 2302,
            }
        ),
    ]

    result = orchestrator.create_bulk(models)

    assert result["results"][0]["networkName"] == "BLUE_NET"
    assert len(requests) == 1
    assert requests[0]["path"] == "/api/v1/manage/fabrics/fab1/networks"
    assert requests[0]["verb"].value == "POST"
    assert [item["networkName"] for item in requests[0]["data"]["networks"]] == [
        "BLUE_NET",
        "GREEN_NET",
    ]


def test_mcfg_parent_network_create_uses_onemanage_manage_schema_payload():
    orchestrator = _mcfg_parent_orchestrator()
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {"results": [{"networkName": "BLUE_NET", "status": "success"}]}

    object.__setattr__(orchestrator, "_request", request)
    model = NDNetworkOrchestrator.model_class.from_config(
        orchestrator.prepare_config_data(
            [
                {
                    "network_name": "BLUE_NET",
                    "network_id": 901030,
                    "vlan_id": 3130,
                    "vlan_name": "BLUE_VLAN",
                    "layer": "layer2",
                }
            ]
        )[0]
    )

    result = orchestrator.create_bulk([model])

    assert result == {"results": [{"networkName": "BLUE_NET", "status": "success"}]}
    assert len(requests) == 1
    assert requests[0]["path"] == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networks"
    assert requests[0]["data"]["vrfName"] == "NA"
    assert len(requests[0]["data"]["networks"]) == 1
    payload = requests[0]["data"]["networks"][0]
    assert payload["networkName"] == "BLUE_NET"
    assert payload["fabricName"] == "MCFG_FAB"
    assert payload["vrfName"] == "NA"
    assert payload["networkType"] == "vxlan"
    assert payload["networkMode"] == "layer2"
    assert payload["vlanNetworkType"] == "normal"
    assert "layer" not in payload
    assert payload["networkId"] == 901030
    assert "vlanId" not in payload
    assert payload["l2Data"]["vlanName"] == ""
    assert "rtAuto" not in payload["l2Data"]
    assert "disableRtAuto" not in payload["l2Data"]
    assert "fabricData" not in payload["l2Data"]
    assert payload["l3Data"] == {
        "gatewayIpv4Address": "",
        "gatewayIpv6Address": "",
        "secondaryGatewayIpv6Collection": [],
        "vlanInterfaceDescription": "",
        "mtu": None,
        "secondaryGatewayIpv4Collection": None,
        "routingTag": 12345,
    }


@pytest.mark.parametrize("vlan_network_type", ["primary", "community", "isolated"])
def test_mcfg_parent_pvlan_network_create_is_rejected(vlan_network_type):
    orchestrator = _mcfg_parent_orchestrator()
    config = {
        "network_name": f"PVLAN_{vlan_network_type.upper()}",
        "network_id": 901031,
        "vlan_id": 3131,
        "vlan_network_type": vlan_network_type,
        "layer": "layer2",
        "vrf_name": "NA",
    }
    if vlan_network_type in ("community", "isolated"):
        config["primary_network_id"] = 901030

    with pytest.raises(ValueError, match="primary, community, and isolated are not supported on Multicluster parent fabrics"):
        orchestrator.prepare_config_data([config])


def test_mcfg_parent_workflow_rejects_pvlan_networks_before_requests():
    module = _Module({"fabric_name": "MCFG_FAB", "state": "merged", "config": []})
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=_mcfg_parent_orchestrator().strategy)

    with pytest.raises(AssertionError, match="primary, community, and isolated are not supported on Multicluster parent fabrics"):
        coordinator._validate_parent_network_capabilities(
            [
                {
                    "network_name": "PVLAN_PRIMARY",
                    "vlan_network_type": "privatePrimary",
                }
            ]
        )


def test_mcfg_parent_network_create_omits_child_netflow_monitor_fields():
    orchestrator = _mcfg_parent_orchestrator()
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {"results": [{"networkName": "GREEN_NET", "status": "success"}]}

    object.__setattr__(orchestrator, "_request", request)
    model = NDNetworkOrchestrator.model_class.from_config(
        orchestrator.prepare_config_data(
            [
                {
                    "network_name": "GREEN_NET",
                    "layer": "layer3",
                    "network_id": 901031,
                    "vlan_id": 3131,
                    "vrf_name": "VRF_GREEN",
                    "gateway_ipv4_address": "192.0.2.1/24",
                    "netflow_enable": True,
                    "vlan_netflow_monitor": "L2_MON",
                    "interface_netflow_monitor": "L3_MON",
                }
            ]
        )[0]
    )

    orchestrator.create_bulk([model])

    payload = requests[0]["data"]["networks"][0]
    assert requests[0]["path"] == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networks"
    assert payload["networkMode"] == "layer3"
    assert "fabricData" not in payload["l3Data"]


def test_mcfg_parent_network_update_uses_l2_onemanage_manage_schema_payload():
    orchestrator = _mcfg_parent_orchestrator()
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {"results": [{"networkName": "BLUE_NET", "status": "success"}]}

    object.__setattr__(orchestrator, "_request", request)
    model = NDNetworkOrchestrator.model_class.from_config(
        orchestrator.prepare_config_data(
            [
                {
                    "network_name": "BLUE_NET",
                    "network_id": 901030,
                    "vlan_id": 3130,
                    "vlan_name": "BLUE_VLAN",
                    "layer": "layer2",
                }
            ]
        )[0]
    )

    result = orchestrator.update(model)

    assert result == {"results": [{"networkName": "BLUE_NET", "status": "success"}]}
    assert len(requests) == 1
    assert requests[0]["path"] == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networks/BLUE_NET"
    payload = requests[0]["data"]
    assert payload["networkMode"] == "layer2"
    assert payload["vrfName"] == "NA"
    assert "vlanId" not in payload
    assert payload["l2Data"] == {"vlanName": ""}
    assert payload["l3Data"] == {
        "gatewayIpv4Address": "",
        "gatewayIpv6Address": "",
        "secondaryGatewayIpv6Collection": [],
        "vlanInterfaceDescription": "",
        "mtu": None,
        "secondaryGatewayIpv4Collection": None,
        "routingTag": 12345,
    }


def test_mcfg_parent_scoped_query_uses_unfiltered_read_and_local_filter():
    orchestrator = _mcfg_parent_orchestrator()
    orchestrator.rest_send.params["state"] = "merged"
    orchestrator.rest_send.params["config"] = [{"network_name": "BLUE_NET"}]
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {
            "networks": [
                {"networkName": "BLUE_NET", "fabricName": "MCFG_FAB", "vrfName": "NA", "networkType": "vxlan"},
                {"networkName": "OTHER_NET", "fabricName": "MCFG_FAB", "vrfName": "NA", "networkType": "vxlan"},
            ],
            "meta": {"counts": {"remaining": 0, "total": 2}},
        }

    object.__setattr__(orchestrator, "_request", request)

    result = orchestrator.query_all()

    assert [item["networkName"] for item in result] == ["BLUE_NET"]
    assert requests[0]["path"].startswith("/api/v1/oneManage/manage/fabrics/MCFG_FAB/networks?")
    assert "max=10000" in requests[0]["path"]
    assert "offset=0" in requests[0]["path"]
    assert "filter=" not in requests[0]["path"]


def test_mcfg_parent_attachment_validate_and_attach_use_onemanage_payload_shape():
    class Module:
        check_mode = False

    class FakeOrchestrator:
        def __init__(self, strategy):
            self.strategy = strategy
            self.requests = []

        def _make_endpoint(self, endpoint_cls, **extra_fields):
            ep = endpoint_cls()
            ep.fabric_name = self.strategy.fabric_name
            self.strategy.configure_endpoint(ep)
            for attr, value in extra_fields.items():
                setattr(ep, attr, value)
            return ep

        def _request(self, **kwargs):
            self.requests.append(kwargs)
            return {"results": [{"networkName": "BLUE_NET", "status": "success"}]}

    class Coordinator:
        module = Module()

        def __init__(self, strategy):
            self.orchestrator = FakeOrchestrator(strategy)

        def _new_network_orchestrator(self, _module_args, _strategy):
            return self.orchestrator, object()

        def _finalize_api_trace(self, _results, deploy_targets=None):
            return {"changed": True, "deploy_targets": deploy_targets or {}}

    strategy = _mcfg_parent_orchestrator().strategy
    coordinator = Coordinator(strategy)
    manager = NetworkAttachmentManager(coordinator)

    manager.post_network_attachments(
        {"config": []},
        strategy,
        [
            {
                "networkName": "BLUE_NET",
                "switchId": "SERIAL1",
                "attach": True,
            }
        ],
        {"BLUE_NET": {"SERIAL1"}},
        OperationType.CREATE,
    )

    assert len(coordinator.orchestrator.requests) == 1
    assert coordinator.orchestrator.requests[0]["path"] == ("/api/v1/oneManage/manage/fabrics/MCFG_FAB/networkAttachments")
    assert coordinator.orchestrator.requests[0]["data"] == {
        "attachments": [
            {
                "networkName": "BLUE_NET",
                "switchId": "SERIAL1",
                "instanceValues": {},
                "interfaces": [],
                "extraConfig": "",
                "attach": True,
            }
        ]
    }


@pytest.mark.parametrize(
    "strategy_factory,undeploy,payload,expected_path,expected_data",
    [
        (
            _orchestrator,
            False,
            {"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1", "SERIAL2"]},
            "/api/v1/manage/fabrics/fab1/networkActions/deploy",
            {"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1", "SERIAL2"]},
        ),
        (
            _orchestrator,
            True,
            {"switchIds": ["SERIAL1", "SERIAL2"]},
            "/api/v1/manage/fabrics/fab1/switchActions/deploy",
            {"switchIds": ["SERIAL1", "SERIAL2"]},
        ),
        (
            _orchestrator,
            True,
            {"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1", "SERIAL2"]},
            "/api/v1/manage/fabrics/fab1/networkActions/deploy",
            {"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1", "SERIAL2"]},
        ),
        (
            lambda: NDNetworkOrchestrator(
                rest_send=RestSend({"state": "deleted", "config": [], "check_mode": False}),
                strategy=MultisiteParentNetworkStrategy(fabric_name="MSD_FAB", fabric_data={"managementType": "vxlanIbgp"}),
            ),
            True,
            {"switchIds": ["SERIAL1", "SERIAL2"]},
            "/api/v1/manage/fabrics/MSD_FAB/switchActions/deploy",
            {"switchIds": ["SERIAL1", "SERIAL2"]},
        ),
        (
            _mcfg_parent_orchestrator,
            False,
            {"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1", "SERIAL2"]},
            "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networkActions/deploy",
            {"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1", "SERIAL2"]},
        ),
        (
            _mcfg_parent_orchestrator,
            True,
            {"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1", "SERIAL2"]},
            "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networkActions/deploy",
            {"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1", "SERIAL2"]},
        ),
        (
            lambda: NDNetworkOrchestrator(
                rest_send=RestSend({"state": "deleted", "config": [], "check_mode": False}),
                strategy=ChildNetworkStrategy(
                    fabric_name="CHILD_FAB",
                    fabric_data={"managementType": "vxlanIbgp"},
                    cluster_name="CLUSTER1",
                ),
            ),
            True,
            {"switchIds": ["SERIAL1", "SERIAL2"]},
            "/api/v1/manage/fabrics/CHILD_FAB/switchActions/deploy?clusterName=CLUSTER1",
            {"switchIds": ["SERIAL1", "SERIAL2"]},
        ),
    ],
)
def test_network_deploy_routes_delete_undeploy_by_scope(strategy_factory, undeploy, payload, expected_path, expected_data):
    class Module:
        check_mode = False

    class Coordinator:
        module = Module()

        def __init__(self, strategy):
            self.strategy = strategy
            self.requests = []

        def _new_network_orchestrator(self, _module_args, _strategy):
            coordinator = self

            class FakeOrchestrator:
                def _make_endpoint(self, endpoint_cls, **extra_fields):
                    ep = endpoint_cls()
                    ep.fabric_name = coordinator.strategy.fabric_name
                    coordinator.strategy.configure_endpoint(ep)
                    for attr, value in extra_fields.items():
                        setattr(ep, attr, value)
                    return ep

                def _request(self, **kwargs):
                    coordinator.requests.append(kwargs)
                    return {"status": "accepted"}

            return FakeOrchestrator(), object()

        def _finalize_api_trace(self, _results):
            return {"changed": True}

    strategy = strategy_factory().strategy
    coordinator = Coordinator(strategy)
    manager = NetworkAttachmentManager(coordinator)

    manager.deploy_network_attachments(
        {"config": []},
        strategy,
        payload,
        undeploy=undeploy,
    )

    assert coordinator.requests == [
        {
            "path": expected_path,
            "verb": HttpVerbEnum.POST,
            "data": expected_data,
            "operation_type": OperationType.UPDATE,
        }
    ]


def test_network_delete_undeploy_without_switch_ids_rejects_network_fallback():
    manager = NetworkAttachmentManager(coordinator=None)

    with pytest.raises(ValueError, match="requires affected switch IDs"):
        manager.deploy_network_attachments({}, None, {"networkNames": ["BLUE_NET"]}, undeploy=True)


def test_mcfg_parent_deploy_without_network_names_is_rejected():
    manager = NetworkAttachmentManager(coordinator=None)

    with pytest.raises(ValueError, match="requires Network names"):
        manager.deploy_network_attachments({}, _mcfg_parent_orchestrator().strategy, {"switchIds": ["SERIAL1"]}, undeploy=True)


@pytest.mark.parametrize("status", ["success", "notExecuted", "completed", "started"])
def test_switch_undeploy_accepts_nonfailure_207_status(status):
    NetworkAttachmentManager._raise_on_failed_switch_deploy({"switchIds": [{"switchId": "SERIAL1", "status": status}]})


def test_switch_undeploy_rejects_embedded_207_failure():
    with pytest.raises(RuntimeError, match="SERIAL2: configuration rejected"):
        NetworkAttachmentManager._raise_on_failed_switch_deploy(
            {
                "switchIds": [
                    {"switchId": "SERIAL1", "status": "success"},
                    {"switchId": "SERIAL2", "status": "failed", "message": "configuration rejected"},
                ]
            }
        )


def test_network_delete_stops_after_failed_switch_undeploy():
    class Coordinator:
        def _new_network_orchestrator(self, _module_args, _strategy):
            return _orchestrator(), object()

        def _finalize_api_trace(self, _results):
            raise AssertionError("failed undeploy must not produce a successful trace")

    manager = NetworkAttachmentManager(Coordinator())
    response = {"switchIds": [{"switchId": "SERIAL1", "status": "failed", "message": "configuration rejected"}]}
    with patch.object(NDNetworkOrchestrator, "_request", return_value=response):
        with pytest.raises(RuntimeError, match="SERIAL1: configuration rejected"):
            manager.deploy_network_attachments(
                {"state": "deleted"},
                _orchestrator().strategy,
                {"switchIds": ["SERIAL1"]},
                undeploy=True,
            )


def test_mcfg_parent_network_query_normalizes_top_down_template_config():
    orchestrator = _mcfg_parent_orchestrator()
    top_down_network = {
        "fabric": "MCFG_FAB",
        "networkName": "BLUE_NET",
        "networkId": 901030,
        "primaryNetworkId": 0,
        "networkStatus": "NA",
        "vrf": "NA",
        "networkTemplateConfig": (
            '{"segmentId":"901030","vlanId":"3130","vlanName":"BLUE_VLAN",'
            '"isLayer2Only":"true","rtBothAuto":"true","enableIR":"false",'
            '"ENABLE_NETFLOW":"true","l2NetflowMonitor":"L2_MON",'
            '"l3NetflowMonitor":"L3_MON"}'
        ),
    }

    normalized = orchestrator._normalize_query_network_item(top_down_network)

    assert normalized["fabricName"] == "MCFG_FAB"
    assert normalized["networkType"] == "vxlan"
    assert normalized["networkStatus"] == "notApplicable"
    assert normalized["vrfName"] == "NA"
    assert normalized["networkId"] == 901030
    assert "primaryNetworkId" not in normalized
    assert normalized["vlanId"] == 3130
    assert normalized["layer"] == "layer2"
    assert normalized["l2Data"]["vlanName"] == "BLUE_VLAN"
    assert "rtAuto" not in normalized["l2Data"]
    assert "disableRtAuto" not in normalized["l2Data"]
    assert "fabricData" not in normalized["l2Data"]
    assert normalized["l3Data"]["fabricData"]["netflow"] is True
    assert normalized["l3Data"]["fabricData"]["l2NetflowMonitor"] == "L2_MON"
    assert normalized["l3Data"]["fabricData"]["l3NetflowMonitor"] == "L3_MON"


def test_mcfg_parent_network_query_infers_private_secondary_vlan_type_from_template_config():
    orchestrator = _mcfg_parent_orchestrator()

    community = orchestrator._normalize_query_network_item(
        {
            "fabric": "MCFG_FAB",
            "networkName": "PVLAN_COMMUNITY",
            "networkTemplateConfig": '{"segmentId":"901031","vlanId":"3131","isLayer2Only":"true","type":"Community"}',
        }
    )
    isolated = orchestrator._normalize_query_network_item(
        {
            "fabric": "MCFG_FAB",
            "networkName": "PVLAN_ISOLATED",
            "networkTemplateConfig": '{"segmentId":"901032","vlanId":"3132","isLayer2Only":"true","type":"Isolated"}',
        }
    )

    assert community["vlanNetworkType"] == "privateSecondaryCommunity"
    assert isolated["vlanNetworkType"] == "privateSecondaryIsolated"
    assert orchestrator.model_class.from_response(community).to_config()["vlan_network_type"] == "community"
    assert orchestrator.model_class.from_response(isolated).to_config()["vlan_network_type"] == "isolated"


def test_mcfg_parent_delete_does_not_seed_empty_network_level_deploy():
    class Strategy:
        is_parent = True
        is_multicluster = True

    class Coordinator:
        deploy_maps = None

        def _configured_network_names(self, _config):
            return ["BLUE_NET"]

        def _build_delete_deploy_payloads(self, _config, *target_maps, strategy=None):
            assert strategy.is_multicluster and strategy.is_parent
            self.deploy_maps = target_maps
            return []

        def _wait_for_network_attachments_delete_ready(self, *_args):
            return None

        def _wait_for_networks_delete_ready(self, *_args):
            return None

        def _network_delete_wait_deadline(self, item_count):
            return 100.0 + item_count, 300

    coordinator = Coordinator()

    traces = NetworkStateMachine(coordinator)._deploy_detach_traces(
        api_args={},
        wait_args={},
        strategy=Strategy(),
        config=[{"network_name": "BLUE_NET"}],
        detach_trace={},
        wait_network_names=["BLUE_NET"],
    )

    assert traces == []
    assert coordinator.deploy_maps == ({},)


def test_network_delete_wait_uses_one_combined_gate():
    class Module:
        check_mode = False

    class Strategy:
        is_parent = False
        is_multicluster = False

    class Coordinator:
        module = Module()

        def __init__(self):
            self.wait_calls = []

        def _configured_network_names(self, _config):
            return ["BLUE_NET"]

        def _build_delete_deploy_payloads(self, _config, *target_maps, strategy=None):
            return []

        def _wait_for_network_attachments_delete_ready(self, *_args):
            raise AssertionError("network delete flow must use the combined readiness gate")

        def _wait_for_networks_delete_ready(self, _args, _strategy, names):
            self.wait_calls.append(("networks", names))

    coordinator = Coordinator()

    traces = NetworkStateMachine(coordinator)._deploy_detach_traces(
        api_args={},
        wait_args={},
        strategy=Strategy(),
        config=[{"network_name": "BLUE_NET"}],
        detach_trace={},
        wait_network_names=["BLUE_NET"],
    )

    assert traces == []
    assert coordinator.wait_calls == [("networks", ["BLUE_NET"])]


def test_network_check_mode_delete_skips_deploy_and_wait():
    class Module:
        check_mode = True

    class Strategy:
        is_parent = False
        is_multicluster = False

    class Coordinator:
        module = Module()

        def _configured_network_names(self, _config):
            return ["BLUE_NET"]

        def _build_delete_deploy_payloads(self, _config, *target_maps, strategy=None):
            assert target_maps == ({"BLUE_NET": {"SERIAL1"}},)
            return [{"switchIds": ["SERIAL1"]}]

        def _deploy_network_attachments(self, *_args):
            raise AssertionError("check mode must not deploy")

        def _wait_for_network_attachments_delete_ready(self, *_args):
            raise AssertionError("check mode must not wait for attachment delete readiness")

        def _wait_for_networks_delete_ready(self, *_args):
            raise AssertionError("check mode must not wait for network delete readiness")

    traces = NetworkStateMachine(Coordinator())._deploy_detach_traces(
        api_args={},
        wait_args={},
        strategy=Strategy(),
        config=[{"network_name": "BLUE_NET"}],
        detach_trace={"deploy_targets": {"BLUE_NET": {"SERIAL1"}}},
        wait_network_names=["BLUE_NET"],
    )

    assert traces == [
        {"deploy_targets": {"BLUE_NET": {"SERIAL1"}}},
        {
            "changed": True,
            "failed": False,
            "check_mode_deploy_payloads": [{"switchIds": ["SERIAL1"]}],
        },
    ]


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("deploy_type", ["switch", "network"])
def test_network_delete_honors_deploy_type(check_mode, deploy_type):
    class Module:
        def __init__(self):
            self.check_mode = check_mode

    class Strategy:
        is_parent = False
        is_multicluster = False

    class Coordinator:
        def __init__(self):
            self.module = Module()
            self.deploy_calls = []
            self.wait_calls = []

        def _build_delete_deploy_payloads(self, config, *target_maps, strategy=None):
            return NetworkAttachmentManager.build_delete_deploy_payloads(config, *target_maps, strategy=strategy)

        def _deploy_network_attachments(self, _args, _strategy, payload, undeploy=False):
            self.deploy_calls.append((payload, undeploy))
            return {"changed": True}

        def _wait_for_networks_delete_ready(self, _args, _strategy, names):
            self.wait_calls.append(names)

    coordinator = Coordinator()
    traces = NetworkStateMachine(coordinator)._deploy_detach_traces(
        api_args={"state": "deleted"},
        wait_args={"state": "deleted"},
        strategy=Strategy(),
        config=[{"network_name": "BLUE_NET", "deploy_type": deploy_type}],
        detach_trace={"deploy_targets": {"BLUE_NET": {"SERIAL1", "SERIAL2"}}},
        wait_network_names=["BLUE_NET"],
    )
    expected_payload = {"switchIds": ["SERIAL1", "SERIAL2"]}
    if deploy_type == "network":
        expected_payload["networkNames"] = ["BLUE_NET"]

    if check_mode:
        assert coordinator.deploy_calls == []
        assert coordinator.wait_calls == []
        assert traces[-1]["check_mode_deploy_payloads"] == [expected_payload]
    else:
        assert coordinator.deploy_calls == [(expected_payload, True)]
        assert coordinator.wait_calls == [["BLUE_NET"]]


def test_network_state_machine_deleted_absent_network_skips_detach_and_deploy():
    class Module:
        check_mode = False

    class Strategy:
        is_child = False
        is_parent = True
        is_multicluster = True

    class Coordinator:
        module = Module()
        strategy = Strategy()

        def __init__(self):
            self.calls = []

        def _configured_network_names(self, _config):
            return ["MISSING_NET"]

        def _query_current_networks(self, *_args, **_kwargs):
            return []

        def _ensure_networks_have_no_networks(self, *_args, **_kwargs):
            raise AssertionError("absent Network must not run dependency checks")

        def _apply_deleted_attachment_phase(self, *_args, **_kwargs):
            raise AssertionError("absent Network must not detach")

        def _deploy_network_attachments(self, *_args, **_kwargs):
            raise AssertionError("absent Network must not deploy")

        def _run_state_machine(self, _args, strategy=None):
            self.calls.append("delete")
            assert strategy is not None
            return {"changed": False, "before": [], "after": []}

        def _trace(self, *_args, **_kwargs):
            return None

    coordinator = Coordinator()
    result = NetworkStateMachine(coordinator).run(
        {
            "state": "deleted",
            "config": [{"network_name": "MISSING_NET"}],
        }
    )

    assert coordinator.calls == ["delete"]
    assert result["changed"] is False


def test_network_check_mode_attachment_phase_returns_planned_payload():
    class Module:
        check_mode = True
        _verbosity = 3
        params = {
            "state": "merged",
            "config": [
                {
                    "network_name": "BLUE_NET",
                    "attach": [{"ip_address": "10.1.1.11"}],
                }
            ],
        }

    module_args = dict(Module.params)
    coordinator = NetworkWorkflowCoordinator(module=Module(), strategy=_orchestrator().strategy)

    def new_network_orchestrator(*_args, **_kwargs):
        raise AssertionError("check mode must not build a REST orchestrator for Network attachments")

    object.__setattr__(coordinator, "_new_network_orchestrator", new_network_orchestrator)
    desired = {
        ("BLUE_NET", "SERIAL1"): {
            "networkName": "BLUE_NET",
            "switchId": "SERIAL1",
            "attach": True,
        }
    }

    trace = coordinator._apply_attachment_phase(
        module_args,
        _orchestrator().strategy,
        phase="post",
        desired=desired,
        current={},
    )

    assert trace["changed"] is True
    assert trace["deploy_targets"] == {"BLUE_NET": {"SERIAL1"}}
    assert trace["check_mode_attachment_payloads"] == [
        {
            "networkName": "BLUE_NET",
            "switchId": "SERIAL1",
            "attach": True,
        }
    ]


def test_network_workflow_coordinator_apply_attachment_phase_forwards_attachment_details():
    module_args = {"state": "replaced", "config": []}
    strategy = _orchestrator().strategy
    coordinator = NetworkWorkflowCoordinator(module=_Module(module_args), strategy=strategy)
    desired = {("BLUE_NET", "SERIAL1"): {"networkName": "BLUE_NET", "switchId": "SERIAL1", "attach": True}}
    current = {("BLUE_NET", "SERIAL2"): {"networkName": "BLUE_NET", "switchId": "SERIAL2", "attach": True}}
    attachment_details = [{"networkName": "BLUE_NET", "switchId": "SERIAL1", "peerSwitchId": "SERIAL2", "attach": False}]
    calls = []

    class Attachments:
        @staticmethod
        def apply_phase(module_args, strategy, phase, desired, current_network_names, current, attachment_details):
            calls.append((module_args, strategy, phase, desired, current_network_names, current, attachment_details))
            return {"attachment_details": attachment_details}

    object.__setattr__(coordinator, "_attachments", Attachments())

    trace = coordinator._apply_attachment_phase(
        module_args,
        strategy,
        phase="post",
        desired=desired,
        current_network_names=["BLUE_NET"],
        current=current,
        attachment_details=attachment_details,
    )

    assert trace == {"attachment_details": attachment_details}
    assert calls == [(module_args, strategy, "post", desired, ["BLUE_NET"], current, attachment_details)]


def test_network_attachment_post_validates_interfaces_before_attach():
    calls = []

    class Module:
        check_mode = False

    class Coordinator:
        module = Module()

        def _new_network_orchestrator(self, _module_args, _strategy):
            class Orchestrator:
                def _make_endpoint(self, endpoint_cls):
                    endpoint = endpoint_cls(fabric_name="fab1")
                    return endpoint

                def _request(self, **kwargs):
                    calls.append(kwargs)
                    return {"results": [{"status": "success"}]}

            return Orchestrator(), {}

        def _finalize_api_trace(self, _results, deploy_targets=None):
            return {"changed": True, "failed": False, "deploy_targets": deploy_targets or {}}

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    payloads = [
        {
            "networkName": "BLUE_NET",
            "switchId": "SERIAL1",
            "interfaces": [{"mode": "trunk", "interfaceRange": "Ethernet1/3"}],
            "instanceValues": {"sviEnabled": True},
            "attach": True,
        }
    ]

    manager.post_network_attachments({}, _orchestrator().strategy, payloads, {"BLUE_NET": {"SERIAL1"}}, operation_type=OperationType.CREATE)

    assert calls[0]["path"] == "/api/v1/manage/fabrics/fab1/networkAttachments/validateInterfaces?strictModeValidation=false"
    assert calls[0]["data"] == {
        "attachments": [
            {
                "networkName": "BLUE_NET",
                "switchId": "SERIAL1",
                "vlanId": -1,
                "interfaces": [
                    {
                        "mode": "trunk",
                        "interfaceRange": "Ethernet1/3",
                        "nativeVlan": False,
                    }
                ],
                "attach": True,
            }
        ]
    }
    assert calls[1]["path"] == "/api/v1/manage/fabrics/fab1/networkAttachments"
    assert calls[1]["data"] == {
        "attachments": [
            {
                "networkName": "BLUE_NET",
                "switchId": "SERIAL1",
                "interfaces": [
                    {
                        "mode": "trunk",
                        "interfaceRange": "Ethernet1/3",
                        "nativeVlan": False,
                    }
                ],
                "instanceValues": {"sviEnabled": True},
                "attach": True,
            }
        ]
    }


def test_network_attachment_validation_batches_only_nonempty_interfaces():
    calls = []

    class Orchestrator:
        def _make_endpoint(self, endpoint_cls):
            return endpoint_cls(fabric_name="fab1")

        def _request(self, **kwargs):
            calls.append(kwargs)
            return {"results": [{"status": "success"}]}

    manager = NetworkAttachmentManager(coordinator=object())
    payloads = [
        {"networkName": "EMPTY", "switchId": "SERIAL1", "interfaces": [], "attach": True},
        {"networkName": "OMITTED", "switchId": "SERIAL2", "attach": True},
        {"networkName": "WITH_INTERFACE", "switchId": "SERIAL3", "interfaces": [{"mode": "access", "interfaceRange": "Ethernet1/3"}], "attach": True},
    ]

    manager.validate_attachment_interfaces(Orchestrator(), _orchestrator().strategy, payloads)

    assert len(calls) == 1
    assert calls[0]["data"]["attachments"] == [
        {
            "networkName": "WITH_INTERFACE",
            "switchId": "SERIAL3",
            "vlanId": -1,
            "interfaces": [{"mode": "access", "interfaceRange": "Ethernet1/3", "nativeVlan": False}],
            "attach": True,
        }
    ]


def test_network_merged_runs_post_attach_and_deploy_for_desired_attachment():
    class Module:
        check_mode = False

    class Strategy:
        is_child = False
        is_parent = False

    class Coordinator(_MergedNetworkCoordinatorStub):
        module = Module()
        strategy = Strategy()

        def __init__(self):
            self.calls = []

        def _desired_attachment_map(self, module_args, strategy):
            self.calls.append(("desired", module_args["state"], strategy))
            return {
                ("BLUE_NET", "SERIAL1"): {
                    "networkName": "BLUE_NET",
                    "switchId": "SERIAL1",
                    "attach": True,
                }
            }

        def _apply_attachment_phase(self, module_args, strategy, phase, desired=None, current_network_names=None, current=None, attachment_details=None):
            self.calls.append(("phase", phase, desired, current))
            if phase == "pre":
                return {}
            assert desired == {
                ("BLUE_NET", "SERIAL1"): {
                    "networkName": "BLUE_NET",
                    "switchId": "SERIAL1",
                    "attach": True,
                }
            }
            return {"changed": True, "deploy_targets": {"BLUE_NET": {"SERIAL1"}}}

        def _run_state_machine(self, module_args, strategy=None):
            self.calls.append(("crud", module_args["state"], strategy))
            module_args["config"][0].clear()
            return {"changed": False, "after": [{"network_name": "BLUE_NET", "network_status": "pending"}]}

        def _attachment_map_after_detach(self, current, payloads):
            return current

        def _merge_api_trace(self, result, trace):
            result["changed"] = result.get("changed", False) or trace.get("changed", False)
            result.setdefault("merged_traces", []).append(trace)

        def _build_deploy_payloads(self, config, *target_maps):
            self.calls.append(("build_deploy", target_maps))
            assert config == [
                {
                    "network_name": "BLUE_NET",
                    "deploy": True,
                    "attach": [{"ip_address": "10.1.1.11"}],
                }
            ]
            assert target_maps == ({}, {"BLUE_NET": {"SERIAL1"}})
            return [{"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1"]}]

        def _build_pending_network_deploy_payloads(self, *_args):
            raise AssertionError("attachment deploy targets should be used first")

        def _deploy_network_attachments(self, module_args, strategy, deploy_payload):
            self.calls.append(("deploy", deploy_payload))
            return {"changed": True, "response": {"status": "accepted"}}

    coordinator = Coordinator()
    result = NetworkStateMachine(coordinator).run(
        {
            "state": "merged",
            "config": [
                {
                    "network_name": "BLUE_NET",
                    "deploy": True,
                    "attach": [{"ip_address": "10.1.1.11"}],
                }
            ],
        }
    )

    assert result["changed"] is True
    assert ("deploy", {"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1"]}) in coordinator.calls


def test_network_deploy_fallback_queries_current_pending_networks():
    class Module:
        check_mode = False

    class Strategy:
        pass

    class Coordinator:
        module = Module()

        def __init__(self):
            self.pending_calls = 0
            self.traces = []

        def _build_deploy_payloads(self, config, *target_maps):
            return []

        def _build_pending_network_deploy_payloads(self, result, config, module_args, strategy):
            self.pending_calls += 1
            if self.pending_calls == 1:
                assert result["after"] == []
                return []
            assert result == {"after": [{"networkName": "BLUE_NET", "networkStatus": "pending"}]}
            return [{"networkNames": ["BLUE_NET"]}]

        def _deploy_enabled_by_network(self, _config):
            return {"BLUE_NET": True}

        def _configured_network_names(self, _config):
            return ["BLUE_NET"]

        def _query_current_networks_with_trace(self, module_args, strategy):
            return [{"networkName": "BLUE_NET", "networkStatus": "pending"}], {"changed": False, "api_paths": ["/networks"]}

        def _merge_api_trace(self, result, trace):
            self.traces.append(trace)
            result["changed"] = result.get("changed", False) or trace.get("changed", False)

        def _deploy_network_attachments(self, module_args, strategy, deploy_payload):
            return {"changed": True, "api_payload": [deploy_payload]}

    coordinator = Coordinator()
    result = NetworkStateMachine(coordinator)._deploy_after_attachment_changes(
        {"changed": False, "after": []},
        [{"network_name": "BLUE_NET", "deploy": True}],
        {"config": [{"network_name": "BLUE_NET", "deploy": True}]},
        Strategy(),
        {},
        {},
        False,
    )

    assert coordinator.pending_calls == 2
    assert coordinator.traces[0] == {"changed": False, "api_paths": ["/networks"]}
    assert result["changed"] is True


def test_network_state_machine_idempotent_run_deploys_pending_attach():
    class Module:
        check_mode = False

    class Strategy:
        is_child = False
        is_parent = False

    class Coordinator(_MergedNetworkCoordinatorStub):
        module = Module()
        strategy = Strategy()

        def __init__(self):
            self.deployed_payloads = []

        def _desired_attachment_map(self, *_args):
            return {
                ("BLUE_NET", "SERIAL1"): {
                    "networkName": "BLUE_NET",
                    "switchId": "SERIAL1",
                    "attach": True,
                }
            }

        def _apply_attachment_phase(self, module_args, strategy, phase, desired=None, current_network_names=None, current=None, attachment_details=None):
            return {"current": {}} if phase == "pre" else {}

        def _attachment_map_after_detach(self, current, payloads):
            return current

        def _run_state_machine(self, *_args, **_kwargs):
            return {
                "changed": False,
                "failed": False,
                "after": [
                    {
                        "network_name": "BLUE_NET",
                        "network_status": "pending",
                    }
                ],
            }

        def _merge_api_trace(self, result, trace, prepend=False):
            result["changed"] = result.get("changed", False) or trace.get("changed", False)

        def _build_deploy_payloads(self, *_args):
            return []

        def _build_pending_network_deploy_payloads(self, result, config, module_args, strategy):
            assert result["after"][0]["network_status"] == "pending"
            return [{"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1"]}]

        def _query_current_networks_with_trace(self, *_args):
            raise AssertionError("pending state from state-machine output should be enough")

        def _deploy_network_attachments(self, module_args, strategy, payload):
            self.deployed_payloads.append(payload)
            return {"changed": True, "final": {"changed": True}}

    coordinator = Coordinator()
    result = NetworkStateMachine(coordinator).run(
        {
            "state": "merged",
            "config": [
                {
                    "network_name": "BLUE_NET",
                    "deploy": True,
                    "deploy_type": "switch",
                    "attach": [
                        {
                            "ip_address": "10.1.1.11",
                            "interfaces": [
                                {
                                    "mode": "access",
                                    "interface_range": "Ethernet1/1",
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )

    assert result["changed"] is True
    assert coordinator.deployed_payloads == [{"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1"]}]


@pytest.mark.parametrize("check_mode,defer_deploy", [(False, False), (True, False), (False, True)])
@pytest.mark.parametrize("deploy_type", ["switch", "network"])
def test_network_attachment_only_detach_honors_deploy_type(check_mode, defer_deploy, deploy_type):
    class Module:
        pass

    Module.check_mode = check_mode

    class Coordinator:
        module = Module()

        def __init__(self):
            self.deploy_calls = []

        def _build_delete_deploy_payloads(self, config, *target_maps, strategy=None):
            return NetworkAttachmentManager.build_delete_deploy_payloads(config, *target_maps, strategy=strategy)

        def _build_deploy_payloads(self, _config, *target_maps):
            assert target_maps == ({}, {})
            return []

        def _build_pending_network_deploy_payloads(self, *_args):
            raise AssertionError("detach targets must not fall back to Network deployment")

        def _merge_api_trace(self, result, trace):
            result.update(trace)

        def _deploy_network_attachments(self, _args, _strategy, payload, undeploy=False):
            self.deploy_calls.append((payload, undeploy))
            return {"changed": True}

    coordinator = Coordinator()
    result = NetworkStateMachine(coordinator)._deploy_after_attachment_changes(
        {"changed": True},
        [{"network_name": "BLUE_NET", "deploy_type": deploy_type}],
        {"state": "replaced"},
        _orchestrator().strategy,
        {"deploy_targets": {"BLUE_NET": {"SERIAL1"}}},
        {},
        defer_deploy,
    )
    expected_payload = {"switchIds": ["SERIAL1"]}
    if deploy_type == "network":
        expected_payload["networkNames"] = ["BLUE_NET"]

    if defer_deploy:
        assert result["_deferred_deploy_payloads"] == [{"_undeploy": True, **expected_payload}]
        assert coordinator.deploy_calls == []
    elif check_mode:
        assert result["check_mode_deploy_payloads"] == [expected_payload]
        assert coordinator.deploy_calls == []
    else:
        assert coordinator.deploy_calls == [(expected_payload, True)]


def test_network_attachment_only_detach_without_switch_id_rejects_network_fallback():
    class Coordinator:
        def _build_delete_deploy_payloads(self, config, *target_maps, strategy=None):
            return NetworkAttachmentManager.build_delete_deploy_payloads(config, *target_maps, strategy=strategy)

    with pytest.raises(ValueError, match="without affected switch IDs"):
        NetworkStateMachine(Coordinator())._deploy_after_attachment_changes(
            {"changed": True},
            [{"network_name": "BLUE_NET", "deploy_type": "network"}],
            {"state": "replaced"},
            _orchestrator().strategy,
            {"deploy_targets": {"BLUE_NET": set()}},
            {},
            False,
        )


def test_network_mixed_detach_and_attach_deploys_detach_first_at_selected_scope():
    class Module:
        check_mode = False

    class Coordinator:
        module = Module()

        def __init__(self):
            self.calls = []

        def _build_delete_deploy_payloads(self, config, *target_maps, strategy=None):
            return NetworkAttachmentManager.build_delete_deploy_payloads(config, *target_maps, strategy=strategy)

        def _build_deploy_payloads(self, _config, *target_maps):
            assert target_maps == ({}, {"BLUE_NET": {"SERIAL2"}})
            return [{"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL2"]}]

        def _merge_api_trace(self, result, trace):
            result["changed"] = result.get("changed", False) or trace.get("changed", False)

        def _deploy_network_attachments(self, _args, _strategy, payload, undeploy=False):
            self.calls.append((payload, undeploy))
            return {"changed": True}

    coordinator = Coordinator()
    NetworkStateMachine(coordinator)._deploy_after_attachment_changes(
        {"changed": True},
        [{"network_name": "BLUE_NET", "deploy_type": "switch"}],
        {"state": "replaced"},
        _orchestrator().strategy,
        {"deploy_targets": {"BLUE_NET": {"SERIAL1"}}},
        {"deploy_targets": {"BLUE_NET": {"SERIAL2"}}},
        False,
    )

    assert coordinator.calls == [
        ({"switchIds": ["SERIAL1"]}, True),
        ({"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL2"]}, False),
    ]


def test_network_state_machine_deploy_false_skips_pending_fallback_query():
    class Module:
        check_mode = False

    class Coordinator:
        module = Module()

        def _build_deploy_payloads(self, *_args):
            return []

        def _build_pending_network_deploy_payloads(self, *_args):
            return []

        def _deploy_enabled_by_network(self, _config):
            return {"BLUE_NET": False}

        def _configured_network_names(self, _config):
            return ["BLUE_NET"]

        def _query_current_networks_with_trace(self, *_args):
            raise AssertionError("deploy false must not query current networks for fallback deploy")

    coordinator = Coordinator()
    result = NetworkStateMachine(coordinator)._deploy_after_attachment_changes(
        {"changed": True, "after": [{"network_name": "BLUE_NET", "network_status": "pending"}]},
        [{"network_name": "BLUE_NET", "deploy": False}],
        {"config": [{"network_name": "BLUE_NET", "deploy": False}]},
        object(),
        {},
        {},
        False,
    )

    assert result["changed"] is True


def test_network_state_machine_skips_pending_fallback_query_when_after_is_complete():
    class Module:
        check_mode = False

    class Coordinator:
        module = Module()

        def __init__(self):
            self.pending_calls = 0

        def _build_deploy_payloads(self, *_args):
            return []

        def _build_pending_network_deploy_payloads(self, *_args):
            self.pending_calls += 1
            return []

        def _deploy_enabled_by_network(self, _config):
            return {"BLUE_NET": True, "GREEN_NET": False}

        def _configured_network_names(self, _config):
            return ["BLUE_NET", "GREEN_NET"]

        def _query_current_networks_with_trace(self, *_args):
            raise AssertionError("complete after data should skip the fallback current-state query")

    coordinator = Coordinator()
    result = NetworkStateMachine(coordinator)._deploy_after_attachment_changes(
        {
            "changed": False,
            "after": [
                {"network_name": "BLUE_NET", "network_status": "deployed"},
                {"network_name": "GREEN_NET", "network_status": "pending"},
            ],
        },
        [
            {"network_name": "BLUE_NET", "deploy": True},
            {"network_name": "GREEN_NET", "deploy": False},
        ],
        {"config": []},
        object(),
        {},
        {},
        False,
    )

    assert coordinator.pending_calls == 1
    assert result["changed"] is False


def test_network_bulk_delete_retries_only_sync_failed_networks():
    orchestrator = _orchestrator()
    requested_payloads = []

    def request(**kwargs):
        requested_payloads.append(list(kwargs["data"]["networkNames"]))
        if len(requested_payloads) == 1:
            orchestrator.rest_send.response_current = {
                "DATA": {
                    "results": [
                        {"networkName": "BLUE_NET", "status": "success"},
                        {
                            "networkName": "GREEN_NET",
                            "status": "failed",
                            "message": "Fabric re-sync is in progress. Retry after sync completes.",
                        },
                    ]
                }
            }
            raise Exception("partial delete failure")
        return {"results": [{"networkName": "GREEN_NET", "status": "success"}]}

    object.__setattr__(orchestrator, "delete_retry_delay", 0)
    object.__setattr__(orchestrator, "_request", request)

    result = orchestrator._delete_bulk_with_retry(["BLUE_NET", "GREEN_NET"])

    assert requested_payloads == [
        ["BLUE_NET", "GREEN_NET"],
        ["GREEN_NET"],
    ]
    assert result["results"] == [
        {"networkName": "GREEN_NET", "status": "success"},
        {"networkName": "BLUE_NET", "status": "success"},
    ]


def test_mcfg_parent_network_delete_uses_remove_action_body():
    orchestrator = _mcfg_parent_orchestrator()
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {"results": [{"networkName": name, "status": "success"} for name in kwargs["data"]["networkNames"]]}

    object.__setattr__(orchestrator, "delete_retry_delay", 0)
    object.__setattr__(orchestrator, "_request", request)

    result = orchestrator._delete_bulk_with_retry(["BLUE_NET", "GREEN_NET"])

    assert requests == [
        {
            "path": "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networkActions/remove",
            "verb": HttpVerbEnum.POST,
            "data": {"networkNames": ["BLUE_NET", "GREEN_NET"]},
            "operation_type": OperationType.DELETE,
        }
    ]
    assert result["results"] == [
        {"networkName": "BLUE_NET", "status": "success"},
        {"networkName": "GREEN_NET", "status": "success"},
    ]


def test_delete_deploy_payloads_ignore_deploy_false():
    payloads = NetworkAttachmentManager.build_delete_deploy_payloads(
        [
            {
                "network_name": "BLUE_NET",
                "deploy": False,
            }
        ],
        {"BLUE_NET": {"FDO123"}},
    )

    assert payloads == [{"switchIds": ["FDO123"]}]


def test_delete_deploy_payloads_honor_network_deploy_type():
    payloads = NetworkAttachmentManager.build_delete_deploy_payloads(
        [
            {
                "network_name": "BLUE_NET",
                "deploy": False,
                "deploy_type": "network",
            }
        ],
        {"BLUE_NET": {"FDO123"}},
    )

    assert payloads == [{"networkNames": ["BLUE_NET"], "switchIds": ["FDO123"]}]


def test_delete_deploy_payloads_combine_switches_across_deploy_types():
    payloads = NetworkAttachmentManager.build_delete_deploy_payloads(
        [
            {"network_name": "BLUE_NET", "deploy_type": "switch"},
            {"network_name": "GREEN_NET", "deploy_type": "switch"},
            {"network_name": "RED_NET", "deploy_type": "network"},
        ],
        {
            "BLUE_NET": {"SERIAL1"},
            "GREEN_NET": {"SERIAL1", "SERIAL2"},
            "RED_NET": {"SERIAL3"},
        },
    )

    assert payloads == [
        {"switchIds": ["SERIAL1", "SERIAL2"]},
        {"networkNames": ["RED_NET"], "switchIds": ["SERIAL3"]},
    ]


def test_delete_deploy_payloads_group_resource_targets_without_cross_deploy():
    payloads = NetworkAttachmentManager.build_delete_deploy_payloads(
        [
            {"network_name": "BLUE_NET", "deploy_type": "network"},
            {"network_name": "GREEN_NET", "deploy_type": "network"},
            {"network_name": "RED_NET", "deploy_type": "network"},
        ],
        {
            "BLUE_NET": {"SERIAL1"},
            "GREEN_NET": {"SERIAL2"},
            "RED_NET": {"SERIAL1"},
        },
    )

    assert payloads == [
        {"networkNames": ["BLUE_NET", "RED_NET"], "switchIds": ["SERIAL1"]},
        {"networkNames": ["GREEN_NET"], "switchIds": ["SERIAL2"]},
    ]


def test_mcfg_parent_delete_deploy_payloads_force_resource_scope():
    payloads = NetworkAttachmentManager.build_delete_deploy_payloads(
        [{"network_name": "BLUE_NET", "deploy_type": "switch"}],
        {"BLUE_NET": {"SERIAL1", "SERIAL2"}},
        strategy=_mcfg_parent_orchestrator().strategy,
    )

    assert payloads == [{"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1", "SERIAL2"]}]


def test_mcfg_parent_normal_deploy_keeps_resource_switch_targets():
    payloads = NetworkAttachmentManager.build_deploy_payloads(
        [{"network_name": "BLUE_NET", "deploy_type": "network"}],
        {"BLUE_NET": {"SERIAL1", "SERIAL2"}},
        strategy=_mcfg_parent_orchestrator().strategy,
    )

    assert payloads == [{"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1", "SERIAL2"]}]


def test_delete_deploy_payloads_without_switch_ids_do_not_fall_back_to_network_scope():
    assert NetworkAttachmentManager.build_delete_deploy_payloads([{"network_name": "BLUE_NET", "deploy_type": "network"}], {"BLUE_NET": set()}) == []


@pytest.mark.parametrize(
    "network_status,attachment_status,attached,deploy,expected",
    [
        ("pending", "pending", True, True, [{"networkNames": ["BLUE_NET"], "switchIds": ["FDO123"]}]),
        ("pending", None, None, True, [{"networkNames": ["BLUE_NET"]}]),
        (ConfigurationStatus.PENDING, None, None, True, [{"networkNames": ["BLUE_NET"]}]),
        ("deployed", "pending", False, True, [{"networkNames": ["BLUE_NET"], "switchIds": ["FDO123"]}]),
        (ConfigurationStatus.DEPLOYED, ConfigurationStatus.PENDING, False, True, [{"networkNames": ["BLUE_NET"], "switchIds": ["FDO123"]}]),
        ("deployed", "pending", False, False, []),
    ],
)
def test_pending_network_deploy_payload_respects_status_and_intent(network_status, attachment_status, attached, deploy, expected):
    manager = NetworkAttachmentManager(coordinator=_NetworkAttachmentCoordinator())
    rows = [] if attachment_status is None else [{"networkName": "BLUE_NET", "switchId": "FDO123", "attach": attached, "status": attachment_status}]
    manager.current_attachment_details_ignore_missing = lambda *_args: rows

    payloads = manager.build_pending_network_deploy_payloads(
        {"after": [{"network_name": "BLUE_NET", "network_status": network_status}]},
        [{"network_name": "BLUE_NET", "deploy": deploy}],
        {"config": []},
        _orchestrator().strategy,
    )

    assert payloads == expected


def test_planned_attach_payloads_ignore_api_empty_defaults():
    current = {
        ("BLUE_NET", "FDO123"): {
            "networkName": "BLUE_NET",
            "switchId": "FDO123",
            "vlanId": 2301,
            "attach": True,
            "status": "pending",
            "instanceValues": {},
            "extraConfig": "",
            "interfaces": [
                {
                    "mode": "access",
                    "interfaceRange": "Ethernet1/10",
                }
            ],
        }
    }
    desired = {
        ("BLUE_NET", "FDO123"): {
            "networkName": "BLUE_NET",
            "switchId": "FDO123",
            "vlanId": 2301,
            "attach": True,
            "interfaces": [
                {
                    "mode": "access",
                    "interfaceRange": "Ethernet1/10",
                }
            ],
        }
    }

    assert NetworkAttachmentManager.planned_attach_payloads(current, desired) == []


def test_planned_attach_payloads_detect_real_interface_change():
    current = {
        ("BLUE_NET", "FDO123"): {
            "networkName": "BLUE_NET",
            "switchId": "FDO123",
            "vlanId": 2301,
            "attach": True,
            "interfaces": [
                {
                    "mode": "access",
                    "interfaceRange": "Ethernet1/10",
                }
            ],
        }
    }
    desired_payload = {
        "networkName": "BLUE_NET",
        "switchId": "FDO123",
        "vlanId": 2301,
        "attach": True,
        "interfaces": [
            {
                "mode": "access",
                "interfaceRange": "Ethernet1/11",
            }
        ],
    }

    assert NetworkAttachmentManager.planned_attach_payloads(current, {("BLUE_NET", "FDO123"): desired_payload}) == [desired_payload]


def test_pending_network_status_is_not_delete_ready():
    class Module:
        params = {}

        def fail_json(self, **kwargs):
            raise RuntimeError(kwargs["msg"])

    class Coordinator:
        module = Module()

        def _query_current_networks_by_names(self, _module_args, _strategy, network_names):
            assert network_names == ["BLUE_NET"]
            return [{"networkName": "BLUE_NET", "networkStatus": "pending"}]

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.wait_attempts = 1
    manager.wait_delay = 0
    manager.undeploy_retry_attempts = 0
    manager.current_attachment_details_ignore_missing = lambda *_args: []

    with pytest.raises(RuntimeError, match="Timed out waiting for networks"):
        manager.wait_for_networks_delete_ready(
            {"config": [{"network_name": "BLUE_NET"}]},
            _orchestrator().strategy,
        )


def test_pending_attachment_status_is_not_delete_ready():
    class Module:
        params = {}

        def fail_json(self, **kwargs):
            raise RuntimeError(kwargs["msg"])

    class Coordinator:
        module = Module()

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.wait_attempts = 1
    manager.wait_delay = 0
    manager.undeploy_retry_attempts = 0
    manager.current_attachment_details_ignore_missing = lambda *_args: [
        {
            "networkName": "BLUE_NET",
            "switchId": "FDO123",
            "attach": False,
            "status": "pending",
        }
    ]

    with pytest.raises(RuntimeError, match="Timed out waiting for network attachments"):
        manager.wait_for_attachments_delete_ready(
            {"config": [{"network_name": "BLUE_NET"}]},
            _orchestrator().strategy,
        )


def test_deleted_attachment_phase_with_empty_targets_does_not_query_all_attachments():
    class Module:
        params = {}

        def fail_json(self, **kwargs):
            raise AssertionError(kwargs)

    class Coordinator:
        module = Module()

        def _new_network_orchestrator(self, *_args):
            raise AssertionError("empty deleted target set must not query all attachments")

    manager = NetworkAttachmentManager(coordinator=Coordinator())

    assert manager.apply_deleted_phase(
        {"config": [{"network_name": "MISSING_NET"}]},
        _orchestrator().strategy,
        network_names=[],
    ) == {"deploy_targets": {}}


def test_attachment_delete_wait_chunks_large_network_name_sets():
    class Module:
        params = {}

        def fail_json(self, **kwargs):
            raise RuntimeError(kwargs["msg"])

    class Coordinator:
        module = Module()

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.wait_attempts = 1
    manager.wait_delay = 0
    manager.wait_chunk_size = 2
    queried_chunks = []

    def query(_module_args, _strategy, names):
        queried_chunks.append(names)
        return []

    manager.current_attachment_details_ignore_missing = query

    manager.wait_for_attachments_delete_ready(
        {"config": [{"network_name": f"NET_{index}"} for index in range(5)]},
        _orchestrator().strategy,
    )

    assert queried_chunks == [["NET_0", "NET_1"], ["NET_2", "NET_3"], ["NET_4"]]


@pytest.mark.parametrize("deploy_type", ["switch", "network"])
def test_pending_attachment_delete_wait_retries_undeploy(deploy_type):
    class Module:
        params = {}

        def fail_json(self, **kwargs):
            raise RuntimeError(kwargs["msg"])

    class Coordinator:
        module = Module()

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.wait_attempts = 1
    manager.wait_delay = 0
    manager.undeploy_retry_attempts = 1
    manager.current_attachment_details_ignore_missing = lambda *_args: [
        {
            "networkName": "BLUE_NET",
            "switchId": "FDO123",
            "attach": False,
            "status": "pending",
        }
    ]
    deploy_payloads = []
    manager.deploy_network_attachments = lambda _module_args, _strategy, payload, undeploy=False: deploy_payloads.append((payload, undeploy))

    with pytest.raises(RuntimeError, match="Timed out waiting for network attachments"):
        manager.wait_for_attachments_delete_ready(
            {"config": [{"network_name": "BLUE_NET", "deploy_type": deploy_type}]},
            _orchestrator().strategy,
        )

    expected_payload = {"switchIds": ["FDO123"]}
    if deploy_type == "network":
        expected_payload["networkNames"] = ["BLUE_NET"]
    assert deploy_payloads == [(expected_payload, True)]


def test_pending_network_delete_wait_retries_undeploy():
    class Module:
        params = {}

        def fail_json(self, **kwargs):
            raise RuntimeError(kwargs["msg"])

    class Coordinator:
        module = Module()

        def _query_current_networks_by_names(self, _module_args, _strategy, network_names):
            assert network_names == ["BLUE_NET"]
            return [{"networkName": "BLUE_NET", "networkStatus": "pending"}]

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.wait_attempts = 1
    manager.wait_delay = 0
    manager.undeploy_retry_attempts = 1
    manager.current_attachment_details_ignore_missing = lambda *_args: []
    deploy_payloads = []
    manager.deploy_network_attachments = lambda _module_args, _strategy, payload, undeploy=False: deploy_payloads.append((payload, undeploy))

    with pytest.raises(RuntimeError, match="Timed out waiting for networks"):
        manager.wait_for_networks_delete_ready(
            {"config": [{"network_name": "BLUE_NET"}]},
            _orchestrator().strategy,
        )

    assert deploy_payloads == []


def test_network_delete_wait_allows_deployed_definition_after_detached_attachment_rows():
    class Module:
        params = {}

        def fail_json(self, **kwargs):
            raise RuntimeError(kwargs)

    class Coordinator:
        module = Module()

        def _query_current_networks_by_names(self, _module_args, _strategy, network_names):
            assert network_names == ["BLUE_NET"]
            return [{"networkName": "BLUE_NET", "networkStatus": "deployed"}]

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.wait_attempts = 1
    manager.wait_delay = 0
    manager.undeploy_retry_attempts = 0
    manager.current_attachment_details_ignore_missing = lambda *_args: [
        {
            "networkName": "BLUE_NET",
            "switchId": "FDO123",
            "attach": False,
            "status": "notApplicable",
        }
    ]

    manager.wait_for_networks_delete_ready(
        {"config": [{"network_name": "BLUE_NET"}]},
        _orchestrator().strategy,
    )


def test_network_delete_wait_blocks_on_pending_attachment_even_when_network_status_is_ready():
    class Module:
        params = {}

        def fail_json(self, **kwargs):
            raise RuntimeError(kwargs)

    class Coordinator:
        module = Module()

        def _query_current_networks_by_names(self, _module_args, _strategy, network_names):
            assert network_names == ["BLUE_NET"]
            return [{"networkName": "BLUE_NET", "networkStatus": "notApplicable"}]

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.wait_attempts = 1
    manager.wait_delay = 0
    manager.undeploy_retry_attempts = 0
    manager.current_attachment_details_ignore_missing = lambda *_args: [
        {
            "networkName": "BLUE_NET",
            "switchId": "FDO123",
            "attach": False,
            "status": "pending",
        }
    ]

    with pytest.raises(RuntimeError, match="last_attachment_blockers"):
        manager.wait_for_networks_delete_ready(
            {"config": [{"network_name": "BLUE_NET"}]},
            _orchestrator().strategy,
        )


@pytest.mark.parametrize("status", ["failed", "outOfSync"])
def test_network_delete_wait_blocks_and_retries_failed_or_out_of_sync_attachment(status):
    class Module:
        params = {}

        def fail_json(self, **kwargs):
            raise RuntimeError(kwargs)

    class Coordinator:
        module = Module()

        def _query_current_networks_by_names(self, _module_args, _strategy, network_names):
            assert network_names == ["BLUE_NET"]
            return [{"networkName": "BLUE_NET", "networkStatus": "notApplicable"}]

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.wait_attempts = 1
    manager.wait_delay = 0
    manager.undeploy_retry_attempts = 1
    manager.current_attachment_details_ignore_missing = lambda *_args: [
        {
            "networkName": "BLUE_NET",
            "switchId": "FDO123",
            "attach": False,
            "status": status,
        }
    ]
    deploy_payloads = []
    manager.deploy_network_attachments = lambda _module_args, _strategy, payload, undeploy=False: deploy_payloads.append((payload, undeploy))

    with pytest.raises(RuntimeError, match="last_attachment_blockers"):
        manager.wait_for_networks_delete_ready(
            {"config": [{"network_name": "BLUE_NET"}]},
            _orchestrator().strategy,
        )

    assert deploy_payloads == [({"switchIds": ["FDO123"]}, True)]


@pytest.mark.parametrize("status", ["failed", "outOfSync"])
def test_network_delete_wait_retries_and_blocks_failed_or_out_of_sync_network_status(status):
    class Module:
        params = {}

        def fail_json(self, **kwargs):
            raise RuntimeError(kwargs["msg"])

    class Coordinator:
        module = Module()

        def _query_current_networks_by_names(self, _module_args, _strategy, network_names):
            assert network_names == ["BLUE_NET"]
            return [{"networkName": "BLUE_NET", "networkStatus": status}]

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.wait_attempts = 1
    manager.wait_delay = 0
    manager.undeploy_retry_attempts = 1
    manager.current_attachment_details_ignore_missing = lambda *_args: [
        {
            "networkName": "BLUE_NET",
            "switchId": "FDO123",
            "attach": False,
            "status": "notApplicable",
        }
    ]
    deploy_payloads = []
    manager.deploy_network_attachments = lambda _module_args, _strategy, payload, undeploy=False: deploy_payloads.append((payload, undeploy))

    with pytest.raises(RuntimeError, match="Timed out waiting for networks"):
        manager.wait_for_networks_delete_ready(
            {"config": [{"network_name": "BLUE_NET"}]},
            _orchestrator().strategy,
        )

    assert deploy_payloads == []


def test_network_response_omits_disable_rt_auto_without_normalizing_rt_auto():
    model = NDNetworkOrchestrator.model_class.from_response(
        {
            "fabricName": "fab1",
            "networkName": "BLUE_NET",
            "vrfName": "NA",
            "networkType": "vxlanIbgp",
            "networkMode": "layer2",
            "l2Data": {
                "disableRtAuto": False,
                "vlanName": "BLUE_VLAN",
                "fabricData": {"enableIr": False},
            },
        }
    )
    config = model.to_config()

    assert config["layer"] == "layer2"
    assert "rt_auto" not in config["l2_data"]
    assert "rtAuto" not in config["l2_data"]
    assert "disableRtAuto" not in config["l2_data"]
    assert "enableIr" not in config["l2_data"]["fabric_data"]


def test_network_status_is_not_sent_in_write_payload_or_diff():
    current = NDNetworkOrchestrator.model_class.from_response(
        {
            "fabricName": "fab1",
            "networkName": "BLUE_NET",
            "vrfName": "NA",
            "networkType": "vxlanIbgp",
            "networkMode": "layer2",
            "networkStatus": "pending",
        }
    )
    desired = NDNetworkOrchestrator.model_class.from_config(
        {
            "network_name": "BLUE_NET",
            "vrf_name": "NA",
            "network_type": "vxlanIbgp",
            "layer": "layer2",
        }
    )

    assert "networkStatus" not in current.to_payload()
    assert current.get_diff(desired, exclude_unset=True) is True


def test_network_gathered_output_uses_public_config_shape():
    model = NDNetworkOrchestrator.model_class.from_response(
        {
            "fabricName": "fab1",
            "networkName": "BLUE_NET",
            "networkStatus": "deployed",
            "displayName": "BLUE_NET",
            "vrfName": "BLUE_VRF",
            "networkId": 30001,
            "vlanId": 101,
            "networkType": "vxlanIbgp",
            "networkMode": "layer3",
            "vlanNetworkType": "normal",
            "l2Data": {
                "vlanName": "BLUE_VLAN",
                "fabricData": {
                    "multicastGroup": "239.1.1.11",
                    "dsVni": 50001,
                },
            },
            "l3Data": {
                "gatewayIpv4Address": "10.10.10.1/24",
                "gatewayIpv6Address": "2001:db8::1/64",
                "secondaryGatewayIpv4Collection": ["10.10.11.1/24"],
                "secondaryGatewayIpv6Collection": ["2001:db8:1::1/64"],
                "vlanInterfaceDescription": "blue svi",
                "mtu": 9000,
                "arpSuppression": True,
                "routingTag": 12345,
                "fabricData": {
                    "dhcpServers": [{"serverAddress": "10.1.1.10", "serverVrf": "management"}],
                    "loopbackId": 101,
                    "igmpVersion": 3,
                    "netflow": True,
                    "l2NetflowMonitor": "VLAN_MON",
                    "l3NetflowMonitor": "INT_MON",
                    "gatewayOnBorder": True,
                    "ipv4Trm": True,
                    "ipv6Trm": True,
                },
            },
        }
    )
    output = NDOutput(output_level="normal", state="gathered")
    output.assign(
        after=NDConfigCollection(NDNetworkOrchestrator.model_class, [model]),
        gathered_spec=NDNetworkOrchestrator.model_class.get_argument_spec()["config"]["options"],
    )

    gathered = output.format()["gathered"][0]

    for internal_key in ("fabric_name", "network_status", "network_type", "l2_data", "l3_data"):
        assert internal_key not in gathered
    assert gathered["network_name"] == "BLUE_NET"
    assert gathered["layer"] == "layer3"
    assert gathered["vlan_name"] == "BLUE_VLAN"
    assert gathered["multicast_group_address"] == "239.1.1.11"
    assert "ds_vni" not in model.to_gathered_config()
    assert gathered["gateway_ipv4_address"] == "10.10.10.1/24"
    assert gathered["interface_netflow_monitor"] == "INT_MON"
    NetworkConfigModel.from_config(gathered)


def _layer2_network_readback(vlan_network_type, with_igmp):
    return {
        "fabricName": "fab1",
        "networkName": "USERS",
        "networkType": "vxlanIbgp",
        "networkMode": "layer2",
        "vlanNetworkType": vlan_network_type,
        "vrfName": "NA",
        "networkId": 30001,
        "vlanId": 101,
        "l2Data": {"vlanName": "USERS", "fabricData": {"multicastGroup": "239.1.1.11"}},
        "l3Data": {
            "routingTag": 12345,
            "arpSuppression": False,
            "fabricData": {
                "netflow": False,
                "gatewayOnBorder": False,
                "ipv4Trm": False,
                "ipv6Trm": False,
                **({"igmpVersion": 3} if with_igmp else {}),
            },
        },
    }


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("vlan_network_type", ["normal", "privatePrimary"])
@pytest.mark.parametrize("with_igmp", [False, True], ids=["nd42-shaped", "nd43-shaped"])
def test_layer2_gathered_config_replays_without_controller_l3_echoes(state, vlan_network_type, with_igmp):
    model = NDNetworkOrchestrator.model_class.from_response(_layer2_network_readback(vlan_network_type, with_igmp))
    output = NDOutput(output_level="normal", state="gathered")
    output.assign(
        after=NDConfigCollection(NDNetworkOrchestrator.model_class, [model]),
        gathered_spec=NDNetworkOrchestrator.model_class.get_argument_spec()["config"]["options"],
    )
    gathered = output.format()["gathered"][0]
    assert gathered["layer"] == "layer2"
    assert gathered["vlan_name"] == "USERS"
    assert gathered["multicast_group_address"] == "239.1.1.11"
    assert not {"mtu", "arp_suppression", "routing_tag", "igmp_version", "gateway_on_border", "trm_enable", "ipv6_trm"} & gathered.keys()
    # Read-side diagnostics retain the controller block without inventing an MTU.
    assert "mtu" not in model.to_config()["l3_data"]
    assert "mtu" not in model.l3_data.model_fields_set
    orchestrator = _orchestrator()
    coordinator = NetworkWorkflowCoordinator(module=_Module({"output_level": "normal"}), strategy=orchestrator.strategy)
    validated = _validated_network_config([gathered])
    NetworkConfigModel.from_config(validated[0], context={"state": state})
    parsed = coordinator._parse_config(validated, orchestrator.strategy.config_model_cls, state)
    orchestrator.rest_send.params["state"] = crud_module_args({"state": state})["state"]
    proposed = orchestrator.model_class.from_config(orchestrator.prepare_config_data(parsed)[0])
    assert model.get_diff(proposed, exclude_unset=state == "merged")
    assert orchestrator._create_or_update_payload(proposed).get("l3Data") in (None, {"fabricData": {"netflow": False}})


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("strategy_cls", [StandaloneNetworkStrategy, MultisiteParentNetworkStrategy])
@pytest.mark.parametrize("vlan_network_type", ["normal", "privatePrimary"])
@pytest.mark.parametrize("with_igmp", [False, True], ids=["nd42-shaped", "nd43-shaped"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_layer2_controller_l3_echo_does_not_trigger_state_machine_update(state, strategy_cls, vlan_network_type, with_igmp, check_mode):
    entry = {
        "network_name": "USERS",
        "layer": "layer2",
        "vlan_network_type": "normal" if vlan_network_type == "normal" else "primary",
        "network_id": 30001,
        "vlan_id": 101,
        "vlan_name": "USERS",
        "multicast_group_address": "239.1.1.11",
    }
    readback = _layer2_network_readback(vlan_network_type, with_igmp)
    if strategy_cls is MultisiteParentNetworkStrategy:
        entry.pop("multicast_group_address")
        readback["l2Data"]["fabricData"].pop("multicastGroup")
    effective_state = crud_module_args({"state": state})["state"]
    strategy = strategy_cls(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    module = _Module({"state": effective_state, "config": [entry], "output_level": "normal"})
    module.check_mode = check_mode
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=strategy)
    parsed = coordinator._parse_config(_validated_network_config([entry]), strategy.config_model_cls, state)
    orchestrator = _LayerValidationNetworkOrchestrator(
        rest_send=RestSend({"state": effective_state}),
        strategy=strategy,
        inventory=[readback],
    )
    sm = NDStateMachine(module=module, model_orchestrator=orchestrator, config=orchestrator.prepare_config_data(parsed))
    sm.manage_state()
    assert not sm.results.changed
    assert sm.output.format()["changed"] is False
    assert not sm.sent
    assert not orchestrator.written_payloads
    assert orchestrator.query_count == 1


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("field,value,payload_key", [("vlan_name", "USERS_NEW", "vlanName"), ("multicast_group_address", "239.1.1.12", "multicastGroup")])
def test_layer2_real_update_remains_actionable_despite_controller_l3_echo(state, field, value, payload_key):
    entry = {
        "network_name": "USERS",
        "layer": "layer2",
        "network_id": 30001,
        "vlan_id": 101,
        "vlan_name": "USERS",
        "multicast_group_address": "239.1.1.11",
        field: value,
    }
    module = _Module({"state": state, "config": [entry], "output_level": "normal"})
    strategy = StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=strategy)
    parsed = coordinator._parse_config(_validated_network_config([entry]), strategy.config_model_cls, state)
    orchestrator = _LayerValidationNetworkOrchestrator(
        rest_send=RestSend({"state": state}), strategy=strategy, inventory=[_layer2_network_readback("normal", True)]
    )
    sm = NDStateMachine(module=module, model_orchestrator=orchestrator, config=orchestrator.prepare_config_data(parsed))
    sm.manage_state()
    assert sm.output.format()["changed"] is True
    assert len(orchestrator.written_payloads) == 1
    payload = orchestrator.written_payloads[0]
    target = payload["l2Data"]["fabricData"] if field == "multicast_group_address" else payload["l2Data"]
    assert target[payload_key] == value
    assert payload.get("l3Data") in (None, {"fabricData": {"netflow": False}})
    assert orchestrator.model_class.from_response(payload).get_diff(sm.proposed.get("USERS"), exclude_unset=state == "merged")


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("strategy_cls", [StandaloneNetworkStrategy])
@pytest.mark.parametrize("vlan_network_type", ["normal", "primary"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_layer2_vlan_netflow_survives_prepare_payload_gather_and_repeat(state, strategy_cls, vlan_network_type, check_mode):
    """Exercise NetFlow through the real CRUD comparison and replay public gathered configuration."""
    entry = {
        "network_name": "USERS",
        "layer": "layer2",
        "vlan_network_type": vlan_network_type,
        "network_id": 30001,
        "vlan_id": 101,
        "netflow_enable": True,
        "vlan_netflow_monitor": "VLAN_MON",
    }
    effective_state = crud_module_args({"state": state})["state"]
    strategy = strategy_cls(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    module = _Module({"state": effective_state, "config": [entry], "output_level": "normal"})
    module.check_mode = check_mode
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=strategy)
    parsed = coordinator._parse_config(_validated_network_config([entry]), strategy.config_model_cls, state)
    orchestrator = _LayerValidationNetworkOrchestrator(rest_send=RestSend({"state": effective_state}), strategy=strategy, inventory=[])
    prepared = orchestrator.prepare_config_data(parsed)
    sm = NDStateMachine(module=module, model_orchestrator=orchestrator, config=prepared)
    sm.manage_state()
    assert sm.sent.get("USERS") is not None
    assert sm.output.format()["changed"] is True
    expected = {"fabricData": {"netflow": True, "l2NetflowMonitor": "VLAN_MON"}}
    payload = orchestrator._create_or_update_payload(sm.proposed.get("USERS"))
    assert payload["l3Data"] == expected
    assert bool(orchestrator.written_payloads) is not check_mode
    assert orchestrator.query_count == 1

    readback = {**payload, "l3Data": {**expected, "mtu": 9216, "arpSuppression": False}}
    model = orchestrator.model_class.from_response(readback)
    gathered = model.to_gathered_config()
    assert gathered["netflow_enable"] is True
    assert gathered["vlan_netflow_monitor"] == "VLAN_MON"
    assert "mtu" not in gathered
    NetworkConfigModel.from_config(_validated_network_config([gathered])[0], context={"state": state})
    repeated = _LayerValidationNetworkOrchestrator(rest_send=RestSend({"state": effective_state}), strategy=strategy, inventory=[readback])
    repeat_sm = NDStateMachine(module=module, model_orchestrator=repeated, config=prepared)
    repeat_sm.manage_state()
    assert not repeat_sm.results.changed
    assert not repeated.written_payloads
    assert repeated.query_count == 1


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("vlan_network_type", ["community", "isolated"])
def test_secondary_pvlan_gathered_output_replays_public_config(state, vlan_network_type):
    """Rebuild public PVLAN configuration without exposing internal custom-template controls."""
    orchestrator = _orchestrator()
    orchestrator.rest_send.params["state"] = crud_module_args({"state": state})["state"]
    entry = {
        "network_name": "SECONDARY",
        "network_id": 30002,
        "vlan_id": 102,
        "vlan_network_type": vlan_network_type,
        "primary_network_id": 30001,
        "vlan_name": "SECONDARY_VLAN",
        "multicast_group_address": "239.1.1.22",
    }
    prepared = orchestrator.prepare_config_data([NetworkConfigModel.from_config(entry).to_config(exclude_unset=True)])[0]
    proposed = orchestrator.model_class.from_config(prepared)
    readback = orchestrator._normalize_query_network_item(orchestrator._create_or_update_payload(proposed))
    readback["networkStatus"] = "deployed"
    current = orchestrator.model_class.from_response(readback)
    gathered = current.to_gathered_config()
    assert gathered["vlan_network_type"] == vlan_network_type
    assert gathered["primary_network_id"] == 30001
    assert gathered["vlan_id"] == 102
    assert gathered["vlan_name"] == "SECONDARY_VLAN"
    assert gathered["multicast_group_address"] == "239.1.1.22"
    assert not {"vrf_name", "x_connect", "ds_vni", "network_template_name", "network_extension_template_name", "network_template_config"} & gathered.keys()
    validated = _validated_network_config([gathered])[0]
    replay = NetworkConfigModel.from_config(validated, context={"state": state}).to_config(exclude_unset=True)
    replay_model = orchestrator.model_class.from_config(orchestrator.prepare_config_data([replay])[0])
    assert current.get_diff(replay_model, exclude_unset=state == "merged")
    wire = orchestrator._create_or_update_payload(replay_model)
    assert "vlanId" not in wire
    assert wire["networkTemplateConfig"]["vlanId"] == "102"


@pytest.mark.parametrize("layer", ["layer2", "layer2WithVrf", "layer3"])
def test_template_normalization_fills_gaps_without_overwriting_explicit_data(layer):
    """Prefer explicit API identity, mode, and nested fields over incomplete template values."""
    row = {
        "networkName": "USERS",
        "networkType": "vxlanIbgp",
        "networkMode": layer,
        "networkId": 30001,
        "vlanNetworkType": "normal",
        "l2Data": {"vlanName": "ACTUAL", "fabricData": {"multicastGroup": "239.1.1.1"}},
        "l3Data": {"mtu": 9100, "gatewayIpv4Address": "192.0.2.1/24", "fabricData": {"netflow": True, "ipv4Trm": True}},
        "networkTemplateConfig": {
            "isLayer2Only": "true",
            "segmentId": "40001",
            "vlanName": "TEMPLATE",
            "mtu": "9000",
            "ENABLE_NETFLOW": "false",
            "l2NetflowMonitor": "VLAN_MON",
            "type": "Community",
        },
    }
    normalized = _orchestrator()._normalize_query_network_item(row)
    assert "layer" not in normalized
    assert normalized["networkMode"] == layer
    assert normalized["networkId"] == 30001
    assert normalized["vlanNetworkType"] == "normal"
    assert normalized["l2Data"] == row["l2Data"]
    assert normalized["l3Data"] == {**row["l3Data"], "fabricData": {"netflow": True, "ipv4Trm": True, "l2NetflowMonitor": "VLAN_MON"}}
    assert _orchestrator().model_class.from_response(normalized).layer == layer
    assert row["l3Data"]["fabricData"] == {"netflow": True, "ipv4Trm": True}


def test_template_without_mode_evidence_does_not_invent_layer3():
    """Do not infer a mode from a missing isLayer2Only template field."""
    normalized = _orchestrator()._normalize_query_network_item(
        {"networkName": "CUSTOM", "networkType": "userDefined", "networkTemplateConfig": {"mtu": "9000"}}
    )
    assert "layer" not in normalized
    assert "networkMode" not in normalized
    assert normalized["l3Data"]["mtu"] == 9000


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("layer", ["layer3", "layer2WithVrf"])
@pytest.mark.parametrize("strategy_cls", [StandaloneNetworkStrategy])
def test_sparse_x_connect_rejects_existing_routed_mode_before_writes(check_mode, layer, strategy_cls):
    """Validate cross-connect after inherited mode resolution without another inventory read."""
    coordinator, sm, parsed, orchestrator = _layer_validation_state_machine(
        [{"network_name": "USERS", "x_connect": True}],
        [{"fabricName": "fab1", "networkName": "USERS", "networkType": "vxlanIbgp", "networkMode": layer, "vrfName": "T"}],
        check_mode,
        strategy_cls,
    )
    with pytest.raises(ValueError, match="x_connect is only valid for layer2 networks"):
        coordinator._resolve_proposed_networks(sm, parsed, "merged", orchestrator.strategy)
    assert not orchestrator.written_payloads
    assert orchestrator.query_count == 1


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("strategy_cls", [StandaloneNetworkStrategy])
def test_layer2_explicit_netflow_disable_remains_actionable_and_converges(state, strategy_cls):
    """Send an explicit false value and compare the disabled readback without L3-only noise."""
    entry = {"network_name": "USERS", "layer": "layer2", "network_id": 30001, "vlan_id": 101, "netflow_enable": False}
    effective_state = crud_module_args({"state": state})["state"]
    strategy = strategy_cls(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    module = _Module({"state": effective_state, "config": [entry], "output_level": "normal"})
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=strategy)
    parsed = coordinator._parse_config(_validated_network_config([entry]), strategy.config_model_cls, state)
    readback = {
        "fabricName": "fab1",
        "networkName": "USERS",
        "networkType": "vxlanIbgp",
        "networkMode": "layer2",
        "vrfName": "NA",
        "networkId": 30001,
        "vlanId": 101,
        "vlanNetworkType": "normal",
        "l3Data": {"fabricData": {"netflow": True}},
    }
    orchestrator = _LayerValidationNetworkOrchestrator(rest_send=RestSend({"state": effective_state}), strategy=strategy, inventory=[readback])
    prepared = orchestrator.prepare_config_data(parsed)
    sm = NDStateMachine(module=module, model_orchestrator=orchestrator, config=prepared)
    sm.manage_state()
    assert sm.output.format()["changed"] is True
    assert len(orchestrator.written_payloads) == 1
    payload = orchestrator.written_payloads[0]
    assert payload["l3Data"] == {"fabricData": {"netflow": False}}
    current = orchestrator.model_class.from_response(payload)
    assert current.get_diff(sm.proposed.get("USERS"), exclude_unset=state == "merged")
    assert orchestrator.query_count == 1


def test_sparse_layer2_rename_preserves_existing_vlan_netflow():
    """A merged L2 rename must preserve omitted NetFlow state and monitor settings."""
    coordinator, sm, parsed, orchestrator = _layer_validation_state_machine(
        [{"network_name": "USERS", "vlan_name": "NEW_NAME"}],
        [
            {
                "fabricName": "fab1",
                "networkName": "USERS",
                "networkType": "vxlanIbgp",
                "networkMode": "layer2",
                "vrfName": "NA",
                "l2Data": {"vlanName": "OLD_NAME"},
                "l3Data": {"mtu": 9216, "fabricData": {"netflow": True, "l2NetflowMonitor": "VLAN_MON"}},
            }
        ],
        False,
    )
    coordinator._resolve_proposed_networks(sm, parsed, "merged", orchestrator.strategy)
    sm.manage_state()
    assert len(orchestrator.written_payloads) == 1
    payload = orchestrator.written_payloads[0]
    assert payload["l2Data"]["vlanName"] == "NEW_NAME"
    assert payload["l3Data"] == {"fabricData": {"netflow": True, "l2NetflowMonitor": "VLAN_MON"}}
    assert orchestrator.query_count == 1


def test_mcfg_layer2_netflow_payload_is_not_changed_without_onemanage_evidence():
    """Leave OneManage parent NetFlow behavior outside the Manage-only correction."""
    orchestrator = _mcfg_parent_orchestrator()
    entry = {"network_name": "USERS", "layer": "layer2", "network_id": 30001, "netflow_enable": True, "vlan_netflow_monitor": "VLAN_MON"}
    prepared = orchestrator.prepare_config_data([entry])[0]
    payload = orchestrator._create_or_update_payload(orchestrator.model_class.from_config(prepared))
    assert payload["l3Data"] == orchestrator._mcfg_parent_default_l3_data()


@pytest.mark.parametrize("network_type", ["routed", "aimlRouted", "classicLanEnhanced"])
def test_layer2_classic_or_routed_preparation_is_unchanged(network_type):
    """Keep unverified non-VXLAN Layer-2 behavior outside the NetFlow correction."""
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend({"state": "replaced"}),
        strategy=StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": network_type}),
    )
    prepared = orchestrator.prepare_config_data([{"network_name": "USERS", "layer": "layer2", "vlan_id": 101}])[0]
    assert "l3_data" not in prepared


@pytest.mark.parametrize("netflow", [False, True])
def test_layer2_child_update_preserves_requested_vlan_netflow(netflow):
    """Keep child deltas through sparse preparation, typed merging, and final payload projection."""
    orchestrator = NDNetworkOrchestrator(
        rest_send=RestSend({"state": "merged"}),
        strategy=ChildNetworkStrategy(fabric_name="child1", fabric_data={"managementType": "vxlanIbgp"}),
    )
    entry = {"network_name": "USERS", "layer": "layer2", "netflow_enable": netflow}
    if netflow:
        entry["vlan_netflow_monitor"] = "VLAN_MON"
    proposed = orchestrator.model_class.from_config(orchestrator.prepare_config_data([entry])[0])
    existing = orchestrator.model_class.from_response(
        {
            "fabricName": "child1",
            "networkName": "USERS",
            "networkType": "vxlanIbgp",
            "networkMode": "layer2",
            "vrfName": "NA",
            "l3Data": {"mtu": 9000, "fabricData": {"netflow": not netflow, "ipv4Trm": False}},
        }
    )
    merged = existing.merge(proposed)
    payload = orchestrator._create_or_update_payload(merged)
    expected = {"netflow": netflow, **({"l2NetflowMonitor": "VLAN_MON"} if netflow else {})}
    assert payload["l3Data"] == {"fabricData": expected}
    assert orchestrator.model_class.from_response(payload).get_diff(proposed, exclude_unset=True)


def test_transform_l3_network_payload_uses_l3_data_fabric_data():
    payload = _orchestrator().prepare_config_data(
        [
            {
                "network_name": "GREEN_NET",
                "layer": "layer3",
                "vrf_name": "Tenant_A",
                "network_id": 50001,
                "vlan_id": 3001,
                "gateway_ipv4_address": "192.0.2.1/24",
                "trm_enable": True,
                "netflow_enable": True,
                "vlan_netflow_monitor": "L2_MON",
                "interface_netflow_monitor": "L3_MON",
            }
        ]
    )[0]

    assert payload["layer"] == "layer3"
    assert payload["vrf_name"] == "Tenant_A"
    assert payload["l3_data"]["gatewayIpv4Address"] == "192.0.2.1/24"
    assert payload["l3_data"]["fabricData"]["ipv4Trm"] is True
    assert payload["l3_data"]["fabricData"]["netflow"] is True
    assert payload["l3_data"]["fabricData"]["l2NetflowMonitor"] == "L2_MON"
    assert payload["l3_data"]["fabricData"]["l3NetflowMonitor"] == "L3_MON"


def test_transform_l3_network_payload_defaults_trm_flags_when_unset():
    orchestrator = _orchestrator()
    prepared = orchestrator.prepare_config_data(
        [
            {
                "network_name": "GREEN_NET",
                "layer": "layer3",
                "vrf_name": "Tenant_A",
                "gateway_ipv4_address": "192.0.2.1/24",
            }
        ]
    )[0]

    model = orchestrator.model_class.from_config(prepared)
    payload = orchestrator._create_or_update_payload(model)
    assert payload["l3Data"]["mtu"] == 9216
    assert payload["l3Data"]["fabricData"]["netflow"] is False
    assert payload["l3Data"]["fabricData"]["gatewayOnBorder"] is False
    assert payload["l3Data"]["fabricData"]["ipv4Trm"] is False
    assert payload["l3Data"]["fabricData"]["ipv6Trm"] is False


def test_network_netflow_monitors_require_netflow_enable():
    with pytest.raises(ValueError, match="netflow monitor fields require netflow_enable=true"):
        NetworkConfigModel.from_config(
            {
                "network_name": "BLUE_NET",
                "layer": "layer3",
                "vrf_name": "BLUE_VRF",
                "vlan_netflow_monitor": "L2_MON",
            }
        )


def test_network_igmp_version_requires_trm_enable():
    with pytest.raises(ValueError, match="igmp_version requires trm_enable=true"):
        NetworkConfigModel.from_config(
            {
                "network_name": "BLUE_NET",
                "layer": "layer3",
                "vrf_name": "BLUE_VRF",
                "igmp_version": 3,
            }
        )

    model = NetworkConfigModel.from_config(
        {
            "network_name": "BLUE_NET",
            "layer": "layer3",
            "vrf_name": "BLUE_VRF",
            "igmp_version": 3,
            "trm_enable": True,
        }
    )

    assert model.igmp_version == 3
    assert model.trm_enable is True


def test_child_network_igmp_version_requires_trm_enable():
    with pytest.raises(ValueError, match="igmp_version requires trm_enable=true"):
        NetworkParentConfigModel.from_config(
            {
                "network_name": "BLUE_NET",
                "layer": "layer3",
                "vrf_name": "BLUE_VRF",
                "child_fabric_config": [
                    {
                        "fabric_name": "child1",
                        "igmp_version": 3,
                    }
                ],
            }
        )

    model = NetworkParentConfigModel.from_config(
        {
            "network_name": "BLUE_NET",
            "layer": "layer3",
            "vrf_name": "BLUE_VRF",
            "child_fabric_config": [
                {
                    "fabric_name": "child1",
                    "igmp_version": 3,
                    "trm_enable": True,
                }
            ],
        }
    )

    assert model.child_fabric_config[0].igmp_version == 3
    assert model.child_fabric_config[0].trm_enable is True


def test_network_interface_netflow_monitor_rejects_layer2_only():
    with pytest.raises(ValueError, match="interface_netflow_monitor is not valid for layer2 networks"):
        NetworkConfigModel.from_config(
            {
                "network_name": "BLUE_NET",
                "layer": "layer2",
                "netflow_enable": True,
                "interface_netflow_monitor": "L3_MON",
            }
        )


def test_network_netflow_monitor_empty_strings_are_omitted():
    model = NetworkConfigModel.from_config(
        {
            "network_name": "BLUE_NET",
            "layer": "layer3",
            "vrf_name": "BLUE_VRF",
            "l2NetflowMonitor": "",
            "l3NetflowMonitor": "",
        }
    )

    assert model.vlan_netflow_monitor is None
    assert model.interface_netflow_monitor is None


@pytest.mark.parametrize(
    "response,expected",
    [
        ([{"networkName": "N"}], [{"networkName": "N"}]),
        ({"networks": [{"networkName": "N"}]}, [{"networkName": "N"}]),
        ({"items": [{"networkName": "N"}]}, [{"networkName": "N"}]),
        ({"unexpected": 1}, []),
        (None, []),
    ],
)
def test_network_scoped_query_result_shapes(response, expected):
    coordinator = NetworkWorkflowCoordinator(_Module({"config": [], "state": "deleted"}), _orchestrator().strategy)

    class Orchestrator:
        def query_by_names(self, names):
            assert names == ["N"]
            return response

    coordinator._new_network_orchestrator = lambda *_args: (Orchestrator(), None)
    assert coordinator._query_current_networks_by_names({"state": "deleted"}, coordinator.strategy, ["N"]) == expected


@pytest.mark.parametrize("check_mode", [False, True])
def test_network_delete_wait_facade_forwards_only_outside_check_mode(check_mode):
    module = _Module({"state": "deleted", "config": []})
    module.check_mode = check_mode
    coordinator = NetworkWorkflowCoordinator(module, _orchestrator().strategy)
    calls = []

    class Attachments:
        def wait_for_networks_delete_ready(self, *args):
            calls.append(("networks", args))

        def wait_for_attachments_delete_ready(self, *args):
            calls.append(("attachments", args))

        def delete_wait_deadline(self, count):
            return count + 1, count

    coordinator._attachments = Attachments()
    coordinator._wait_for_networks_delete_ready({}, coordinator.strategy, ["N"], 10, 2)
    coordinator._wait_for_network_attachments_delete_ready({}, coordinator.strategy, ["N"], 10, 2)
    assert coordinator._network_delete_wait_deadline(3) == (4, 3)
    assert [name for name, _args in calls] == ([] if check_mode else ["networks", "attachments"])


@pytest.mark.parametrize(
    "scope,scoped_error,expected",
    [
        ([], False, [{"networkName": "N"}]),
        (["N"], False, [{"networkName": "N"}]),
        (["N"], True, [{"networkName": "N"}]),
    ],
)
def test_network_query_all_scoped_fallback_uses_one_unfiltered_read_when_needed(scope, scoped_error, expected, monkeypatch):
    orchestrator = _orchestrator()
    calls = []
    orchestrator._query_scope_network_names = lambda: scope

    def unfiltered():
        calls.append("unfiltered")
        return [{"networkName": "N"}]

    def scoped(_names):
        calls.append("scoped")
        if scoped_error:
            raise RuntimeError("scoped unavailable")
        return expected

    orchestrator._query_all_unfiltered = unfiltered
    monkeypatch.setattr(NDNetworkOrchestrator, "query_by_names", lambda _self, names: scoped(names))
    assert orchestrator.query_all() == expected
    assert calls == (["unfiltered"] if not scope else ["scoped", "unfiltered"] if scoped_error else ["scoped"])


def test_network_query_all_unfiltered_error_keeps_cause():
    orchestrator = _orchestrator()
    orchestrator._query_scope_network_names = lambda: []

    def fail():
        raise RuntimeError("controller unavailable")

    orchestrator._query_all_unfiltered = fail
    with pytest.raises(Exception, match="Query all networks failed: controller unavailable"):
        orchestrator.query_all()


@pytest.mark.parametrize(
    "config,state,expected",
    [
        ("not-a-dict", "merged", False),
        ({"network_name": "N", "vlan_network_type": "community", "vlan_id": 100}, "merged", False),
        ({"network_name": "N", "vlan_id": 100}, "merged", True),
    ],
)
def test_network_omitted_layer_defer_decision(config, state, expected):
    assert NDNetworkOrchestrator.should_defer_omitted_layer(config, state) is expected


def test_network_payload_helpers_preserve_sparse_and_reject_unknown_vlan_type():
    orchestrator = _orchestrator()
    assert orchestrator.query_by_names([]) == []
    assert orchestrator.prepare_config_data("not-a-list") == "not-a-list"
    assert orchestrator._template_config_string(None) == ""
    assert orchestrator._template_config_string(False) == "false"
    assert orchestrator._template_config_string(True) == "true"
    with pytest.raises(ValueError, match="vlan_network_type must be one of"):
        orchestrator._normalize_vlan_network_type("unknown")


def test_mcfg_parent_omitted_defaults_are_stripped_without_removing_explicit_fields():
    data = {
        "vlan_id": 100,
        "l2_data": {"vlanName": "N", "xConnect": False, "fabricData": {}},
        "l3_data": {"fabricData": {"gatewayOnBorder": False, "ipv4Trm": False, "ipv6Trm": False, "netflow": False}},
    }
    NDNetworkOrchestrator._remove_mcfg_parent_non_echoed_fields(data, {})
    assert data == {}
    explicit = {
        "l2_data": {"xConnect": False},
        "l3_data": {"fabricData": {"netflow": False}},
    }
    NDNetworkOrchestrator._remove_mcfg_parent_non_echoed_fields(explicit, {"x_connect": False, "netflow_enable": False})
    assert explicit == {"l2_data": {"xConnect": False}, "l3_data": {"fabricData": {"netflow": False}}}


def test_network_attachment_payload_helpers_keep_omission_and_explicit_mapping():
    manager = NetworkAttachmentManager(_NetworkAttachmentCoordinator())
    assert manager._attachment_interfaces({}) is None
    assert manager._attachment_interfaces({"interfaces": []}) == []
    assert manager._attachment_interfaces(
        {"interfaces": [{"interface_range": "Ethernet1/1", "mode": "access", "mapping_type": "single", "customer_vlan": 10}]}
    ) == [{"mode": "access", "interfaceRange": "Ethernet1/1", "mapping": {"mappingType": "single", "customerVlan": 10}}]
    assert manager.attachment_instance_values({}) == {}
    assert manager._interfaces_for_controller(None, "4.3.1") is None
    assert manager._interfaces_for_controller([None, {"mode": "pvlan_host"}], "4.3.1") == [None, {"mode": "pvlanHost"}]
    assert manager._payloads_for_controller([{"networkName": "N"}], "4.3.1") == [{"networkName": "N"}]


@pytest.mark.parametrize("wait_kind", ["attachments", "networks"])
def test_network_delete_wait_times_out_with_controller_blockers(wait_kind):
    coordinator = _NetworkAttachmentCoordinator()
    coordinator.module = _Module({"state": "deleted", "config": []})
    coordinator._query_current_networks_by_names = lambda *_args: [{"networkName": "N", "networkStatus": "pending"}]
    manager = NetworkAttachmentManager(coordinator)
    manager.undeploy_retry_attempts = 0
    manager.delete_wait_deadline = lambda _count: (0, 0)
    manager._current_attachment_details_for_wait = lambda *_args: [
        {"networkName": "OTHER", "switchId": "S2", "attach": True, "status": "pending"},
        {"networkName": "N", "switchId": "S1", "attach": True, "status": "pending"},
    ]
    strategy = _orchestrator().strategy
    assert manager._delete_wait_timeout(1) > 0
    if wait_kind == "networks":
        manager.wait_for_networks_delete_ready({}, strategy, [])
        with pytest.raises(AssertionError, match="Timed out waiting for networks"):
            manager.wait_for_networks_delete_ready({}, strategy, ["N"])
    else:
        manager.wait_for_attachments_delete_ready({}, strategy, [])
        with pytest.raises(AssertionError, match="Timed out waiting for network attachments"):
            manager.wait_for_attachments_delete_ready({}, strategy, ["N"])


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
def test_network_state_machine_setup_restores_params_after_validation(state, monkeypatch):
    from types import SimpleNamespace

    module = _Module({"config": [{"network_name": "ORIGINAL"}], "state": "original"})
    coordinator = NetworkWorkflowCoordinator(module, _orchestrator().strategy)
    snapshot = SimpleNamespace(existing={}, proposed={}, state=state)
    calls = []
    monkeypatch.setattr(coordinator_mod, "NDStateMachine", lambda **_kwargs: snapshot)
    monkeypatch.setattr(coordinator, "_resolve_proposed_networks", lambda *_args: calls.append("resolve"))
    sm, original_config, original_state = coordinator._new_state_machine(
        {"state": state, "config": [{"network_name": "N", "layer": "layer2"}]}, coordinator.strategy
    )
    assert sm is snapshot
    assert calls == ["resolve"]
    coordinator._restore_state_machine_params(original_config, original_state)
    assert module.params == {"config": [{"network_name": "ORIGINAL"}], "state": "original"}


def test_network_state_machine_setup_restores_params_on_constructor_failure(monkeypatch):
    module = _Module({"config": [{"network_name": "ORIGINAL"}], "state": "original"})
    coordinator = NetworkWorkflowCoordinator(module, _orchestrator().strategy)

    def fail(**_kwargs):
        raise RuntimeError("query unavailable")

    monkeypatch.setattr(coordinator_mod, "NDStateMachine", fail)
    with pytest.raises(RuntimeError, match="query unavailable"):
        coordinator._new_state_machine({"state": "merged", "config": [{"network_name": "N", "layer": "layer2"}]})
    assert module.params == {"config": [{"network_name": "ORIGINAL"}], "state": "original"}


def test_network_merged_layer_resolution_updates_cached_proposal():
    from types import SimpleNamespace

    strategy = _orchestrator().strategy
    coordinator = NetworkWorkflowCoordinator(_Module({"state": "merged", "config": []}), strategy)
    proposed = SimpleNamespace(layer=None)
    sm = SimpleNamespace(
        existing={"N": SimpleNamespace(layer="layer2", vrf_name="NA")},
        proposed={"N": proposed},
    )
    coordinator._resolve_proposed_networks(sm, [{"network_name": "N", "vlan_name": "NEW"}], "merged", strategy)
    assert proposed.layer == "layer2"


def test_network_merged_layer_resolution_leaves_unresolved_proposal_unchanged():
    from types import SimpleNamespace

    coordinator = NetworkWorkflowCoordinator(_Module({"state": "merged", "config": []}), _orchestrator().strategy)
    proposed = SimpleNamespace(layer=None)
    snapshot = SimpleNamespace(existing={}, proposed={"N": proposed})
    model_cls = SimpleNamespace(from_config=lambda *_args, **_kwargs: SimpleNamespace(layer=None))
    strategy = SimpleNamespace(config_model_cls=model_cls, fabric_data={"managementType": "vxlanIbgp"}, is_child=False)
    coordinator._resolve_proposed_networks(snapshot, [{"network_name": "N", "vlan_id": 100}], "merged", strategy)
    assert proposed.layer is None


def test_network_child_task_retains_explicit_child_layer():
    coordinator = NetworkWorkflowCoordinator(_Module({"state": "merged", "config": []}), _ParentStrategy())
    existing = {"child1": {"module_args": {"config": []}, "network_list": []}}
    tasks = coordinator._accumulate_child_task(
        {"network_name": "N", "layer": "layer3"},
        {"fabric_name": "child1", "layer": "layer2"},
        existing,
        {},
        "merged",
    )
    assert tasks["child1"]["module_args"]["config"] == [{"network_name": "N", "layer": "layer2"}]


@pytest.mark.parametrize("wait_kind", ["attachments", "networks"])
def test_network_delete_wait_observes_pending_then_ready(wait_kind):
    coordinator = _NetworkAttachmentCoordinator()
    coordinator.module = _Module({"state": "deleted", "config": []})
    coordinator._query_current_networks_by_names = lambda *_args: [{"networkName": "N", "networkStatus": "notApplicable"}]
    manager = NetworkAttachmentManager(coordinator)
    manager.wait_delay = 0
    manager.undeploy_retry_attempts = 1 if wait_kind == "networks" else 0
    polls = []
    manager._current_attachment_details_for_wait = lambda *_args: polls.append("poll") or (
        [{"networkName": "N", "attach": True, "status": "pending"}] if len(polls) == 1 else []
    )
    manager.build_delete_deploy_payloads = lambda *_args, **_kwargs: []
    with patch("ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_attachment_manager.time.sleep") as sleep:
        if wait_kind == "networks":
            manager.wait_for_networks_delete_ready({}, _orchestrator().strategy, ["N"], float("inf"), 1)
        else:
            manager.wait_for_attachments_delete_ready({}, _orchestrator().strategy, ["N"], float("inf"), 1)
    assert polls == ["poll", "poll"]
    sleep.assert_called_once_with(0)


def test_network_orchestrator_payload_branches_keep_supported_fields():
    from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_data_models import VxlanIbgpNetworkModel

    orchestrator = _orchestrator()
    assert orchestrator._network_layer({"network_name": "N"}) == "layer3"
    assert orchestrator._l3_data({"mtu": 9000, "layer": "layer3"}, "routed")["mtu"] == 9000
    l2 = VxlanIbgpNetworkModel(networkName="N", networkMode="layer2", l3Data={"mtu": 9000})
    assert "l3Data" not in orchestrator._create_or_update_payload(l2)

    mcfg = _mcfg_parent_orchestrator()
    secondary = VxlanIbgpNetworkModel(networkName="N", networkMode="layer2", vlanNetworkType="privateSecondaryCommunity", l3Data={"mtu": 9000})
    assert "l3Data" not in mcfg._mcfg_parent_network_payload(secondary)
    normalized = mcfg._normalize_query_network_item(
        {"networkName": "N", "l3Data": {"secondaryGatewayIpv4Collection": [], "secondaryGatewayIpv6Collection": [], "mtu": 9000}}
    )
    assert normalized["l3Data"] == {"mtu": 9000}


def test_private_secondary_payload_omits_unrequested_optional_fields():
    orchestrator = _orchestrator()
    data = orchestrator._private_secondary_payload_model_data(
        {"network_name": "N", "network_id": 30000, "vlan_id": 100},
        "FAB",
        "privateSecondaryCommunity",
        {"network_name": "N", "network_id": 30000},
    )
    assert data["network_template_config"]["type"] == "Community"
    assert "vlanName" not in data["network_template_config"]
    assert "mcastGroup" not in data["network_template_config"]
    assert "primary_network_id" not in data
    assert "l2_data" not in data


def test_mcfg_parent_preserves_explicit_nonempty_l2_fabric_data():
    data = {"l2_data": {"fabricData": {"multicastGroup": "239.1.1.1"}}}
    NDNetworkOrchestrator._remove_mcfg_parent_non_echoed_fields(data, {})
    assert data == {"l2_data": {"fabricData": {"multicastGroup": "239.1.1.1"}}}


def test_network_single_name_query_accepts_endpoint_without_filter_parameters():
    from types import SimpleNamespace

    orchestrator = _orchestrator()
    object.__setattr__(orchestrator, "_make_endpoint", lambda _cls: SimpleNamespace(path="/networks", verb=HttpVerbEnum.GET))
    object.__setattr__(orchestrator, "_request", lambda **_kwargs: {"networks": [{"networkName": "N"}]})
    assert orchestrator.query_by_names(["N"]) == [{"networkName": "N", "fabricName": "fab1"}]
