# -*- coding: utf-8 -*-

"""Unit tests for network config and payload orchestration."""

from __future__ import annotations

import pytest

from unittest.mock import patch

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import (
    NetworkConfigModel,
    NetworkParentConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.enums import (
    ConfigurationStatus,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import (
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
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import (
    StandaloneNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.child_network import (
    ChildNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_network import (
    MulticlusterParentNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


class _Module:
    def __init__(self, params):
        self.params = params
        self.check_mode = False
        self._verbosity = 3

    def fail_json(self, **kwargs):
        raise AssertionError(kwargs)


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

    def build_child_task_args(self, child_fabric_name, network_configs, state):
        return {
            "fabric_name": child_fabric_name,
            "state": state,
            "config": network_configs,
        }


def _orchestrator():
    strategy = StandaloneNetworkStrategy(
        fabric_name="fab1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    return NDNetworkOrchestrator(
        rest_send=RestSend({"state": "merged", "config": [], "check_mode": False}),
        strategy=strategy,
    )


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


def test_network_config_model_requires_attachment_interfaces():
    with pytest.raises(ValueError, match="interfaces"):
        NetworkConfigModel.from_config(
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


def test_network_parent_argument_spec_includes_child_config():
    spec = network_parent_argument_spec()
    child_spec = spec["child_fabric_config"]["options"]

    assert "child_fabric_config" in spec
    assert spec["attach"]["options"]["interfaces"]["options"]["mode"]["choices"]
    assert spec["attach"]["options"]["interfaces"]["options"]["mode"]["required"] is True
    assert spec["attach"]["options"]["interfaces"]["options"]["interface_range"]["required"] is True
    assert spec["attach"]["options"]["interfaces"]["required"] is True
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
    assert "network_id" not in child_spec
    assert "vlan_id" not in child_spec
    assert "vlan_name" not in child_spec
    assert "vrf_name" not in child_spec
    assert "gateway_ipv4_address" not in child_spec
    assert "routing_tag" not in child_spec
    assert "mtu" not in child_spec
    assert "attach" not in child_spec
    assert "enable_ir" not in child_spec
    assert "l2_fabric_data" not in child_spec
    assert "netflow_enable" in child_spec
    assert "gateway_on_border" in child_spec


def test_user_defined_template_fields_infer_user_defined_type():
    model = NetworkConfigModel.from_config(
        {
            "network_name": "CUSTOM_TEMPLATE",
            "network_template_name": "Custom_Network",
        }
    )

    assert model.network_type == "userDefined"


def test_user_defined_template_fields_reject_explicit_non_user_defined_type():
    with pytest.raises(ValueError, match="network template fields require"):
        NetworkConfigModel.from_config(
            {
                "network_name": "BAD_TEMPLATE",
                "network_type": "vxlanIbgp",
                "network_template_name": "Custom_Network",
            }
        )


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
                    "gateway_on_border": True,
                }
            ],
        }
    )

    assert model.to_config()["child_fabric_config"][0]["fabric_name"] == "child1"
    assert model.to_config()["child_fabric_config"][0]["multicast_group_address"] == "239.1.1.53"
    assert model.to_config()["child_fabric_config"][0]["gateway_on_border"] is True


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


def test_child_network_config_without_fabric_options_does_not_require_child_task():
    assert NetworkWorkflowCoordinator._has_child_network_options({"fabric_name": "child1"}) is False
    assert NetworkWorkflowCoordinator._has_child_network_options({"fabric_name": "child1", "multicast_group_address": "239.1.1.53"}) is True


def test_network_workflow_coordinator_parent_deploy_deferred_after_child_tasks():
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

    def deploy_parent(_args, _strategy, payload):
        call_order.append("deploy")
        assert payload == {
            "networkNames": ["ansible-msd-net"],
            "switchIds": ["SERIAL1"],
        }
        return {}

    object.__setattr__(coordinator, "_run_state_machine_with_attachments", run_parent)
    object.__setattr__(coordinator, "_run_child_task", run_child)
    object.__setattr__(coordinator, "_deploy_network_attachments", deploy_parent)

    result = coordinator._handle_parent_workflow(dict(module_args), "multisite_parent")

    assert call_order == ["parent", "child", "deploy"]
    assert result["changed"] is True
    assert result["fabric_type"] == "multisite_parent"


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
                "ds_vni": 901030,
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
    assert payload["l2Data"]["fabricData"] == {
        "multicastGroup": "239.1.1.53",
        "dsVni": 901030,
    }
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
    assert payload["l3Data"]["fabricData"]["gatewayOnBorder"] is False
    assert payload["l3Data"]["fabricData"]["ipv4Trm"] is False
    assert payload["l3Data"]["fabricData"]["ipv6Trm"] is False
    assert payload["l3Data"]["fabricData"]["netflow"] is False


def test_attachment_only_network_config_does_not_generate_definition_defaults():
    orchestrator = _orchestrator()

    transformed = orchestrator.prepare_config_data(
        [
            {
                "network_name": "BLUE_NET",
                "netflow_enable": False,
                "arp_suppression": False,
                "mtu": 9216,
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
        [
            {
                "network_name": "BLUE_NET",
                "netflow_enable": False,
                "arp_suppression": False,
                "mtu": 9216,
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
        ],
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


def test_argument_spec_uses_manage_json_defaults():
    spec = network_parent_argument_spec()

    assert spec["mtu"]["default"] == 9216
    assert "mtu_l3intf" not in spec
    assert "arp_suppress" not in spec
    assert "default" not in spec["trm_enable"]
    assert "default" not in spec["ipv6_trm"]
    assert "enable_ir" not in spec
    assert "rt_auto" not in spec
    assert "route_target_both" not in spec
    assert spec["dhcp_servers"]["options"]["server_address"]["required"] is True


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
        {"networkName": "BLUE_NET"},
        {"networkName": "GREEN_NET"},
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

    assert orchestrator.query_all() == [{"networkName": network_name}]
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
        {"networkName": "BLUE_NET"},
        {"networkName": "GREEN_NET"},
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
        {"networkName": "BLUE_NET"},
        {"networkName": "GREEN_NET"},
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

    assert orchestrator.query_all() == [{"networkName": "NET_0"}]
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


def test_attachment_shape_rejects_ports_without_interfaces():
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

    with pytest.raises(ValueError, match="interfaces"):
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
    assert payload["l2Data"]["fabricData"] == {}
    assert payload["l3Data"] == {
        "gatewayIpv4Address": "",
        "gatewayIpv6Address": "",
        "secondaryGatewayIpv6Collection": [],
        "vlanInterfaceDescription": "",
        "mtu": None,
        "secondaryGatewayIpv4Collection": None,
        "routingTag": 12345,
    }


def test_mcfg_parent_network_create_keeps_onemanage_netflow_monitor_fields():
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
                    "network_id": 901031,
                    "vlan_id": 3131,
                    "vrf_name": "VRF_GREEN",
                    "gateway_ipv4_address": "192.0.2.1/24",
                    "netflow_enable": True,
                    "l2_netflow_monitor": "L2_MON",
                    "l3_netflow_monitor": "L3_MON",
                    "netflow_sampler": "NF_SAMPLER",
                }
            ]
        )[0]
    )

    orchestrator.create_bulk([model])

    payload = requests[0]["data"]["networks"][0]
    assert requests[0]["path"] == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networks"
    assert payload["networkMode"] == "layer3"
    assert payload["l3Data"]["fabricData"]["netflow"] is True
    assert payload["l3Data"]["fabricData"]["l2NetflowMonitor"] == "L2_MON"
    assert payload["l3Data"]["fabricData"]["l3NetflowMonitor"] == "L3_MON"
    assert payload["l3Data"]["fabricData"]["netflowSampler"] == "NF_SAMPLER"


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
    assert payload["l2Data"] == {"vlanName": "", "fabricData": {}}
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

    assert len(coordinator.orchestrator.requests) == 2
    assert coordinator.orchestrator.requests[0]["path"] == (
        "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networkAttachments/validateInterfaces?strictModeValidation=false"
    )
    assert coordinator.orchestrator.requests[0]["data"] == {
        "attachments": [{"networkName": "BLUE_NET", "switchId": "SERIAL1", "vlanId": -1, "interfaces": [], "attach": True}]
    }
    assert coordinator.orchestrator.requests[1]["path"] == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networkAttachments"
    assert coordinator.orchestrator.requests[1]["data"] == {
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


def test_mcfg_parent_switch_scoped_deploy_uses_onemanage_switch_actions():
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

    strategy = _mcfg_parent_orchestrator().strategy
    coordinator = Coordinator(strategy)
    manager = NetworkAttachmentManager(coordinator)

    manager.deploy_network_attachments(
        {"config": []},
        strategy,
        {"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1", "SERIAL2"]},
    )

    assert coordinator.requests == [
        {
            "path": "/api/v1/oneManage/manage/fabrics/MCFG_FAB/switchActions/deploy?forceShowRun=false",
            "verb": HttpVerbEnum.POST,
            "data": {"switchIds": ["SERIAL1", "SERIAL2"]},
            "operation_type": OperationType.UPDATE,
        }
    ]


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
            '"l3NetflowMonitor":"L3_MON","netflowSampler":"NF_SAMPLER"}'
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
    assert "fabricData" not in normalized["l2Data"]
    assert normalized["l3Data"]["fabricData"]["netflow"] is True
    assert normalized["l3Data"]["fabricData"]["l2NetflowMonitor"] == "L2_MON"
    assert normalized["l3Data"]["fabricData"]["l3NetflowMonitor"] == "L3_MON"
    assert normalized["l3Data"]["fabricData"]["netflowSampler"] == "NF_SAMPLER"


def test_mcfg_parent_delete_does_not_seed_empty_network_level_deploy():
    class Strategy:
        is_parent = True
        is_multicluster = True

    class Coordinator:
        deploy_maps = None

        def _configured_network_names(self, _config):
            return ["BLUE_NET"]

        def _build_delete_deploy_payloads(self, _config, *target_maps):
            self.deploy_maps = target_maps
            return []

        def _wait_for_network_attachments_delete_ready(self, *_args):
            return None

        def _wait_for_networks_delete_ready(self, *_args):
            return None

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

        def _build_delete_deploy_payloads(self, _config, *target_maps):
            assert target_maps == ({"BLUE_NET": {"SERIAL1"}},)
            return [{"networkNames": ["BLUE_NET"]}]

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
            "check_mode_deploy_payloads": [{"networkNames": ["BLUE_NET"]}],
        },
    ]


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
                "attach": True,
            }
        ]
    }


def test_network_merged_runs_post_attach_and_deploy_for_desired_attachment():
    class Module:
        check_mode = False

    class Strategy:
        is_child = False
        is_parent = False

    class Coordinator:
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

        def _apply_attachment_phase(self, module_args, strategy, phase, desired=None, current_network_names=None, current=None):
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

    class Coordinator:
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

        def _apply_attachment_phase(self, module_args, strategy, phase, desired=None, current_network_names=None, current=None):
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

    assert payloads == [{"networkNames": ["BLUE_NET"], "switchIds": ["FDO123"]}]


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

    assert payloads == [{"networkNames": ["BLUE_NET"]}]


def test_pending_network_deploy_payload_covers_deploy_false_then_deploy_true_attach():
    class Coordinator:
        pass

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.current_attachment_details_ignore_missing = lambda *_args: [
        {
            "networkName": "BLUE_NET",
            "switchId": "FDO123",
            "attach": True,
            "status": "pending",
        }
    ]

    payloads = manager.build_pending_network_deploy_payloads(
        {"after": [{"network_name": "BLUE_NET", "network_status": "pending"}]},
        [{"network_name": "BLUE_NET", "deploy": True}],
        {"config": []},
        _orchestrator().strategy,
    )

    assert payloads == [{"networkNames": ["BLUE_NET"], "switchIds": ["FDO123"]}]


def test_pending_network_deploy_payload_falls_back_to_network_scope_without_attachments():
    class Coordinator:
        pass

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.current_attachment_details_ignore_missing = lambda *_args: []

    payloads = manager.build_pending_network_deploy_payloads(
        {"after": [{"network_name": "BLUE_NET", "network_status": "pending"}]},
        [{"network_name": "BLUE_NET", "deploy": True}],
        {"config": []},
        _orchestrator().strategy,
    )

    assert payloads == [{"networkNames": ["BLUE_NET"]}]


def test_pending_network_deploy_payload_accepts_enum_status():
    class Coordinator:
        pass

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.current_attachment_details_ignore_missing = lambda *_args: []

    payloads = manager.build_pending_network_deploy_payloads(
        {"after": [{"network_name": "BLUE_NET", "network_status": ConfigurationStatus.PENDING}]},
        [{"network_name": "BLUE_NET", "deploy": True}],
        {"config": []},
        _orchestrator().strategy,
    )

    assert payloads == [{"networkNames": ["BLUE_NET"]}]


def test_pending_network_deploy_payload_covers_deploy_false_then_deploy_true_detach():
    class Coordinator:
        pass

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.current_attachment_details_ignore_missing = lambda *_args: [
        {
            "networkName": "BLUE_NET",
            "switchId": "FDO123",
            "attach": False,
            "status": "pending",
        }
    ]

    payloads = manager.build_pending_network_deploy_payloads(
        {"after": [{"network_name": "BLUE_NET", "network_status": "deployed"}]},
        [{"network_name": "BLUE_NET", "deploy": True}],
        {"config": []},
        _orchestrator().strategy,
    )

    assert payloads == [{"networkNames": ["BLUE_NET"], "switchIds": ["FDO123"]}]


def test_pending_network_deploy_payload_accepts_enum_attachment_status():
    class Coordinator:
        pass

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.current_attachment_details_ignore_missing = lambda *_args: [
        {
            "networkName": "BLUE_NET",
            "switchId": "FDO123",
            "attach": False,
            "status": ConfigurationStatus.PENDING,
        }
    ]

    payloads = manager.build_pending_network_deploy_payloads(
        {"after": [{"network_name": "BLUE_NET", "network_status": ConfigurationStatus.DEPLOYED}]},
        [{"network_name": "BLUE_NET", "deploy": True}],
        {"config": []},
        _orchestrator().strategy,
    )

    assert payloads == [{"networkNames": ["BLUE_NET"], "switchIds": ["FDO123"]}]


def test_pending_network_deploy_payload_honors_deploy_false_for_pending_detach():
    class Coordinator:
        pass

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.current_attachment_details_ignore_missing = lambda *_args: [
        {
            "networkName": "BLUE_NET",
            "switchId": "FDO123",
            "attach": False,
            "status": "pending",
        }
    ]

    payloads = manager.build_pending_network_deploy_payloads(
        {"after": [{"network_name": "BLUE_NET", "network_status": "deployed"}]},
        [{"network_name": "BLUE_NET", "deploy": False}],
        {"config": []},
        _orchestrator().strategy,
    )

    assert payloads == []


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

        def _new_network_orchestrator(self, _module_args, _strategy):
            class Orchestrator:
                def query_all(self):
                    return [{"networkName": "BLUE_NET", "networkStatus": "pending"}]

            return Orchestrator(), {}

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.wait_attempts = 1
    manager.wait_delay = 0
    manager.undeploy_retry_attempts = 0

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


def test_pending_attachment_delete_wait_retries_undeploy():
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
    manager.deploy_network_attachments = lambda _module_args, _strategy, payload: deploy_payloads.append(payload)

    with pytest.raises(RuntimeError, match="Timed out waiting for network attachments"):
        manager.wait_for_attachments_delete_ready(
            {"config": [{"network_name": "BLUE_NET"}]},
            _orchestrator().strategy,
        )

    assert deploy_payloads == [{"networkNames": ["BLUE_NET"], "switchIds": ["FDO123"]}]


def test_pending_network_delete_wait_retries_undeploy():
    class Module:
        params = {}

        def fail_json(self, **kwargs):
            raise RuntimeError(kwargs["msg"])

    class Coordinator:
        module = Module()

        def _new_network_orchestrator(self, _module_args, _strategy):
            class Orchestrator:
                def query_all(self):
                    return [{"networkName": "BLUE_NET", "networkStatus": "pending"}]

            return Orchestrator(), {}

    manager = NetworkAttachmentManager(coordinator=Coordinator())
    manager.wait_attempts = 1
    manager.wait_delay = 0
    manager.undeploy_retry_attempts = 1
    deploy_payloads = []
    manager.deploy_network_attachments = lambda _module_args, _strategy, payload: deploy_payloads.append(payload)

    with pytest.raises(RuntimeError, match="Timed out waiting for networks"):
        manager.wait_for_networks_delete_ready(
            {"config": [{"network_name": "BLUE_NET"}]},
            _orchestrator().strategy,
        )

    assert deploy_payloads == [{"networkNames": ["BLUE_NET"]}]


def test_network_response_omits_unsupported_l2_fields_for_idempotency():
    model = NDNetworkOrchestrator.model_class.from_response(
        {
            "fabricName": "fab1",
            "networkName": "BLUE_NET",
            "vrfName": "NA",
            "networkType": "vxlanIbgp",
            "networkMode": "layer2",
            "l2Data": {
                "disableRtAuto": False,
                "rtAuto": True,
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


def test_transform_l3_network_payload_uses_l3_data_fabric_data():
    payload = _orchestrator().prepare_config_data(
        [
            {
                "network_name": "GREEN_NET",
                "vrf_name": "Tenant_A",
                "network_id": 50001,
                "vlan_id": 3001,
                "gateway_ipv4_address": "192.0.2.1/24",
                "trm_enable": True,
                "netflow_enable": True,
                "l2_netflow_monitor": "L2_MON",
                "l3_netflow_monitor": "L3_MON",
                "netflow_sampler": "NF_SAMPLER",
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
    assert payload["l3_data"]["fabricData"]["netflowSampler"] == "NF_SAMPLER"


def test_transform_l3_network_payload_omits_trm_flags_when_unset():
    payload = _orchestrator().prepare_config_data(
        [
            {
                "network_name": "GREEN_NET",
                "vrf_name": "Tenant_A",
                "gateway_ipv4_address": "192.0.2.1/24",
            }
        ]
    )[0]

    assert payload["l3_data"]["mtu"] == 9216
    assert payload["l3_data"]["fabricData"]["netflow"] is False
    assert "ipv4Trm" not in payload["l3_data"]["fabricData"]
    assert "ipv6Trm" not in payload["l3_data"]["fabricData"]
