# -*- coding: utf-8 -*-

"""Unit tests for network config and payload orchestration."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import (
    NetworkConfigModel,
    NetworkParentConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import (
    network_parent_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_attachment_manager import (
    NetworkAttachmentManager,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.networks import (
    NDNetworkOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_workflow_coordinator import (
    NetworkWorkflowCoordinator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import (
    StandaloneNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


def _orchestrator():
    strategy = StandaloneNetworkStrategy(
        fabric_name="fab1",
        fabric_data={"managementType": "vxlanIbgp"},
    )
    return NDNetworkOrchestrator(
        rest_send=RestSend({"state": "merged", "config": [], "check_mode": False}),
        strategy=strategy,
    )


def test_network_config_model_normalizes_attachment_ports():
    model = NetworkConfigModel.from_config(
        {
            "network_name": "BLUE_NET",
            "is_l2only": True,
            "vlan_id": 2301,
            "attach": [
                {
                    "ip_address": "10.1.1.11",
                    "ports": "Ethernet1/1",
                }
            ],
        }
    )

    assert model.to_config()["attach"][0]["ports"] == ["Ethernet1/1"]


def test_network_parent_argument_spec_includes_child_config():
    spec = network_parent_argument_spec()

    assert "child_fabric_config" in spec
    assert spec["attach"]["options"]["interfaces"]["options"]["mode"]["choices"]
    assert spec["attach"]["options"]["deploy"]["default"] is True
    assert "tor_ports" in spec["attach"]["options"]
    assert "attachment_options" in spec["attach"]["options"]
    assert "instance_values" not in spec["attach"]["options"]
    assert "net_name" in spec
    assert "net_id" in spec
    assert "gw_ip_subnet" in spec
    assert spec["deploy_type"]["choices"] == ["switch", "network", "resource"]


def test_user_defined_template_fields_require_user_defined_type():
    with pytest.raises(ValueError, match="network template fields require"):
        NetworkConfigModel.from_config(
            {
                "network_name": "BAD_TEMPLATE",
                "network_type": "vxlanIbgp",
                "network_template_name": "Custom_Network",
            }
        )


def test_parent_config_accepts_child_fabric_overrides():
    model = NetworkParentConfigModel.from_config(
        {
            "network_name": "BLUE_NET",
            "is_l2only": True,
            "child_fabric_config": [
                {
                    "fabric": "child1",
                    "vlan_id": 2301,
                    "gateway_ipv4_address": "192.0.2.1/24",
                }
            ],
        }
    )

    assert model.to_config()["child_fabric_config"][0]["fabric"] == "child1"


def test_argument_spec_uses_manage_json_defaults():
    spec = network_parent_argument_spec()

    assert spec["mtu"]["default"] == 9216
    assert spec["mtu_l3intf"]["default"] == 9216
    assert "default" not in spec["trm_enable"]
    assert "default" not in spec["ipv6_trm"]
    assert spec["enable_ir"]["default"] is False
    assert spec["dhcp_servers"]["options"]["server_address"]["required"] is True


def test_legacy_network_names_are_normalized():
    model = NetworkConfigModel.from_config(
        {
            "net_name": "LEGACY_NET",
            "net_id": 50001,
            "vrf_name": "Tenant_A",
            "vlan_id": 2301,
            "gw_ip_subnet": "192.0.2.1/24",
            "gw_ipv6_subnet": "2001:db8::1/64",
            "secondary_ip_gw1": "192.0.2.2/24",
            "int_desc": "Legacy SVI",
            "mtu_l3intf": 9216,
            "arp_suppress": True,
            "dhcp_srvr1_ip": "10.1.1.10",
            "dhcp_srvr1_vrf": "management",
            "dhcp_loopback_id": 101,
            "l3gw_on_border": True,
            "route_target_both": True,
        }
    )
    config = model.to_config()

    assert config["network_name"] == "LEGACY_NET"
    assert config["network_id"] == 50001
    assert config["gateway_ipv4_address"] == "192.0.2.1/24"
    assert config["gateway_ipv6_address"] == "2001:db8::1/64"
    assert config["secondary_gateway_ipv4_collection"] == ["192.0.2.2/24"]
    assert config["vlan_intf_desc"] == "Legacy SVI"
    assert config["mtu"] == 9216
    assert config["arp_suppression"] is True
    assert config["dhcp_servers"] == [{"server_address": "10.1.1.10", "server_vrf": "management"}]
    assert config["loopback_id"] == 101
    assert config["gateway_on_border"] is True
    assert config["rt_auto"] is True


def test_legacy_attachment_shape_accepts_ports_and_deploy():
    model = NetworkConfigModel.from_config(
        {
            "net_name": "LEGACY_ATTACH",
            "is_l2only": True,
            "attach": [
                {
                    "ip_address": "10.1.1.11",
                    "ports": ["Ethernet1/1"],
                    "deploy": False,
                }
            ],
        }
    )
    attach = model.to_config()["attach"][0]

    assert attach["deploy"] is False
    assert attach["ports"] == ["Ethernet1/1"]


def test_attachment_options_replace_instance_values():
    model = NetworkConfigModel.from_config(
        {
            "net_name": "ATTACH_OPTIONS",
            "is_l2only": True,
            "attach": [
                {
                    "ip_address": "10.1.1.11",
                    "ports": ["Ethernet1/1"],
                    "attachment_options": {
                        "sviEnabled": True,
                        "dpuSecure": False,
                    },
                }
            ],
        }
    )
    config = model.to_config()

    assert config["attach"][0]["attachment_options"] == {"sviEnabled": True, "dpuSecure": False}

    orchestrator = _orchestrator()
    manager = NetworkAttachmentManager(coordinator=None)
    module_args = {"config": [config]}
    manager.resolve_switch_ids = lambda *_args: {"10.1.1.11": "FDO123"}
    desired = manager.desired_attachment_map(module_args, orchestrator.strategy)

    assert desired[("ATTACH_OPTIONS", "FDO123")]["instanceValues"] == {
        "sviEnabled": True,
        "dpuSecure": False,
    }


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


def test_tor_ports_are_rejected_because_network_attachment_api_has_no_tor_field():
    with pytest.raises(ValueError, match="tor_ports is not supported"):
        NetworkConfigModel.from_config(
            {
                "net_name": "LEGACY_ATTACH",
                "is_l2only": True,
                "attach": [
                    {
                        "ip_address": "10.1.1.11",
                        "ports": ["Ethernet1/1"],
                        "tor_ports": [
                            {
                                "ip_address": "10.1.1.12",
                                "ports": ["Ethernet1/2"],
                            }
                        ],
                    }
                ],
            }
        )


def test_module_level_query_and_resource_deploy_type_are_normalized():
    module_args = {
        "state": "query",
        "deploy_type": "resource",
        "config": [{"net_name": "LEGACY_NET", "is_l2only": True}],
    }

    NetworkWorkflowCoordinator._normalize_module_args(module_args)

    assert module_args["state"] == "gathered"
    assert module_args["config"][0]["deploy_type"] == "network"


def test_transform_l2_network_payload_uses_manage_schema_shape():
    payload = _orchestrator().prepare_config_data(
        [
            {
                "network_name": "BLUE_NET",
                "is_l2only": True,
                "vlan_id": 2301,
                "vlan_name": "BLUE_VLAN",
                "rt_auto": True,
                "enable_ir": False,
                "multicast_group_address": "239.1.1.2",
            }
        ]
    )[0]

    assert payload["network_name"] == "BLUE_NET"
    assert payload["network_type"] == "vxlanIbgp"
    assert payload["layer"] == "layer2"
    assert payload["vrf_name"] == "NA"
    assert payload["l2_data"]["vlanName"] == "BLUE_VLAN"
    assert payload["l2_data"]["rtAuto"] is True
    assert payload["l2_data"]["fabricData"]["enableIr"] is False
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


def test_network_response_normalizes_network_mode_for_l2_idempotency():
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
            },
        }
    )
    config = model.to_config()

    assert config["layer"] == "layer2"
    assert config["l2_data"]["rt_auto"] is True


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
            }
        ]
    )[0]

    assert payload["layer"] == "layer3"
    assert payload["vrf_name"] == "Tenant_A"
    assert payload["l3_data"]["gatewayIpv4Address"] == "192.0.2.1/24"
    assert payload["l3_data"]["fabricData"]["ipv4Trm"] is True
    assert payload["l3_data"]["fabricData"]["netflow"] is True


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
