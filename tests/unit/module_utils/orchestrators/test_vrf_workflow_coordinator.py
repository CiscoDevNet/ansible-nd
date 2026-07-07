# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for VRF workflow result aggregation.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import (
    VrfWorkflowCoordinator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_attachment_manager import (
    VrfAttachmentManager,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_vrf import (
    MulticlusterParentVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import (
    VrfConfigModel,
    VrfParentConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_argument_specs import (
    vrf_parent_argument_spec,
)


class _Module:
    def __init__(self, params):
        self.params = params
        self.check_mode = False
        self._verbosity = 3

    def fail_json(self, **kwargs):
        raise AssertionError(kwargs)


class _ParentStrategy:
    config_model_cls = VrfParentConfigModel
    fabric_data = {"members": [{"fabricName": "AK-VXLAN"}]}
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
        return ["AK-VXLAN"]

    def build_child_task_args(self, child_fabric_name, vrf_configs, state):
        return {
            "fabric_name": child_fabric_name,
            "state": state,
            "config": vrf_configs,
        }


class _McfgParentStrategy(_ParentStrategy):
    fabric_data = {"members": [{"fabricName": "nacfab", "clusterName": "ND42-REL"}]}
    fabric_name = "MCFG_C"

    @property
    def fabric_type(self):
        return "multicluster_parent"

    @property
    def is_multicluster(self):
        return True


class _StandaloneStrategy:
    config_model_cls = VrfConfigModel
    fabric_type = "standalone"
    fabric_name = "AK-VXLAN"

    @property
    def is_child(self):
        return False

    @property
    def is_parent(self):
        return False

    @property
    def is_multicluster(self):
        return False


class _ChildStrategy:
    config_model_cls = VrfConfigModel
    fabric_type = "multisite_child"
    fabric_name = "AK-VXLAN"

    @property
    def is_child(self):
        return True

    @property
    def is_parent(self):
        return False


class _Results:
    def __init__(self):
        self.finalized = 0

    def build_final_result(self):
        self.finalized += 1
        return {}


class _AttachmentQueryOrchestrator:
    def __init__(self, strategy, responses):
        self.strategy = strategy
        self.responses = responses
        self.requests = []

    def _make_endpoint(self, endpoint_cls):
        endpoint = endpoint_cls()
        endpoint.fabric_name = self.strategy.fabric_name
        return endpoint

    def _request(self, **kwargs):
        self.requests.append(kwargs)
        return self.responses.pop(0)


def test_vrf_attachment_query_chunks_large_vrf_name_sets():
    class Coordinator:
        def __init__(self):
            self.queried_chunks = []

        def _current_attachment_details(self, _module_args, _strategy, vrf_names):
            self.queried_chunks.append(vrf_names)
            return []

    coordinator = Coordinator()
    manager = VrfAttachmentManager(coordinator=coordinator)
    manager.delete_wait_chunk_size = 2

    result = manager.current_attachment_details_ignore_missing(
        {},
        _StandaloneStrategy(),
        [f"vrf-{index}" for index in range(5)],
    )

    assert result == []
    assert coordinator.queried_chunks == [["vrf-0", "vrf-1"], ["vrf-2", "vrf-3"], ["vrf-4"]]


def test_vrf_attachment_query_walks_paginated_results():
    strategy = _StandaloneStrategy()
    responses = [
        {
            "attachments": [{"vrfName": "BLUE", "switchId": "SW1"}],
            "meta": {"counts": {"remaining": 1, "total": 2}},
        },
        {
            "attachments": [{"vrfName": "BLUE", "switchId": "SW2"}],
            "meta": {"counts": {"remaining": 0, "total": 2}},
        },
    ]
    orchestrator = _AttachmentQueryOrchestrator(strategy, responses)
    results = _Results()

    class Coordinator:
        def _new_vrf_orchestrator(self, _module_args, _strategy):
            return orchestrator, results

    manager = VrfAttachmentManager(coordinator=Coordinator())
    manager.attachment_query_page_size = 1

    assert manager.current_attachment_details({}, strategy, ["BLUE"]) == [
        {"vrfName": "BLUE", "switchId": "SW1"},
        {"vrfName": "BLUE", "switchId": "SW2"},
    ]
    assert orchestrator.requests[0]["path"].endswith("/vrfAttachments/query?offset=0&max=1&includeAll=true")
    assert orchestrator.requests[1]["path"].endswith("/vrfAttachments/query?offset=1&max=1&includeAll=true")
    assert orchestrator.requests[0]["data"] == {"vrfNames": ["BLUE"]}
    assert results.finalized == 2


def test_vrf_workflow_coordinator_00001_arg_spec_blocks_invalid_child_suboptions():
    """
    # Summary

    Verify the wired parent config spec keeps child_fabric_config constrained
    to child-supported fields.
    """
    spec = vrf_parent_argument_spec()
    child_spec = spec["child_fabric_config"]["options"]

    assert "vlan_id" not in child_spec
    assert "attach" not in child_spec
    assert "deploy" not in child_spec
    assert "child_fabric_config" not in child_spec
    assert "default" not in spec["child_fabric_config"]


def test_vrf_workflow_coordinator_00002_standalone_rejects_child_fabric_config():
    """
    # Summary

    Verify parent-only child_fabric_config is blocked after fabric resolution
    when the target fabric is standalone.
    """
    module_args = {
        "fabric_name": "AK-VXLAN",
        "state": "merged",
        "config": [
            {
                "vrf_name": "ansible-vrf",
                "child_fabric_config": [{"fabric_name": "child"}],
            }
        ],
    }
    coordinator = VrfWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_StandaloneStrategy(),
    )

    try:
        coordinator._validate_topology_argument_scope(module_args, "standalone")
    except AssertionError as exc:
        assert "child_fabric_config is only valid" in exc.args[0]["msg"]
    else:
        raise AssertionError("standalone child_fabric_config was not rejected")


def test_vrf_workflow_coordinator_00003_child_rejects_direct_attach():
    """
    # Summary

    Verify direct child-fabric tasks reject parent-level attachment input
    before workflow execution.
    """
    module_args = {
        "fabric_name": "AK-VXLAN",
        "state": "gathered",
        "config": [
            {
                "vrf_name": "ansible-vrf",
                "attach": [{"ip_address": "192.0.2.10"}],
            }
        ],
    }
    coordinator = VrfWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_ChildStrategy(),
    )

    try:
        coordinator._validate_topology_argument_scope(module_args, "multisite_child")
    except AssertionError as exc:
        assert "attach is not valid" in exc.args[0]["msg"]
    else:
        raise AssertionError("child attach was not rejected")


def test_vrf_workflow_coordinator_000035_mcfg_parent_scrubs_child_scoped_defaults():
    """
    # Summary

    Verify defaulted parent fabric options are removed from MCFG parent rows
    that are controlled through child_fabric_config.
    """
    parent_vrf = {
        "vrf_name": "ansible-mcfg-vrf",
        "l3vni_wo_vlan": False,
        "adv_host_routes": False,
        "adv_default_routes": True,
        "static_default_route": True,
        "netflow_enable": False,
        "trm_enable": False,
        "max_bgp_paths": 4,
    }

    VrfWorkflowCoordinator._remove_defaulted_mcfg_parent_fabric_options(parent_vrf)

    assert parent_vrf == {
        "vrf_name": "ansible-mcfg-vrf",
        "max_bgp_paths": 4,
    }


def test_vrf_workflow_coordinator_000036_mcfg_parent_keeps_nondefault_fabric_options():
    """
    # Summary

    Verify non-default MCFG parent fabric options survive the default scrub.
    """
    parent_vrf = {
        "vrf_name": "ansible-mcfg-vrf",
        "l3vni_wo_vlan": True,
        "adv_host_routes": True,
        "adv_default_routes": False,
        "static_default_route": False,
        "netflow_enable": True,
    }

    VrfWorkflowCoordinator._remove_defaulted_mcfg_parent_fabric_options(parent_vrf)

    assert parent_vrf == {
        "vrf_name": "ansible-mcfg-vrf",
        "l3vni_wo_vlan": True,
        "adv_host_routes": True,
        "adv_default_routes": False,
        "static_default_route": False,
        "netflow_enable": True,
    }


def test_vrf_workflow_coordinator_000037_mcfg_parent_scrubs_child_owned_fabric_options():
    """
    # Summary

    Verify MCFG parent rows with child_fabric_config leave fabric-instance
    options to the child manage endpoint.
    """
    parent_vrf = {
        "vrf_name": "ansible-mcfg-vrf",
        "vrf_id": 9008037,
        "l3vni_wo_vlan": True,
        "adv_host_routes": True,
        "adv_default_routes": False,
        "static_default_route": False,
        "bgp_password": "abcdef12",
        "bgp_passwd_encrypt": 3,
        "netflow_enable": True,
        "max_bgp_paths": 4,
    }

    VrfWorkflowCoordinator._remove_child_owned_mcfg_parent_fabric_options(parent_vrf)

    assert parent_vrf == {
        "vrf_name": "ansible-mcfg-vrf",
        "vrf_id": 9008037,
        "max_bgp_paths": 4,
    }


def test_vrf_workflow_coordinator_000038_attachment_match_treats_missing_extra_config_as_empty():
    """
    # Summary

    Verify attach idempotence is not broken when ND returns empty extraConfig
    but the playbook omitted freeform_config.
    """
    existing = {
        "vrfName": "ansible-vrf",
        "switchId": "FDO123",
        "attach": True,
        "extraConfig": "",
    }
    desired = {
        "vrfName": "ansible-vrf",
        "switchId": "FDO123",
        "attach": True,
    }

    assert VrfAttachmentManager.attachment_matches(existing, desired) is True


def test_vrf_workflow_coordinator_00004_child_write_ignores_null_parser_defaults():
    """
    # Summary

    Verify parser-added null values for parent-scoped fields do not mask the
    direct-child write rejection message.
    """
    module_args = {
        "fabric_name": "AK-VXLAN",
        "state": "merged",
        "config": [
            {
                "vrf_name": "ansible-vrf",
                "vrf_id": 9008053,
                "child_fabric_config": None,
                "attach": None,
            }
        ],
    }
    coordinator = VrfWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_ChildStrategy(),
    )

    try:
        coordinator.run()
    except AssertionError as exc:
        msg = exc.args[0]["msg"]
        assert "Only state='gathered' is allowed on child fabrics" in msg
        assert "child_fabric_config is only valid" not in msg
    else:
        raise AssertionError("child write was not rejected")


def test_vrf_workflow_coordinator_00005_attach_fields_map_to_api_payload():
    """
    # Summary

    Verify attachment_options DPU fields and attach-level freeform_config are
    mapped to the correct Manage API attachment payload locations.
    """
    module_args = {
        "fabric_name": "AK-VXLAN",
        "state": "merged",
        "config": [
            {
                "vrf_name": "ansible-vrf",
                "attach": [
                    {
                        "ip_address": "192.0.2.10",
                        "freeform_config": "interface loopback10\n description test",
                        "attachment_options": {
                            "dpu_secure": True,
                            "dpu_affinity": "dpu1",
                            "loopback_id": 10,
                            "loopback_ipv4_address": "10.10.10.10",
                            "import_vpn_rt": ["65000:10"],
                        },
                    }
                ],
            }
        ],
    }
    coordinator = VrfWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_StandaloneStrategy(),
    )

    object.__setattr__(coordinator, "_resolve_switch_ids", lambda *_args: {"192.0.2.10": "FDO123"})

    desired = coordinator._desired_attachment_map(module_args, _StandaloneStrategy())
    payload = desired[("ansible-vrf", "FDO123")]

    assert payload["extraConfig"] == "interface loopback10\n description test"
    assert payload["instanceValues"]["dpuSecure"] is True
    assert payload["instanceValues"]["dpuAffinity"] == "dpu1"
    assert payload["instanceValues"]["loopbackId"] == 10
    assert payload["instanceValues"]["loopbackIpv4Address"] == "10.10.10.10"
    assert payload["instanceValues"]["routeTargetImport"] == ["65000:10"]


def test_vrf_workflow_coordinator_00010_parent_child_results_keep_state_machine_shape():
    """
    # Summary

    Verify MSD/MCFG parent aggregation preserves the standalone-style
    state-machine result fields under parent_fabric and child_fabrics.
    """
    coordinator = VrfWorkflowCoordinator.__new__(VrfWorkflowCoordinator)
    parent_result = {
        "changed": False,
        "output_level": "debug",
        "before": [],
        "after": [{"vrf_name": "ansible-msd-vrf"}],
        "diff": [],
        "api_paths": ["/api/v1/manage/fabrics/msd_p/vrfs"],
        "api_verbs": ["GET"],
        "api_payload": [None],
        "api_response": [{"RETURN_CODE": 200}],
        "api_result": [{"success": True}],
        "api_diff": [],
        "api_metadata": [{}],
    }
    child_result = {
        "child_fabric": "AK-VXLAN",
        "fabric_type": "multisite_child",
        "changed": True,
        "output_level": "debug",
        "before": [],
        "after": [{"vrf_name": "ansible-msd-vrf"}],
        "diff": [],
        "api_paths": ["/api/v1/manage/fabrics/AK-VXLAN/vrfs/ansible-msd-vrf"],
        "api_verbs": ["PUT"],
        "api_payload": [{"vrfName": "ansible-msd-vrf"}],
        "api_response": [{"RETURN_CODE": 204}],
        "api_result": [{"success": True, "changed": True}],
        "api_diff": [],
        "api_metadata": [{}],
    }

    result = coordinator._build_structured_result(
        parent_result,
        [child_result],
        "msd_p",
        "multisite_parent",
        "multisite",
    )

    assert result["changed"] is True
    assert result["fabric_type"] == "multisite_parent"
    assert result["workflow"] == "Multisite Parent with Child Fabric Processing"

    parent = result["parent_fabric"]
    assert parent["fabric_name"] == "msd_p"
    assert parent["fabric_type"] == "multisite_parent"
    assert parent["after"] == parent_result["after"]
    assert parent["api_paths"] == parent_result["api_paths"]
    assert parent["api_response"] == parent_result["api_response"]
    assert "child_fabric" not in parent

    child = result["child_fabrics"][0]
    assert child["fabric_name"] == "AK-VXLAN"
    assert child["fabric_type"] == "multisite_child"
    assert child["after"] == child_result["after"]
    assert child["api_paths"] == child_result["api_paths"]
    assert child["api_payload"] == child_result["api_payload"]
    assert "child_fabric" not in child


def test_vrf_workflow_coordinator_00011_child_exception_returns_structured_failure():
    """
    # Summary

    Verify an exception raised while processing a child fabric is converted
    into a child-scoped failed result that parent aggregation can preserve.
    """
    coordinator = VrfWorkflowCoordinator(
        module=_Module({"output_level": "debug"}),
        strategy=_ParentStrategy(),
    )

    def raise_child(*_args, **_kwargs):
        raise RuntimeError("child route failed")

    object.__setattr__(coordinator, "_run_state_machine", raise_child)
    child_result = coordinator._run_child_task(
        {
            "module_args": {"config": [{"vrf_name": "ansible-msd-vrf"}]},
            "strategy": _ChildStrategy(),
        }
    )
    child_result["child_fabric"] = "AK-VXLAN"

    result = coordinator._build_structured_result(
        {"changed": True, "failed": False, "before": [], "after": [], "diff": []},
        [child_result],
        "msd_p",
        "multisite_parent",
        "multisite",
    )

    assert result["changed"] is True
    assert result["failed"] is True
    assert "AK-VXLAN" in result["msg"]
    child = result["child_fabrics"][0]
    assert child["fabric_name"] == "AK-VXLAN"
    assert child["fabric_type"] == "multisite_child"
    assert child["failed"] is True
    assert child["msg"] == "child route failed"
    assert child["exception"] == "RuntimeError"
    assert child["proposed"] == [{"vrf_name": "ansible-msd-vrf"}]
    assert child["workflow_trace"][-1]["event"] == "child_task_error"
    assert child["workflow_trace"][-1]["exception"] == "RuntimeError"


def test_vrf_workflow_coordinator_00020_parent_deploy_deferred_after_child_tasks():
    """
    # Summary

    Verify parent attach/deploy fields stay on the parent task, are stripped
    from child tasks, and the parent deploy runs after child processing.
    """
    module_args = {
        "fabric_name": "msd_p",
        "state": "merged",
        "output_level": "debug",
        "config": [
            {
                "vrf_name": "ansible-msd-vrf",
                "deploy": True,
                "attach": [{"ip_address": "192.168.1.224"}],
                "child_fabric_config": [
                    {
                        "fabric_name": "AK-VXLAN",
                        "adv_default_routes": False,
                    }
                ],
            }
        ],
    }
    coordinator = VrfWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_ParentStrategy(),
    )
    call_order = []

    def run_parent(args, defer_deploy=False):
        call_order.append("parent")
        parent_vrf = args["config"][0]
        assert defer_deploy is True
        assert parent_vrf["attach"] == [{"ip_address": "192.168.1.224"}]
        assert parent_vrf["deploy"] is True
        assert "child_fabric_config" not in parent_vrf
        return {
            "changed": True,
            "output_level": "debug",
            "before": [],
            "after": [],
            "diff": [],
            "_deferred_deploy_payload": {
                "vrfNames": ["ansible-msd-vrf"],
                "switchIds": ["SERIAL1"],
            },
        }

    def run_child(child_task):
        call_order.append("child")
        child_vrf = child_task["module_args"]["config"][0]
        assert "attach" not in child_vrf
        assert "deploy" not in child_vrf
        assert child_vrf["vrf_name"] == "ansible-msd-vrf"
        assert child_vrf["adv_default_routes"] is False
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
            "vrfNames": ["ansible-msd-vrf"],
            "switchIds": ["SERIAL1"],
        }
        return {}

    object.__setattr__(coordinator, "_run_state_machine_with_attachments", run_parent)
    object.__setattr__(coordinator, "_run_child_task", run_child)
    object.__setattr__(coordinator, "_deploy_vrf_attachments", deploy_parent)

    result = coordinator._handle_parent_workflow(dict(module_args), "multisite_parent")

    assert call_order == ["parent", "child", "deploy"]
    assert result["changed"] is True
    assert result["fabric_type"] == "multisite_parent"
    assert result["parent_fabric"]["fabric_type"] == "multisite_parent"
    assert result["child_fabrics"][0]["fabric_type"] == "multisite_child"


def test_vrf_workflow_coordinator_00030_build_pending_vrf_deploy_payload():
    """
    # Summary

    Verify deploy=true can deploy an already-pending VRF even when no fresh
    attachment payload was generated during the current task.
    """
    coordinator = VrfWorkflowCoordinator.__new__(VrfWorkflowCoordinator)
    coordinator._current_attachment_details = lambda *_args, **_kwargs: [
        {
            "vrfName": "ansible-msd-vrf",
            "switchId": "SERIAL1",
            "attach": False,
        }
    ]
    payloads = coordinator._build_pending_vrf_deploy_payloads(
        {
            "after": [
                {
                    "vrf_name": "ansible-msd-vrf",
                    "vrf_status": "pending",
                },
                {
                    "vrf_name": "ansible-no-deploy",
                    "vrf_status": "pending",
                },
                {
                    "vrf_name": "ansible-deployed",
                    "vrf_status": "deployed",
                },
            ]
        },
        [
            {"vrf_name": "ansible-msd-vrf", "deploy": True},
            {"vrf_name": "ansible-no-deploy", "deploy": False},
            {"vrf_name": "ansible-deployed", "deploy": True},
        ],
        {"config": []},
        _ParentStrategy(),
    )

    assert payloads == [
        {
            "switchIds": ["SERIAL1"],
            "vrfNames": ["ansible-msd-vrf"],
        }
    ]


def test_vrf_workflow_coordinator_00031_build_pending_vrf_deploy_payload_for_pending_detach():
    """
    # Summary

    Verify deploy=true can deploy a pending detached attachment left behind by
    an earlier deploy=false attachment removal.
    """
    coordinator = VrfWorkflowCoordinator.__new__(VrfWorkflowCoordinator)
    coordinator._current_attachment_details = lambda *_args, **_kwargs: [
        {
            "vrfName": "ansible-msd-vrf",
            "switchId": "SERIAL1",
            "attach": False,
            "deploymentStatus": "pending",
        }
    ]

    payloads = coordinator._build_pending_vrf_deploy_payloads(
        {"after": [{"vrf_name": "ansible-msd-vrf", "vrf_status": "deployed"}]},
        [{"vrf_name": "ansible-msd-vrf", "deploy": True}],
        {"config": []},
        _ParentStrategy(),
    )

    assert payloads == [
        {
            "switchIds": ["SERIAL1"],
            "vrfNames": ["ansible-msd-vrf"],
        }
    ]


def test_vrf_workflow_coordinator_00031a_build_pending_vrf_deploy_payload_for_pending_attach():
    """
    # Summary

    Verify deploy=true can recover an already-staged attached row that is still
    pending, even when the current task does not need another attach POST.
    """
    coordinator = VrfWorkflowCoordinator.__new__(VrfWorkflowCoordinator)
    coordinator._current_attachment_details = lambda *_args, **_kwargs: [
        {
            "vrfName": "ansible-msd-vrf",
            "switchId": "SERIAL1",
            "attach": True,
            "status": "pending",
        }
    ]

    payloads = coordinator._build_pending_vrf_deploy_payloads(
        {"after": [{"vrf_name": "ansible-msd-vrf", "vrf_status": "notApplicable"}]},
        [{"vrf_name": "ansible-msd-vrf", "deploy": True}],
        {"config": []},
        _ParentStrategy(),
    )

    assert payloads == [
        {
            "switchIds": ["SERIAL1"],
            "vrfNames": ["ansible-msd-vrf"],
        }
    ]


def test_vrf_workflow_coordinator_00032_pending_detach_deploy_payload_honors_deploy_false():
    """
    # Summary

    Verify deploy=false still defers an already-pending detached attachment.
    """
    coordinator = VrfWorkflowCoordinator.__new__(VrfWorkflowCoordinator)
    coordinator._current_attachment_details = lambda *_args, **_kwargs: [
        {
            "vrfName": "ansible-msd-vrf",
            "switchId": "SERIAL1",
            "attach": False,
            "deploymentStatus": "pending",
        }
    ]

    payloads = coordinator._build_pending_vrf_deploy_payloads(
        {"after": [{"vrf_name": "ansible-msd-vrf", "vrf_status": "deployed"}]},
        [{"vrf_name": "ansible-msd-vrf", "deploy": False}],
        {"config": []},
        _ParentStrategy(),
    )

    assert payloads == []


def test_vrf_workflow_coordinator_00040_build_vrf_level_deploy_payload():
    """
    # Summary

    Verify deploy_type=vrf omits switchIds even when attachment changes
    provide affected switch IDs.
    """
    coordinator = VrfWorkflowCoordinator.__new__(VrfWorkflowCoordinator)
    payloads = coordinator._build_deploy_payloads(
        [
            {"vrf_name": "ansible-switch-scope", "deploy_type": "switch"},
            {"vrf_name": "ansible-vrf-scope", "deploy_type": "vrf"},
        ],
        {
            "ansible-switch-scope": {"SERIAL1"},
            "ansible-vrf-scope": {"SERIAL2"},
        },
    )

    assert payloads == [
        {
            "switchIds": ["SERIAL1"],
            "vrfNames": ["ansible-switch-scope"],
        },
        {
            "vrfNames": ["ansible-vrf-scope"],
        },
    ]


def test_vrf_workflow_coordinator_00045_build_switch_level_deploy_payload_batches_by_switch_set():
    """
    # Summary

    Verify switch-level deploy payloads batch VRFs that share the same switch
    set instead of emitting one deploy request per VRF.
    """
    coordinator = VrfWorkflowCoordinator.__new__(VrfWorkflowCoordinator)
    payloads = coordinator._build_deploy_payloads(
        [
            {"vrf_name": "ansible-vrf-a", "deploy_type": "switch"},
            {"vrf_name": "ansible-vrf-b", "deploy_type": "switch"},
            {"vrf_name": "ansible-vrf-c", "deploy_type": "switch"},
            {"vrf_name": "ansible-vrf-d", "deploy_type": "vrf"},
        ],
        {
            "ansible-vrf-a": {"SERIAL1", "SERIAL2"},
            "ansible-vrf-b": {"SERIAL2", "SERIAL1"},
            "ansible-vrf-c": {"SERIAL3"},
            "ansible-vrf-d": {"SERIAL4"},
        },
    )

    assert payloads == [
        {
            "switchIds": ["SERIAL1", "SERIAL2"],
            "vrfNames": ["ansible-vrf-a", "ansible-vrf-b"],
        },
        {
            "switchIds": ["SERIAL3"],
            "vrfNames": ["ansible-vrf-c"],
        },
        {
            "vrfNames": ["ansible-vrf-d"],
        },
    ]


def test_vrf_workflow_coordinator_00050_deleted_ignores_child_fabric_config():
    """
    # Summary

    Verify state=deleted strips child_fabric_config and does not create or
    execute child fabric tasks.
    """
    module_args = {
        "fabric_name": "msd_p",
        "state": "deleted",
        "output_level": "debug",
        "config": [
            {
                "vrf_name": "ansible-msd-vrf",
                "child_fabric_config": [{"fabric_name": "not-a-member"}],
            }
        ],
    }
    coordinator = VrfWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_ParentStrategy(),
    )
    calls = []

    def run_parent(args, defer_deploy=False):
        calls.append("parent")
        assert defer_deploy is True
        parent_vrf = args["config"][0]
        assert parent_vrf["vrf_name"] == "ansible-msd-vrf"
        assert "child_fabric_config" not in parent_vrf
        assert "not-a-member" not in parent_vrf.values()
        return {
            "changed": True,
            "output_level": "debug",
            "before": [],
            "after": [],
            "diff": [],
        }

    def fail_child(_child_task):
        raise AssertionError("deleted state must not execute child tasks")

    object.__setattr__(coordinator, "_run_state_machine_with_attachments", run_parent)
    object.__setattr__(coordinator, "_run_child_task", fail_child)

    result = coordinator._handle_parent_workflow(dict(module_args), "multisite_parent")

    assert calls == ["parent"]
    assert result["changed"] is True
    assert result["workflow"] == "Multisite Parent without Child Fabric Processing"


def test_vrf_workflow_coordinator_00060_deleted_detach_ignores_attach_and_deploy():
    """
    # Summary

    Verify state=deleted detaches current ND attachments and records deploy
    targets without honoring the playbook attach block or deploy=false.
    """
    coordinator = VrfWorkflowCoordinator.__new__(VrfWorkflowCoordinator)
    module_args = {
        "state": "deleted",
        "config": [
            {
                "vrf_name": "ansible-msd-vrf",
                "deploy": False,
                "attach": [{"ip_address": "192.0.2.10"}],
            }
        ],
    }
    posted = {}

    object.__setattr__(
        coordinator,
        "_current_attachment_details",
        lambda *_args, **_kwargs: [
            {
                "vrfName": "ansible-msd-vrf",
                "switchId": "SERIAL1",
                "attach": True,
            },
            {
                "vrfName": "ansible-msd-vrf",
                "switchId": "SERIAL2",
                "attach": False,
            },
            {
                "vrfName": "ansible-msd-vrf",
                "switchId": "SERIAL3",
                "attach": False,
                "deploymentStatus": "pending",
            },
        ],
    )

    def post_attachments(_args, _strategy, payloads, deploy_targets, operation_type):
        posted["payloads"] = payloads
        posted["deploy_targets"] = deploy_targets
        posted["operation_type"] = operation_type
        return {"changed": True, "deploy_targets": deploy_targets}

    object.__setattr__(coordinator, "_post_vrf_attachments", post_attachments)

    trace = coordinator._apply_deleted_attachment_phase(module_args, _ParentStrategy())

    assert posted["payloads"] == [
        {
            "vrfName": "ansible-msd-vrf",
            "switchId": "SERIAL1",
            "attach": False,
        }
    ]
    assert posted["deploy_targets"] == {"ansible-msd-vrf": {"SERIAL1", "SERIAL3"}}
    assert trace["deploy_targets"] == {"ansible-msd-vrf": {"SERIAL1", "SERIAL3"}}


def test_vrf_workflow_coordinator_00065_deleted_ignores_absent_vrf_attachment_query():
    """
    # Summary

    Verify state=deleted treats ND's absent-VRF attachment query response as
    no attachments to detach instead of failing before idempotency handling.
    """
    coordinator = VrfWorkflowCoordinator.__new__(VrfWorkflowCoordinator)
    module_args = {
        "state": "deleted",
        "config": [{"vrf_name": "already-absent-vrf"}],
    }

    def missing_vrf(*_args, **_kwargs):
        raise Exception("Request failed (400): Bad Request: {'message': 'VRF(s) already-absent-vrf not found in fabric msd_p'}")

    object.__setattr__(coordinator, "_current_attachment_details", missing_vrf)

    trace = coordinator._apply_deleted_attachment_phase(module_args, _ParentStrategy())

    assert trace == {"deploy_targets": {}}


def test_vrf_workflow_coordinator_00070_deleted_deploys_before_delete():
    """
    # Summary

    Verify state=deleted runs detach, deploy, wait, then delete, and honors
    deploy_type=vrf while ignoring deploy=false.
    """
    module_args = {
        "fabric_name": "msd_p",
        "state": "deleted",
        "output_level": "debug",
        "config": [
            {
                "vrf_name": "ansible-msd-vrf",
                "deploy": False,
                "deploy_type": "vrf",
            }
        ],
    }
    coordinator = VrfWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_ParentStrategy(),
    )
    call_order = []

    def detach(_args, _strategy, vrf_names=None):
        call_order.append("detach")
        assert vrf_names == ["ansible-msd-vrf"]
        return {"deploy_targets": {"ansible-msd-vrf": {"SERIAL1"}}}

    def deploy(_args, _strategy, payload):
        call_order.append("deploy")
        assert payload == {"vrfNames": ["ansible-msd-vrf"]}
        return {}

    def wait(_args, _strategy, vrf_names=None):
        call_order.append("wait")
        assert vrf_names is None

    def delete(_args, strategy=None):
        call_order.append("delete")
        assert strategy is not None
        return {
            "changed": True,
            "output_level": "debug",
            "before": [],
            "after": [],
            "diff": [],
        }

    object.__setattr__(coordinator, "_apply_deleted_attachment_phase", detach)
    object.__setattr__(coordinator, "_deploy_vrf_attachments", deploy)
    object.__setattr__(coordinator, "_wait_for_vrfs_delete_ready", wait)
    object.__setattr__(coordinator, "_run_state_machine", delete)
    object.__setattr__(coordinator, "_ensure_vrfs_have_no_networks", lambda *_args, **_kwargs: None)
    object.__setattr__(
        coordinator,
        "_query_current_vrfs",
        lambda *_args, **_kwargs: [{"vrfName": "ansible-msd-vrf"}],
    )

    result = coordinator._run_state_machine_with_attachments(
        dict(module_args),
        defer_deploy=True,
    )

    assert call_order == ["detach", "deploy", "wait", "delete"]
    assert result["changed"] is True
    assert "_deferred_deploy_payloads" not in result


def test_vrf_workflow_coordinator_deleted_absent_vrf_skips_detach_and_deploy():
    """
    # Summary

    Verify targeted state=deleted does not query attachments or deploy when
    every requested VRF is already absent.
    """
    module_args = {
        "fabric_name": "msd_p",
        "state": "deleted",
        "output_level": "debug",
        "config": [{"vrf_name": "already-absent-vrf"}],
    }
    coordinator = VrfWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_ParentStrategy(),
    )
    call_order = []

    def delete(_args, strategy=None):
        call_order.append("delete")
        assert strategy is not None
        return {
            "changed": False,
            "output_level": "debug",
            "before": [],
            "after": [],
            "diff": [],
        }

    object.__setattr__(coordinator, "_query_current_vrfs", lambda *_args, **_kwargs: [])
    object.__setattr__(
        coordinator,
        "_ensure_vrfs_have_no_networks",
        lambda *_args, **_kwargs: (_sentinel for _sentinel in ()).throw(AssertionError("absent VRF must not run dependency checks")),
    )
    object.__setattr__(
        coordinator,
        "_apply_deleted_attachment_phase",
        lambda *_args, **_kwargs: (_sentinel for _sentinel in ()).throw(AssertionError("absent VRF must not detach")),
    )
    object.__setattr__(
        coordinator,
        "_deploy_vrf_attachments",
        lambda *_args, **_kwargs: (_sentinel for _sentinel in ()).throw(AssertionError("absent VRF must not deploy")),
    )
    object.__setattr__(coordinator, "_run_state_machine", delete)

    result = coordinator._run_state_machine_with_attachments(dict(module_args))

    assert call_order == ["delete"]
    assert result["changed"] is False


def test_vrf_workflow_coordinator_00075_deleted_empty_config_deletes_state_machine_existing():
    """
    # Summary

    Verify state=deleted with config=[] uses the current VRFs already gathered
    by NDStateMachine initialization without running another current-state
    query or rewriting proposed config.
    """
    module_args = {
        "fabric_name": "msd_p",
        "state": "deleted",
        "output_level": "debug",
        "config": [],
    }
    coordinator = VrfWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_ParentStrategy(),
    )
    call_order = []

    class FakeVrf:
        def __init__(self, vrf_name):
            self.vrf_name = vrf_name

        def get_identifier_value(self):
            return self.vrf_name, "msd_p"

    class FakeStateMachine:
        def __init__(self):
            self.existing = [
                FakeVrf("ansible-msd-a"),
                FakeVrf("ansible-msd-b"),
            ]
            self.deleted = []

        def _delete_items(self, items):
            call_order.append("delete_items")
            self.deleted = items

    def detach(args, _strategy, vrf_names=None):
        call_order.append("detach")
        assert args["config"] == [
            {"vrf_name": "ansible-msd-a", "deploy_type": "vrf"},
            {"vrf_name": "ansible-msd-b", "deploy_type": "vrf"},
        ]
        assert module_args["config"] == []
        assert vrf_names == ["ansible-msd-a", "ansible-msd-b"]
        return {"deploy_targets": {}}

    def new_state_machine(args, _strategy):
        call_order.append("state_machine_init")
        assert args["config"] == []
        return FakeStateMachine(), "original-config", "original-state"

    def query_current(*_args, **_kwargs):
        raise AssertionError("delete-all must use state-machine existing data, not another query")

    def format_output(sm):
        call_order.append("format")
        assert [item.vrf_name for item in sm.deleted] == ["ansible-msd-a", "ansible-msd-b"]
        return {
            "changed": True,
            "before": [
                {"vrf_name": "ansible-msd-a"},
                {"vrf_name": "ansible-msd-b"},
            ],
            "after": [],
            "invocation": {"module_args": dict(module_args)},
        }

    def restore(original_config, original_state):
        call_order.append("restore")
        assert original_config == "original-config"
        assert original_state == "original-state"

    object.__setattr__(coordinator, "_new_state_machine", new_state_machine)
    object.__setattr__(coordinator, "_query_current_vrfs", query_current)
    object.__setattr__(coordinator, "_query_current_vrfs_with_trace", query_current)
    object.__setattr__(coordinator, "_apply_deleted_attachment_phase", detach)
    object.__setattr__(coordinator, "_format_state_machine_output", format_output)
    object.__setattr__(coordinator, "_restore_state_machine_params", restore)
    object.__setattr__(coordinator, "_ensure_vrfs_have_no_networks", lambda *_args, **_kwargs: None)

    result = coordinator._run_deleted_state_machine_with_detach_deploy(
        dict(module_args),
        _ParentStrategy(),
    )

    assert call_order == ["state_machine_init", "detach", "delete_items", "format", "restore"]
    assert result["changed"] is True
    assert result["before"] == [
        {"vrf_name": "ansible-msd-a"},
        {"vrf_name": "ansible-msd-b"},
    ]
    assert result["after"] == []
    assert result["invocation"]["module_args"]["config"] == []


def test_vrf_workflow_coordinator_00080_overridden_deploys_omitted_detach_before_delete():
    """
    # Summary

    Verify overridden detaches and deploys omitted VRFs before the state
    machine deletes them, while leaving retained VRFs to the normal flow.
    """
    module_args = {
        "fabric_name": "msd_p",
        "state": "overridden",
        "output_level": "debug",
        "config": [
            {
                "vrf_name": "ansible-keep-vrf",
                "attach": [{"ip_address": "192.0.2.10"}],
            }
        ],
    }
    coordinator = VrfWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_ParentStrategy(),
    )
    call_order = []

    class FakeVrf:
        def __init__(self, vrf_name):
            self.vrf_name = vrf_name

        def get_identifier_value(self):
            return self.vrf_name, "msd_p"

    class FakeStateMachine:
        def __init__(self):
            self.existing = [
                FakeVrf("ansible-keep-vrf"),
                FakeVrf("ansible-delete-vrf"),
            ]

        def manage_state(self):
            call_order.append("state_machine")

    def attachment_details(_args, _strategy, vrf_names=None):
        call_order.append("query_attachments")
        assert vrf_names == ["ansible-keep-vrf", "ansible-delete-vrf"]
        return [
            {
                "vrfName": "ansible-keep-vrf",
                "switchId": "SERIAL2",
                "attach": True,
            },
            {
                "vrfName": "ansible-delete-vrf",
                "switchId": "SERIAL1",
                "attach": True,
            },
        ]

    def detach(_args, _strategy, vrf_names=None, attachment_details=None):
        call_order.append("detach")
        assert vrf_names == ["ansible-delete-vrf"]
        assert attachment_details == [
            {
                "vrfName": "ansible-delete-vrf",
                "switchId": "SERIAL1",
                "attach": True,
            }
        ]
        return {"deploy_targets": {"ansible-delete-vrf": {"SERIAL1"}}}

    def deploy(_args, _strategy, payload):
        call_order.append("deploy")
        assert payload == {
            "switchIds": ["SERIAL1"],
            "vrfNames": ["ansible-delete-vrf"],
        }
        return {}

    def wait(_args, _strategy, vrf_names=None):
        call_order.append("wait")
        assert vrf_names == ["ansible-delete-vrf"]

    def attachment_phase(_args, _strategy, phase, **kwargs):
        call_order.append(f"{phase}_attach")
        assert kwargs["current_vrf_names"] == ["ansible-keep-vrf"]
        return {}

    def new_state_machine(args, strategy=None):
        assert args["config"] == module_args["config"]
        assert strategy is not None
        return FakeStateMachine(), "original-config", "original-state"

    def format_output(_sm):
        return {
            "changed": True,
            "output_level": "debug",
            "before": [],
            "after": [],
            "diff": [],
        }

    object.__setattr__(
        coordinator,
        "_query_current_vrfs",
        lambda *_args, **_kwargs: (_sentinel for _sentinel in ()).throw(AssertionError("overridden must use state-machine existing data")),
    )
    object.__setattr__(coordinator, "_new_state_machine", new_state_machine)
    object.__setattr__(coordinator, "_current_attachment_details_ignore_missing", attachment_details)
    object.__setattr__(coordinator, "_apply_deleted_attachment_phase", detach)
    object.__setattr__(coordinator, "_deploy_vrf_attachments", deploy)
    object.__setattr__(coordinator, "_wait_for_vrfs_delete_ready", wait)
    object.__setattr__(coordinator, "_apply_attachment_phase", attachment_phase)
    object.__setattr__(coordinator, "_desired_attachment_map", lambda *_args: {})
    object.__setattr__(coordinator, "_format_state_machine_output", format_output)
    object.__setattr__(coordinator, "_restore_state_machine_params", lambda *_args: None)
    object.__setattr__(coordinator, "_build_pending_vrf_deploy_payloads", lambda *_args: [])
    object.__setattr__(coordinator, "_ensure_vrfs_have_no_networks", lambda *_args, **_kwargs: None)

    result = coordinator._run_state_machine_with_attachments(dict(module_args))

    assert call_order == [
        "query_attachments",
        "detach",
        "deploy",
        "wait",
        "pre_attach",
        "state_machine",
        "post_attach",
    ]
    assert result["changed"] is True


def test_vrf_workflow_coordinator_check_mode_deleted_skips_deploy_and_wait():
    module_args = {
        "fabric_name": "msd_p",
        "state": "deleted",
        "output_level": "debug",
        "config": [
            {
                "vrf_name": "ansible-msd-vrf",
                "deploy_type": "vrf",
            }
        ],
    }
    module = _Module(dict(module_args))
    module.check_mode = True
    coordinator = VrfWorkflowCoordinator(
        module=module,
        strategy=_ParentStrategy(),
    )
    call_order = []

    def detach(_args, _strategy, vrf_names=None):
        call_order.append("detach")
        assert vrf_names == ["ansible-msd-vrf"]
        return {"deploy_targets": {"ansible-msd-vrf": {"SERIAL1"}}}

    def deploy(*_args):
        raise AssertionError("check mode must not deploy")

    def wait(*_args):
        raise AssertionError("check mode must not wait for delete readiness")

    def delete(_args, strategy=None):
        call_order.append("delete")
        assert strategy is not None
        return {
            "changed": True,
            "output_level": "debug",
            "before": [],
            "after": [],
            "diff": [],
        }

    object.__setattr__(coordinator, "_apply_deleted_attachment_phase", detach)
    object.__setattr__(coordinator, "_deploy_vrf_attachments", deploy)
    object.__setattr__(coordinator, "_wait_for_vrfs_delete_ready", wait)
    object.__setattr__(coordinator, "_run_state_machine", delete)
    object.__setattr__(coordinator, "_ensure_vrfs_have_no_networks", lambda *_args, **_kwargs: None)
    object.__setattr__(
        coordinator,
        "_query_current_vrfs",
        lambda *_args, **_kwargs: [{"vrfName": "ansible-msd-vrf"}],
    )

    result = coordinator._run_state_machine_with_attachments(dict(module_args))

    assert call_order == ["detach", "delete"]
    assert result["changed"] is True
    assert result["check_mode_deploy_payloads"] == [{"vrfNames": ["ansible-msd-vrf"]}]


def test_vrf_workflow_coordinator_deleted_deploys_pending_vrfs_before_delete():
    module_args = {
        "fabric_name": "MCFG_C",
        "state": "deleted",
        "config": [],
        "timeout": 30,
    }
    coordinator = VrfWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_McfgParentStrategy(),
    )
    call_order = []

    class FakeVrf:
        def to_config(self):
            return {
                "vrf_name": "ansible-nd-vrf-mcfg-merged",
                "vrf_status": "pending",
            }

    def deploy(args, strategy, payload):
        call_order.append("deploy")
        assert args == module_args
        assert strategy.fabric_name == "MCFG_C"
        assert payload == {"vrfNames": ["ansible-nd-vrf-mcfg-merged"]}
        return {"changed": True, "failed": False}

    def wait(args, strategy, vrf_names):
        call_order.append("wait")
        assert args == module_args
        assert strategy.fabric_name == "MCFG_C"
        assert vrf_names == ["ansible-nd-vrf-mcfg-merged"]

    object.__setattr__(coordinator, "_deploy_vrf_attachments", deploy)
    object.__setattr__(coordinator, "_wait_for_vrfs_delete_ready", wait)

    traces = coordinator._vrf_state_machine()._deploy_pending_vrfs_before_delete(
        module_args,
        _McfgParentStrategy(),
        [FakeVrf()],
        ["ansible-nd-vrf-mcfg-merged"],
    )

    assert call_order == ["deploy", "wait"]
    assert traces == [{"changed": True, "failed": False}]


def test_vrf_workflow_coordinator_delete_all_parent_cleanup_uses_vrf_deploy_scope():
    coordinator = VrfWorkflowCoordinator(
        module=_Module({"fabric_name": "MCFG_C", "state": "deleted", "config": []}),
        strategy=_McfgParentStrategy(),
    )

    config = coordinator._vrf_state_machine()._delete_all_generated_config(
        "ansible-nd-vrf-mcfg-merged",
        _McfgParentStrategy(),
    )

    assert config == {
        "vrf_name": "ansible-nd-vrf-mcfg-merged",
        "deploy_type": "vrf",
    }


def test_vrf_workflow_coordinator_mcfg_parent_uses_manage_deploy_endpoint():
    strategy = MulticlusterParentVrfStrategy(
        fabric_name="MCFG_C",
        fabric_data={},
    )
    endpoint = strategy.vrf_actions_deploy_post_cls()(fabric_name="MCFG_C")

    assert endpoint.path == "/api/v1/oneManage/manage/fabrics/MCFG_C/vrfActions/deploy"


def test_vrf_workflow_coordinator_check_mode_attachment_phase_returns_planned_payload():
    module_args = {
        "fabric_name": "msd_p",
        "state": "merged",
        "config": [
            {
                "vrf_name": "ansible-msd-vrf",
                "attach": [{"ip_address": "10.1.1.11"}],
            }
        ],
    }
    module = _Module(dict(module_args))
    module.check_mode = True
    coordinator = VrfWorkflowCoordinator(
        module=module,
        strategy=_ParentStrategy(),
    )

    def post_vrf_attachments(*_args, **_kwargs):
        raise AssertionError("check mode must not post VRF attachments")

    coordinator.attachments.post_vrf_attachments = post_vrf_attachments
    desired = {
        ("ansible-msd-vrf", "SERIAL1"): {
            "vrfName": "ansible-msd-vrf",
            "switchId": "SERIAL1",
            "attach": True,
        }
    }

    trace = coordinator._apply_attachment_phase(
        module_args,
        _ParentStrategy(),
        phase="post",
        desired=desired,
        current={},
    )

    assert trace["changed"] is True
    assert trace["deploy_targets"] == {"ansible-msd-vrf": {"SERIAL1"}}
    assert trace["check_mode_attachment_payloads"] == [
        {
            "vrfName": "ansible-msd-vrf",
            "switchId": "SERIAL1",
            "attach": True,
        }
    ]


def test_vrf_workflow_coordinator_attachment_payload_includes_vrf_vlan_id():
    """Verify VRF attach payloads inherit the VRF VLAN ID."""

    class Coordinator:
        @staticmethod
        def _resolve_switch_ids(_module_args, _strategy, _config):
            return {"10.1.1.11": "SERIAL1"}

        @staticmethod
        def _attachment_instance_values(_attachment):
            return {}

    manager = VrfAttachmentManager(Coordinator())
    module_args = {
        "config": [
            {
                "vrf_name": "ansible-vrf",
                "vlan_id": 3701,
                "attach": [{"ip_address": "10.1.1.11"}],
            }
        ]
    }

    desired = manager.desired_attachment_map(module_args, _StandaloneStrategy())

    assert desired[("ansible-vrf", "SERIAL1")] == {
        "vrfName": "ansible-vrf",
        "switchId": "SERIAL1",
        "vlanId": 3701,
        "attach": True,
    }


def test_vrf_workflow_coordinator_expands_vpc_peer_from_existing_attachment_query():
    """Verify peerSwitchId from the existing attachment query expands desired attachments."""

    desired = {
        ("ansible-vrf", "SERIAL1"): {
            "vrfName": "ansible-vrf",
            "switchId": "SERIAL1",
            "vlanId": 3701,
            "attach": True,
        }
    }
    attachment_details = [
        {
            "vrfName": "ansible-vrf",
            "switchId": "SERIAL1",
            "peerSwitchId": "SERIAL2",
            "attach": False,
            "status": "notApplicable",
        },
        {
            "vrfName": "ansible-vrf",
            "switchId": "SERIAL2",
            "peerSwitchId": "SERIAL1",
            "attach": False,
            "status": "notApplicable",
        },
    ]

    expanded = VrfAttachmentManager.expand_desired_attachments_with_vpc_peers(desired, attachment_details)

    assert expanded == {
        ("ansible-vrf", "SERIAL1"): {
            "vrfName": "ansible-vrf",
            "switchId": "SERIAL1",
            "vlanId": 3701,
            "attach": True,
        },
        ("ansible-vrf", "SERIAL2"): {
            "vrfName": "ansible-vrf",
            "switchId": "SERIAL2",
            "vlanId": 3701,
            "attach": True,
        },
    }


def test_vrf_workflow_coordinator_attachment_207_failure_fails_fast():
    """Verify per-switch attachment failures are surfaced instead of entering deploy wait loops."""

    module = _Module({})

    class Coordinator:
        def __init__(self):
            self.module = module

    manager = VrfAttachmentManager(Coordinator())
    response = {
        "results": [
            {
                "status": "failed",
                "switchId": "SERIAL1",
                "vrfName": "ansible-vrf",
                "message": "Attach Response : Failed : VPC details not found",
            }
        ]
    }

    with pytest.raises(AssertionError, match="VRF attachment failed"):
        manager._raise_on_attachment_failures(response)


def test_vrf_workflow_coordinator_00085_overridden_new_vrf_does_not_query_missing_attachments():
    """
    # Summary

    Verify overridden can replace old VRFs with a brand-new attached VRF
    without querying attachments for the new VRF before it exists on ND.
    """
    module_args = {
        "fabric_name": "msd_p",
        "state": "overridden",
        "output_level": "debug",
        "config": [
            {
                "vrf_name": "ansible-new-vrf",
                "deploy": False,
                "attach": [{"ip_address": "192.0.2.10"}],
            }
        ],
    }
    coordinator = VrfWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_ParentStrategy(),
    )
    call_order = []
    posted = {}

    class FakeVrf:
        def __init__(self, vrf_name):
            self.vrf_name = vrf_name

        def get_identifier_value(self):
            return self.vrf_name, "msd_p"

    class FakeStateMachine:
        def __init__(self):
            self.existing = [FakeVrf("ansible-old-vrf")]

        def manage_state(self):
            call_order.append("state_machine")

    def attachment_details(_args, _strategy, vrf_names=None):
        call_order.append("query_attachments")
        assert vrf_names == ["ansible-old-vrf"]
        return []

    def detach(_args, _strategy, vrf_names=None, attachment_details=None):
        call_order.append("detach")
        assert vrf_names == ["ansible-old-vrf"]
        assert attachment_details == []
        return {"deploy_targets": {}}

    def fail_current_attachment_query(*_args, **_kwargs):
        raise AssertionError("new overridden VRF attachments must not be queried before create")

    def post_attachments(_args, _strategy, payloads, deploy_targets, operation_type):
        call_order.append("post_attach")
        posted["payloads"] = payloads
        posted["deploy_targets"] = deploy_targets
        posted["operation_type"] = operation_type
        return {"changed": True, "deploy_targets": deploy_targets}

    def new_state_machine(args, strategy=None):
        assert args["config"] == module_args["config"]
        assert strategy is not None
        return FakeStateMachine(), "original-config", "original-state"

    def format_output(_sm):
        return {
            "changed": True,
            "output_level": "debug",
            "before": [],
            "after": [{"vrf_name": "ansible-new-vrf"}],
            "diff": [],
        }

    object.__setattr__(
        coordinator,
        "_query_current_vrfs",
        lambda *_args, **_kwargs: (_sentinel for _sentinel in ()).throw(AssertionError("overridden must use state-machine existing data")),
    )
    object.__setattr__(coordinator, "_new_state_machine", new_state_machine)
    object.__setattr__(coordinator, "_current_attachment_details_ignore_missing", attachment_details)
    object.__setattr__(coordinator, "_apply_deleted_attachment_phase", detach)
    object.__setattr__(coordinator, "_current_attachment_map", fail_current_attachment_query)
    object.__setattr__(
        coordinator,
        "_desired_attachment_map",
        lambda *_args: {
            ("ansible-new-vrf", "SERIAL1"): {
                "vrfName": "ansible-new-vrf",
                "switchId": "SERIAL1",
                "attach": True,
            }
        },
    )
    object.__setattr__(coordinator, "_post_vrf_attachments", post_attachments)
    object.__setattr__(coordinator, "_format_state_machine_output", format_output)
    object.__setattr__(coordinator, "_restore_state_machine_params", lambda *_args: None)
    object.__setattr__(coordinator, "_build_pending_vrf_deploy_payloads", lambda *_args: [])
    object.__setattr__(coordinator, "_ensure_vrfs_have_no_networks", lambda *_args, **_kwargs: None)

    result = coordinator._run_state_machine_with_attachments(dict(module_args))

    assert call_order == ["query_attachments", "detach", "state_machine", "post_attach"]
    assert posted["payloads"] == [
        {
            "vrfName": "ansible-new-vrf",
            "switchId": "SERIAL1",
            "attach": True,
        }
    ]
    assert posted["deploy_targets"] == {}
    assert result["changed"] is True


def test_vrf_workflow_coordinator_00090_delete_precheck_blocks_network_references():
    """
    # Summary

    Verify VRF delete fails before detach/delete when networks still reference
    the target VRF.
    """
    module_args = {
        "fabric_name": "msd_p",
        "state": "deleted",
        "output_level": "debug",
        "config": [{"vrf_name": "ansible-msd-vrf"}],
    }
    coordinator = VrfWorkflowCoordinator(
        module=_Module(dict(module_args)),
        strategy=_ParentStrategy(),
    )

    object.__setattr__(
        coordinator,
        "_current_networks_for_vrfs",
        lambda *_args, **_kwargs: [
            {
                "vrfName": "ansible-msd-vrf",
                "networkName": "ansible-net-a",
            }
        ],
    )

    with pytest.raises(AssertionError) as exc:
        coordinator._ensure_vrfs_have_no_networks(
            module_args,
            _ParentStrategy(),
            ["ansible-msd-vrf"],
        )

    assert "Cannot delete VRF" in str(exc.value)
    assert "ansible-net-a" in str(exc.value)
