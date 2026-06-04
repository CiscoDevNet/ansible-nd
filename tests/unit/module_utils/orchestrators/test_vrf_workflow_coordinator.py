# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for VRF workflow result aggregation.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import (
    VrfWorkflowCoordinator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import (
    VrfConfigModel,
    VrfParentConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_argument_specs import (
    vrf_parent_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_fabric_resolver import (
    VrfFabricResolver,
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
    def is_child(self):
        return False

    @property
    def is_parent(self):
        return True

    def child_fabric_members(self):
        return ["AK-VXLAN"]

    def build_child_task_args(self, child_fabric_name, vrf_configs, state):
        return {
            "fabric": child_fabric_name,
            "state": state,
            "config": vrf_configs,
        }


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
        "fabric": "AK-VXLAN",
        "state": "merged",
        "config": [
            {
                "vrf_name": "ansible-vrf",
                "child_fabric_config": [{"fabric": "child"}],
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
        "fabric": "AK-VXLAN",
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
    assert parent["fabric"] == "msd_p"
    assert parent["fabric_type"] == "multisite_parent"
    assert parent["after"] == parent_result["after"]
    assert parent["api_paths"] == parent_result["api_paths"]
    assert parent["api_response"] == parent_result["api_response"]
    assert "child_fabric" not in parent

    child = result["child_fabrics"][0]
    assert child["fabric"] == "AK-VXLAN"
    assert child["fabric_type"] == "multisite_child"
    assert child["after"] == child_result["after"]
    assert child["api_paths"] == child_result["api_paths"]
    assert child["api_payload"] == child_result["api_payload"]
    assert "child_fabric" not in child


def test_vrf_workflow_coordinator_00020_parent_deploy_deferred_after_child_tasks(monkeypatch):
    """
    # Summary

    Verify parent attach/deploy fields stay on the parent task, are stripped
    from child tasks, and the parent deploy runs after child processing.
    """
    module_args = {
        "fabric": "msd_p",
        "state": "merged",
        "output_level": "debug",
        "config": [
            {
                "vrf_name": "ansible-msd-vrf",
                "deploy": True,
                "attach": [{"ip_address": "192.168.1.224"}],
                "child_fabric_config": [
                    {
                        "fabric": "AK-VXLAN",
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

    monkeypatch.setattr(
        VrfFabricResolver,
        "strategy_from_fabric_details",
        staticmethod(lambda _name, _data: _ChildStrategy()),
    )

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

    monkeypatch.setattr(coordinator, "_run_state_machine_with_attachments", run_parent)
    monkeypatch.setattr(coordinator, "_run_child_task", run_child)
    monkeypatch.setattr(coordinator, "_deploy_vrf_attachments", deploy_parent)

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


def test_vrf_workflow_coordinator_00050_deleted_ignores_child_fabric_config(monkeypatch):
    """
    # Summary

    Verify state=deleted strips child_fabric_config and does not create or
    execute child fabric tasks.
    """
    module_args = {
        "fabric": "msd_p",
        "state": "deleted",
        "output_level": "debug",
        "config": [
            {
                "vrf_name": "ansible-msd-vrf",
                "child_fabric_config": [{"fabric": "not-a-member"}],
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

    monkeypatch.setattr(coordinator, "_run_state_machine_with_attachments", run_parent)
    monkeypatch.setattr(coordinator, "_run_child_task", fail_child)

    result = coordinator._handle_parent_workflow(dict(module_args), "multisite_parent")

    assert calls == ["parent"]
    assert result["changed"] is True
    assert result["workflow"] == "Multisite Parent without Child Fabric Processing"


def test_vrf_workflow_coordinator_00060_deleted_detach_ignores_attach_and_deploy(monkeypatch):
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

    monkeypatch.setattr(
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

    monkeypatch.setattr(coordinator, "_post_vrf_attachments", post_attachments)

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


def test_vrf_workflow_coordinator_00065_deleted_ignores_absent_vrf_attachment_query(monkeypatch):
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

    monkeypatch.setattr(coordinator, "_current_attachment_details", missing_vrf)

    trace = coordinator._apply_deleted_attachment_phase(module_args, _ParentStrategy())

    assert trace == {"deploy_targets": {}}


def test_vrf_workflow_coordinator_00070_deleted_deploys_before_delete(monkeypatch):
    """
    # Summary

    Verify state=deleted runs detach, deploy, wait, then delete, and honors
    deploy_type=vrf while ignoring deploy=false.
    """
    module_args = {
        "fabric": "msd_p",
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

    def detach(_args, _strategy):
        call_order.append("detach")
        return {"deploy_targets": {"ansible-msd-vrf": {"SERIAL1"}}}

    def deploy(_args, _strategy, payload):
        call_order.append("deploy")
        assert payload == {"vrfNames": ["ansible-msd-vrf"]}
        return {}

    def wait(_args, _strategy):
        call_order.append("wait")

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

    monkeypatch.setattr(coordinator, "_apply_deleted_attachment_phase", detach)
    monkeypatch.setattr(coordinator, "_deploy_vrf_attachments", deploy)
    monkeypatch.setattr(coordinator, "_wait_for_vrfs_delete_ready", wait)
    monkeypatch.setattr(coordinator, "_run_state_machine", delete)

    result = coordinator._run_state_machine_with_attachments(
        dict(module_args),
        defer_deploy=True,
    )

    assert call_order == ["detach", "deploy", "wait", "delete"]
    assert result["changed"] is True
    assert "_deferred_deploy_payloads" not in result


def test_vrf_workflow_coordinator_00080_overridden_deploys_omitted_detach_before_delete(monkeypatch):
    """
    # Summary

    Verify overridden detaches and deploys omitted VRFs before the state
    machine deletes them, while leaving retained VRFs to the normal flow.
    """
    module_args = {
        "fabric": "msd_p",
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

    def query_current(_args, _strategy):
        return [
            {"vrfName": "ansible-keep-vrf"},
            {"vrfName": "ansible-delete-vrf"},
        ]

    def detach(_args, _strategy, vrf_names=None):
        call_order.append("detach")
        assert vrf_names == ["ansible-delete-vrf"]
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

    def run_state_machine(_args, strategy=None):
        call_order.append("state_machine")
        assert strategy is not None
        return {
            "changed": True,
            "output_level": "debug",
            "before": [],
            "after": [],
            "diff": [],
        }

    monkeypatch.setattr(coordinator, "_query_current_vrfs", query_current)
    monkeypatch.setattr(coordinator, "_apply_deleted_attachment_phase", detach)
    monkeypatch.setattr(coordinator, "_deploy_vrf_attachments", deploy)
    monkeypatch.setattr(coordinator, "_wait_for_vrfs_delete_ready", wait)
    monkeypatch.setattr(coordinator, "_apply_attachment_phase", attachment_phase)
    monkeypatch.setattr(coordinator, "_desired_attachment_map", lambda *_args: {})
    monkeypatch.setattr(coordinator, "_run_state_machine", run_state_machine)

    result = coordinator._run_state_machine_with_attachments(dict(module_args))

    assert call_order == [
        "detach",
        "deploy",
        "wait",
        "pre_attach",
        "state_machine",
        "post_attach",
    ]
    assert result["changed"] is True
