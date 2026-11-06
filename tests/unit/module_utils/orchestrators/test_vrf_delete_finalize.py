# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""VRF finalization dispatch preserves the ordinary deletion path."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.overlay_deletion_finalizer import OverlayDeletionFinalizer
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_state_machine import (
    VrfStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import (
    VrfWorkflowCoordinator,
)
from ansible_collections.cisco.nd.plugins.modules import nd_manage_vrfs


def test_vrf_delete_finalize_uses_only_definition_finalizer():
    coordinator = Mock()
    strategy = Mock()
    args = {
        "state": "deleted",
        "deletion_mode": "finalize",
        "config": [{"vrf_name": "BLUE"}],
    }
    expected = {"changed": True, "deletion_finalization": {"resource": "vrf"}}
    with patch("ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_state_machine.OverlayDeletionFinalizer") as factory:
        factory.return_value.run.return_value = expected
        assert VrfStateMachine(coordinator).run_deleted(args, strategy) is expected
    factory.assert_called_once_with(coordinator, "vrf")
    factory.return_value.run.assert_called_once_with(args, strategy)
    coordinator._query_current_vrfs.assert_not_called()
    coordinator._apply_deleted_attachment_phase.assert_not_called()
    coordinator._deploy_vrf_attachments.assert_not_called()


def test_vrf_standard_delete_keeps_existing_workflow():
    coordinator = Mock()
    strategy = Mock()
    args = {"state": "deleted", "config": [{"vrf_name": "BLUE", "deploy": False}]}
    coordinator._configured_vrf_names.return_value = ["BLUE"]
    coordinator._query_current_vrfs.return_value = [{"vrfName": "BLUE"}]
    coordinator._apply_deleted_attachment_phase.return_value = {}
    coordinator._build_deploy_payloads.return_value = []
    coordinator._run_state_machine.return_value = {"changed": True}
    with patch("ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_state_machine.OverlayDeletionFinalizer") as factory:
        result = VrfStateMachine(coordinator).run_deleted(args, strategy)
    assert result["changed"] is True
    factory.assert_not_called()
    coordinator._ensure_vrfs_have_no_networks.assert_called_once_with(args, strategy, ["BLUE"])
    coordinator._apply_deleted_attachment_phase.assert_called_once_with(args, strategy, ["BLUE"])


def test_coordinator_routes_finalize_before_parent_child_dispatch():
    module = Mock()
    module.params = {
        "fabric_name": "fab1",
        "state": "deleted",
        "deletion_mode": "finalize",
        "config": [{"vrf_name": "BLUE"}],
    }
    module.check_mode = False
    module._verbosity = 0
    strategy = Mock()
    strategy.fabric_type = "standalone"
    coordinator = VrfWorkflowCoordinator(module, strategy=strategy)
    coordinator._validate_topology_argument_scope = Mock()
    expected = {"changed": False}
    with patch("ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator.OverlayDeletionFinalizer") as factory:
        factory.return_value.run.return_value = expected
        assert coordinator.run() == expected
    factory.return_value.run.assert_called_once_with(module.params, strategy)


def test_vrf_module_exposes_opt_in_finalize_mode_with_unchanged_default():
    arguments = {}

    class Module:
        params = {"fabric_name": "fab1", "state": "gathered", "config": []}

        def __init__(self, **kwargs):
            arguments.update(kwargs["argument_spec"])

        def exit_json(self, **kwargs):
            pass

    with (
        patch.object(nd_manage_vrfs, "AnsibleModule", Module),
        patch.object(nd_manage_vrfs, "require_pydantic"),
        patch.object(nd_manage_vrfs, "VrfWorkflowCoordinator") as factory,
    ):
        factory.return_value.run.return_value = {"changed": False}
        nd_manage_vrfs.main()
    assert arguments["deletion_mode"] == {
        "type": "str",
        "default": "standard",
        "choices": ["standard", "finalize"],
    }


class _FinalizationCoordinator:
    """Record helper routing with controller-shaped observations."""

    def __init__(self, definition_status="notApplicable", attachment=None, check_mode=False, remain_after_delete=False):
        self.module = SimpleNamespace(check_mode=check_mode)
        self.definitions = [{"vrfName": "BLUE", "vrfStatus": definition_status}]
        self.attachment = attachment if attachment is not None else {"vrfName": "BLUE", "switchId": "SERIAL1", "attach": False, "status": "notApplicable"}
        self.calls = []
        self.remain_after_delete = remain_after_delete
        self.dependency_error = False
        self.loaded_names = None
        self.params_restored = False
        from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_attachment_manager import VrfAttachmentManager

        self.attachments = VrfAttachmentManager(self)

    def _new_vrf_orchestrator(self, _args, _strategy):
        return self, object()

    @staticmethod
    def _vrf_name_filter(_names):
        return "vrfName:BLUE"

    @staticmethod
    def _make_endpoint(endpoint_type):
        endpoint = endpoint_type()
        endpoint.fabric_name = "fab1"
        return endpoint

    def _request(self, **kwargs):
        if "/vrfAttachments/query" in kwargs["path"]:
            assert kwargs["data"] == {"vrfNames": ["BLUE"]}
            self.calls.append("attachment_query")
            return {"attachments": [deepcopy(self.attachment)]}
        assert "/vrfs?" in kwargs["path"]
        self.calls.append("definition_query")
        return {"vrfs": deepcopy(self.definitions)}

    def _ensure_vrfs_have_no_networks(self, _args, _strategy, names):
        self.calls.append("dependency_check")
        assert names in (["BLUE"], [])
        if self.dependency_error:
            raise ValueError("Network still references BLUE")

    def _new_state_machine(self, _args, _strategy):
        names = self.loaded_names if self.loaded_names is not None else [row["vrfName"] for row in self.definitions]

        def manage_state():
            if self.module.check_mode:
                self.calls.append("delete_plan")
            else:
                self.calls.append("definition_delete")
                if not self.remain_after_delete:
                    self.definitions = []

        return SimpleNamespace(existing=[SimpleNamespace(vrf_name=name) for name in names], manage_state=manage_state), [], "deleted"

    def _restore_state_machine_params(self, _config, _state):
        self.params_restored = True

    @staticmethod
    def _format_state_machine_output(_sm):
        return {"changed": True, "failed": False}

    @staticmethod
    def _finalize_api_trace(_results):
        return {}

    @staticmethod
    def _merge_api_trace(_result, _trace, **_kwargs):
        pass


def _finalize_args():
    return {"state": "deleted", "deletion_mode": "finalize", "config": [{"vrf_name": "BLUE"}]}


def test_vrf_finalize_reuses_crud_state_and_reports_operations_without_extra_reads():
    coordinator = _FinalizationCoordinator()
    result = OverlayDeletionFinalizer(coordinator, "vrf").run(_finalize_args(), StandaloneVrfStrategy("fab1"))
    assert coordinator.calls == ["dependency_check", "definition_delete"]
    receipt = result["deletion_finalization"]
    assert receipt["version"] == 1
    assert receipt["deletion_operations_succeeded"] is True
    assert "definition_absence_verified" not in receipt
    assert "attachments_verified_detached" not in receipt
    assert receipt["names"] == ["BLUE"]
    assert receipt["deployment_attempts"] == receipt["detach_attempts"] == 0


@pytest.mark.parametrize("status", ["deployed", "pending", "failed", "outOfSync", "", None])
def test_vrf_finalize_does_not_repeat_caller_readiness_checks(status):
    coordinator = _FinalizationCoordinator(definition_status=status)
    result = OverlayDeletionFinalizer(coordinator, "vrf").run(_finalize_args(), StandaloneVrfStrategy("fab1"))
    assert coordinator.calls == ["dependency_check", "definition_delete"]
    assert result["deletion_finalization"]["deletion_operations_succeeded"] is True


@pytest.mark.parametrize(
    "fields",
    [{"attach": True}, {"attach": "false"}, {"attach": None}, {"status": "pending"}, {"status": "failed"}, {"status": "outOfSync"}, {"status": None}],
)
def test_vrf_finalize_does_not_query_or_modify_attachments(fields):
    attachment = {"vrfName": "BLUE", "switchId": "SERIAL1", "attach": False, "status": "notApplicable", **fields}
    coordinator = _FinalizationCoordinator(attachment=attachment)
    result = OverlayDeletionFinalizer(coordinator, "vrf").run(_finalize_args(), StandaloneVrfStrategy("fab1"))
    assert coordinator.calls == ["dependency_check", "definition_delete"]
    assert result["deletion_finalization"]["detach_attempts"] == 0


def test_vrf_finalize_keeps_existing_network_dependency_guard():
    coordinator = _FinalizationCoordinator()
    coordinator.dependency_error = True
    with pytest.raises(ValueError, match="Network still references"):
        OverlayDeletionFinalizer(coordinator, "vrf").run(_finalize_args(), StandaloneVrfStrategy("fab1"))
    assert "definition_delete" not in coordinator.calls


def test_vrf_finalize_treats_absent_crud_target_as_no_op_and_restores_params():
    coordinator = _FinalizationCoordinator()
    coordinator.loaded_names = []
    result = OverlayDeletionFinalizer(coordinator, "vrf").run(_finalize_args(), StandaloneVrfStrategy("fab1"))
    assert coordinator.calls == ["dependency_check", "definition_delete"]
    assert result["deletion_finalization"]["existing_before"] == []
    assert coordinator.params_restored is True


def test_vrf_finalize_check_mode_is_a_plan_not_an_operation_success_claim():
    coordinator = _FinalizationCoordinator(check_mode=True)
    result = OverlayDeletionFinalizer(coordinator, "vrf").run(_finalize_args(), StandaloneVrfStrategy("fab1"))
    assert coordinator.calls == ["dependency_check", "delete_plan"]
    assert coordinator.definitions
    assert result["deletion_finalization"]["deletion_operations_succeeded"] is None


def test_vrf_finalize_trusts_delete_result_without_an_extra_absence_query_or_deployment():
    coordinator = _FinalizationCoordinator(remain_after_delete=True)
    result = OverlayDeletionFinalizer(coordinator, "vrf").run(_finalize_args(), StandaloneVrfStrategy("fab1"))
    assert result["failed"] is False
    assert result["deletion_finalization"]["deletion_operations_succeeded"] is True
    assert coordinator.definitions
    assert coordinator.calls == ["dependency_check", "definition_delete"]
    assert result["deletion_finalization"]["deployment_attempts"] == 0
