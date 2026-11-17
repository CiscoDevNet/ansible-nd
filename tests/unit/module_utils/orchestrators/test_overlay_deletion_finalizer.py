# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Definition-only deletion trusts completed caller deployment without extra reads."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.overlay_deletion_finalizer import OverlayDeletionFinalizer
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_state_machine import NetworkStateMachine
from ansible_collections.cisco.nd.plugins.modules import nd_manage_networks


class _Endpoint:
    def __init__(self):
        self.endpoint_params = SimpleNamespace(filter=None, max=None, offset=0, include_all=None)

    @property
    def path(self):
        return f"{self.kind}:{self.endpoint_params.offset}"


class _Definitions(_Endpoint):
    kind = "definitions"
    verb = "GET"


class _Attachments(_Endpoint):
    kind = "attachments"
    verb = "POST"


class _Coordinator:
    def __init__(self, resource="network", *, check_mode=False):
        self.resource = resource
        self.module = SimpleNamespace(check_mode=check_mode)
        self.requests = []
        self.calls = []
        self.definitions = [{resource + "Name": "BLUE", resource + "Status": "notApplicable"}]
        self.attachment_rows = [{resource + "Name": "BLUE", "switchId": "SERIAL1", "attach": False, "status": "notApplicable"}]
        self.deleted = False
        self.after = []
        self.read_failure_after_delete = False
        self.attachments = SimpleNamespace(_attachments_query_endpoint_cls=lambda _strategy: _Attachments)
        self.loaded_names = None
        self.params_restored = False
        self.crud_error = None
        self.result_failure = False
        self.dependency_error = None

    def _factory(self, _args, _strategy):
        return self, None

    _new_network_orchestrator = _factory
    _new_vrf_orchestrator = _factory

    @staticmethod
    def _make_endpoint(endpoint_type):
        return endpoint_type()

    @staticmethod
    def _name_filter(names):
        return "|".join(names)

    _network_name_filter = _name_filter
    _vrf_name_filter = _name_filter

    def _request(self, *, path, verb, data=None, **_kwargs):
        self.requests.append((path, verb, deepcopy(data)))
        if path.startswith("definitions:"):
            if self.deleted and self.read_failure_after_delete:
                raise RuntimeError("lost observation")
            rows = self.after if self.deleted else self.definitions
            return {self.resource + "s": deepcopy(rows), "meta": {"counts": {"total": len(rows), "remaining": 0}}}
        assert path.startswith("attachments:")
        return {"attachments": deepcopy(self.attachment_rows), "meta": {"counts": {"total": len(self.attachment_rows), "remaining": 0}}}

    def _ensure(self, _args, _strategy, names):
        self.calls.append(("dependency_guard", names))
        if self.dependency_error:
            raise ValueError(self.dependency_error)

    _ensure_networks_have_no_networks = _ensure
    _ensure_vrfs_have_no_networks = _ensure

    def _new_state_machine(self, _args, strategy):
        names = self.loaded_names if self.loaded_names is not None else [row[self.resource + "Name"] for row in self.definitions]
        existing = [SimpleNamespace(**{self.resource + "_name": name}) for name in names]

        def manage_state():
            self.calls.append(("definition_crud", strategy.fabric_name))
            if self.crud_error:
                raise RuntimeError(self.crud_error)
            if not self.module.check_mode:
                self.deleted = True

        return SimpleNamespace(existing=existing, manage_state=manage_state), [], "deleted"

    def _restore_state_machine_params(self, _config, _state):
        self.params_restored = True

    def _format_state_machine_output(self, _sm):
        return {"changed": bool(self.definitions), "failed": self.result_failure, "before": deepcopy(self.definitions), "after": []}

    @staticmethod
    def _finalize_api_trace(_results):
        return {}

    @staticmethod
    def _merge_api_trace(_result, _trace, prepend=False):
        assert prepend


def _args(resource="network"):
    return {"state": "deleted", "deletion_mode": "finalize", "config": [{resource + "_name": "BLUE"}]}


def _strategy():
    return SimpleNamespace(
        fabric_name="fab1",
        fabric_type="standalone",
        is_parent=False,
        is_child=False,
        is_multicluster=False,
        is_multisite=False,
        networks_get_cls=lambda: _Definitions,
        vrfs_get_cls=lambda: _Definitions,
    )


@pytest.mark.parametrize("resource", ["network", "vrf"])
def test_finalize_uses_loaded_crud_scope_without_extra_queries(resource):
    coordinator = _Coordinator(resource)
    result = OverlayDeletionFinalizer(coordinator, resource).run(_args(resource), _strategy())
    assert coordinator.calls == [("dependency_guard", ["BLUE"]), ("definition_crud", "fab1")]
    assert coordinator.requests == []
    assert coordinator.params_restored is True
    proof = result["deletion_finalization"]
    assert proof["version"] == 1
    assert proof["proof"] == "definition_only_overlay_deletion_v1"
    assert proof["deletion_operations_succeeded"] is True
    assert "definition_absence_verified" not in proof
    assert "attachments_verified_detached" not in proof
    assert proof["detach_attempts"] == proof["deployment_attempts"] == 0
    assert proof["existing_before"] == proof["names"] == ["BLUE"]
    assert len(proof["request_sha256"]) == 64
    assert result["fabric_type"] == "standalone"
    assert result["workflow"] == f"Standalone Fabric {resource.capitalize()} Definition Finalization"


@pytest.mark.parametrize("resource", ["network", "vrf"])
def test_check_mode_plans_without_deleting_or_claiming_operation_success(resource):
    coordinator = _Coordinator(resource, check_mode=True)
    result = OverlayDeletionFinalizer(coordinator, resource).run(_args(resource), _strategy())
    assert coordinator.deleted is False
    assert coordinator.requests == []
    assert coordinator.params_restored is True
    assert result["deletion_finalization"]["deletion_operations_succeeded"] is None


@pytest.mark.parametrize("status", ["pending", "failed", "outOfSync", "deployed", "inSync", None, ""])
@pytest.mark.parametrize("resource", ["network", "vrf"])
def test_finalize_does_not_add_readiness_gate_to_caller_completed_deployment(resource, status):
    coordinator = _Coordinator(resource)
    coordinator.definitions[0][resource + "Status"] = status
    result = OverlayDeletionFinalizer(coordinator, resource).run(_args(resource), _strategy())
    assert coordinator.deleted is True
    assert coordinator.requests == []
    assert result["deletion_finalization"]["deletion_operations_succeeded"] is True
    assert "definition_absence_verified" not in result["deletion_finalization"]


@pytest.mark.parametrize("change", [{"attach": True}, {"attach": "false"}, {"status": "pending"}, {"status": "failed"}, {"status": None}])
def test_finalize_never_queries_or_changes_attachments(change):
    coordinator = _Coordinator()
    coordinator.attachment_rows[0].update(change)
    result = OverlayDeletionFinalizer(coordinator, "network").run(_args(), _strategy())
    assert coordinator.requests == []
    assert result["deletion_finalization"]["detach_attempts"] == 0
    assert result["deletion_finalization"]["deployment_attempts"] == 0


@pytest.mark.parametrize("resource", ["network", "vrf"])
def test_already_absent_target_succeeds_without_extra_absence_query(resource):
    coordinator = _Coordinator(resource)
    coordinator.definitions = []
    result = OverlayDeletionFinalizer(coordinator, resource).run(_args(resource), _strategy())
    assert result["changed"] is False
    assert result["deletion_finalization"]["existing_before"] == []
    assert result["deletion_finalization"]["names"] == ["BLUE"]
    assert result["deletion_finalization"]["deletion_operations_succeeded"] is True
    assert coordinator.requests == []


@pytest.mark.parametrize(
    "config",
    [
        [],
        None,
        [{"network_name": ""}],
        [{"network_name": " BLUE"}],
        [{"network_name": "BLUE"}, {"network_name": "BLUE"}],
        [{"network_name": "BLUE", "attach": [{"switch_id": "SERIAL1"}]}],
        [{"network_name": "BLUE", "detach": [{"switch_id": "SERIAL1"}]}],
        [{"network_name": "BLUE", "child_fabric_config": [{"name": "child"}]}],
    ],
)
def test_implicit_ambiguous_or_attachment_scope_rejects_without_requests(config):
    coordinator = _Coordinator()
    with pytest.raises(ValueError):
        OverlayDeletionFinalizer(coordinator, "network").run(dict(_args(), config=config), _strategy())
    assert coordinator.requests == coordinator.calls == []


@pytest.mark.parametrize("flag", ["is_parent", "is_child", "is_multicluster", "is_multisite"])
def test_unsupported_topology_rejects_without_requests(flag):
    coordinator = _Coordinator()
    strategy = _strategy()
    setattr(strategy, flag, True)
    with pytest.raises(ValueError, match="standalone Manage"):
        OverlayDeletionFinalizer(coordinator, "network").run(_args(), strategy)
    assert coordinator.requests == []


def test_wrong_state_rejects_without_requests():
    coordinator = _Coordinator()
    with pytest.raises(ValueError, match="state=deleted"):
        OverlayDeletionFinalizer(coordinator, "network").run(dict(_args(), state="merged"), _strategy())
    assert coordinator.requests == []


@pytest.mark.parametrize("resource", ["network", "vrf"])
def test_definition_api_error_propagates_and_restores_module_parameters(resource):
    coordinator = _Coordinator(resource)
    coordinator.crud_error = "ND rejected definition deletion"
    with pytest.raises(RuntimeError, match="ND rejected"):
        OverlayDeletionFinalizer(coordinator, resource).run(_args(resource), _strategy())
    assert coordinator.params_restored is True
    assert coordinator.requests == []


@pytest.mark.parametrize("resource", ["network", "vrf"])
def test_failed_crud_result_does_not_claim_success_or_retry_deployment(resource):
    coordinator = _Coordinator(resource)
    coordinator.result_failure = True
    result = OverlayDeletionFinalizer(coordinator, resource).run(_args(resource), _strategy())
    assert result["failed"] is True
    assert result["deletion_finalization"]["deletion_operations_succeeded"] is False
    assert result["deletion_finalization"]["detach_attempts"] == result["deletion_finalization"]["deployment_attempts"] == 0
    assert coordinator.requests == []


def test_dependency_failure_prevents_definition_crud_and_restores_params():
    coordinator = _Coordinator("vrf")
    coordinator.dependency_error = "Network still references BLUE"
    with pytest.raises(ValueError, match="Network still references"):
        OverlayDeletionFinalizer(coordinator, "vrf").run(_args("vrf"), _strategy())
    assert coordinator.deleted is False
    assert coordinator.calls == [("dependency_guard", ["BLUE"])]
    assert coordinator.params_restored is True


def test_duplicate_loaded_targets_reject_before_definition_crud():
    coordinator = _Coordinator()
    coordinator.loaded_names = ["BLUE", "BLUE"]
    with pytest.raises(ValueError, match="duplicate target"):
        OverlayDeletionFinalizer(coordinator, "network").run(_args(), _strategy())
    assert coordinator.calls == []
    assert coordinator.params_restored is True


def test_only_requested_loaded_names_are_used_for_dependency_checks():
    coordinator = _Coordinator()
    coordinator.loaded_names = ["FOREIGN", "BLUE"]
    result = OverlayDeletionFinalizer(coordinator, "network").run(_args(), _strategy())
    assert coordinator.calls[0] == ("dependency_guard", ["BLUE"])
    assert result["deletion_finalization"]["existing_before"] == ["BLUE"]


def test_request_receipt_changes_with_exact_requested_scope():
    coordinator = _Coordinator()
    first = OverlayDeletionFinalizer(coordinator, "network").run(_args(), _strategy())
    coordinator = _Coordinator()
    second = OverlayDeletionFinalizer(coordinator, "network").run(dict(_args(), config=[{"network_name": "GREEN"}]), _strategy())
    assert first["deletion_finalization"]["request_sha256"] != second["deletion_finalization"]["request_sha256"]


def test_network_finalize_dispatch_does_not_enter_normal_detach_or_deploy():
    coordinator = Mock()
    strategy = Mock()
    with patch("ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_state_machine.OverlayDeletionFinalizer") as factory:
        factory.return_value.run.return_value = {"changed": True}
        result = NetworkStateMachine(coordinator).run_deleted(_args(), strategy)
    assert result["changed"] is True
    factory.assert_called_once_with(coordinator, "network")
    coordinator._apply_deleted_attachment_phase.assert_not_called()
    coordinator._build_delete_deploy_payloads.assert_not_called()


def test_network_module_exposes_opt_in_mode_and_preserves_default():
    captured = {}

    class Module:
        params = {"fabric_name": "fab1", "state": "gathered", "config": []}

        def __init__(self, **kwargs):
            captured.update(kwargs["argument_spec"])

        def exit_json(self, **kwargs):
            pass

    with (
        patch.object(nd_manage_networks, "AnsibleModule", Module),
        patch.object(nd_manage_networks, "require_pydantic"),
        patch.object(nd_manage_networks, "NetworkWorkflowCoordinator") as factory,
    ):
        factory.return_value.run.return_value = {"changed": False}
        nd_manage_networks.main()
    assert captured["deletion_mode"] == {"type": "str", "default": "standard", "choices": ["standard", "finalize"]}
