# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Finalization requires observed completed detach and never deploys."""

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

    _ensure_networks_have_no_networks = _ensure
    _ensure_vrfs_have_no_networks = _ensure

    def _new_state_machine(self, _args, strategy):
        names = self.loaded_names if self.loaded_names is not None else [row[self.resource + "Name"] for row in self.definitions]
        existing = [SimpleNamespace(**{self.resource + "_name": name}) for name in names]

        def manage_state():
            self.calls.append(("definition_crud", strategy.fabric_name))
            if not self.module.check_mode:
                self.deleted = True

        return SimpleNamespace(existing=existing, manage_state=manage_state), [], "deleted"

    @staticmethod
    def _restore_state_machine_params(_config, _state):
        pass

    def _format_state_machine_output(self, _sm):
        return {"changed": bool(self.definitions), "before": deepcopy(self.definitions), "after": []}

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
def test_terminal_detach_finalizes_with_only_queries_and_definition_crud(resource):
    coordinator = _Coordinator(resource)
    result = OverlayDeletionFinalizer(coordinator, resource).run(_args(resource), _strategy())
    assert coordinator.calls == [("dependency_guard", ["BLUE"]), ("definition_crud", "fab1")]
    assert [verb for _path, verb, _data in coordinator.requests] == ["GET", "POST", "GET"]
    assert coordinator.requests[1][2] == {resource + "Names": ["BLUE"]}
    proof = result["deletion_finalization"]
    assert proof["definition_absence_verified"] is True
    assert proof["detach_attempts"] == proof["deployment_attempts"] == 0
    assert proof["existing_before"] == proof["names"] == ["BLUE"]
    assert len(proof["request_sha256"]) == 64
    assert result["fabric_type"] == "standalone"
    assert result["workflow"] == f"Standalone Fabric {resource.capitalize()} Definition Finalization"


@pytest.mark.parametrize("resource", ["network", "vrf"])
def test_check_mode_reads_and_plans_without_deleting_or_claiming_absence(resource):
    coordinator = _Coordinator(resource, check_mode=True)
    result = OverlayDeletionFinalizer(coordinator, resource).run(_args(resource), _strategy())
    assert coordinator.deleted is False
    assert len(coordinator.requests) == 2
    assert result["deletion_finalization"]["definition_absence_verified"] is None


@pytest.mark.parametrize("status", ["pending", "failed", "outOfSync", "deployed", "inSync", None, ""])
@pytest.mark.parametrize("resource", ["network", "vrf"])
def test_definition_not_proven_undeployed_rejects_before_crud(resource, status):
    coordinator = _Coordinator(resource)
    coordinator.definitions[0][resource + "Status"] = status
    with pytest.raises(ValueError, match="not detached"):
        OverlayDeletionFinalizer(coordinator, resource).run(_args(resource), _strategy())
    assert coordinator.calls == []
    assert coordinator.deleted is False


@pytest.mark.parametrize(
    "change",
    [
        {"attach": True},
        {"attach": "false"},
        {"status": "pending"},
        {"status": "failed"},
        {"status": "outOfSync"},
        {"status": None},
        {"status": "inSync"},
        {"configStatus": "pending"},
    ],
)
def test_attachment_unsafe_or_unknown_rejects_before_crud(change):
    coordinator = _Coordinator()
    coordinator.attachment_rows[0].update(change)
    with pytest.raises(ValueError, match="not explicitly detached"):
        OverlayDeletionFinalizer(coordinator, "network").run(_args(), _strategy())
    assert coordinator.calls == []


def test_complete_empty_attachment_collection_allows_never_attached_definition():
    coordinator = _Coordinator()
    coordinator.attachment_rows = []
    result = OverlayDeletionFinalizer(coordinator, "network").run(_args(), _strategy())
    assert result["deletion_finalization"]["definition_absence_verified"] is True


@pytest.mark.parametrize(
    "config",
    [
        [],
        None,
        [{"network_name": ""}],
        [{"network_name": " BLUE"}],
        [{"network_name": "BLUE"}, {"network_name": "BLUE"}],
        [{"network_name": "BLUE", "attach": [{"switch_id": "SERIAL1"}]}],
    ],
)
def test_implicit_ambiguous_or_attachment_scope_rejects_without_requests(config):
    coordinator = _Coordinator()
    args = dict(_args(), config=config)
    with pytest.raises(ValueError):
        OverlayDeletionFinalizer(coordinator, "network").run(args, _strategy())
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


def test_failed_post_delete_observation_preserves_truthful_failure_receipt():
    coordinator = _Coordinator()
    coordinator.read_failure_after_delete = True
    result = OverlayDeletionFinalizer(coordinator, "network").run(_args(), _strategy())
    assert coordinator.deleted is True
    assert result["changed"] is True
    assert result["failed"] is True
    assert result["deletion_finalization"]["definition_absence_verified"] is False
    assert "lost observation" in result["msg"]


def test_controller_acceptance_without_definition_absence_is_failure():
    coordinator = _Coordinator()
    coordinator.after = deepcopy(coordinator.definitions)
    result = OverlayDeletionFinalizer(coordinator, "network").run(_args(), _strategy())
    assert result["failed"] is True
    assert result["deletion_finalization"]["definition_absence_verified"] is False


def test_new_definition_after_crud_discovery_is_not_unconditionally_deleted():
    coordinator = _Coordinator()
    coordinator.loaded_names = []
    with pytest.raises(ValueError, match="target set changed"):
        OverlayDeletionFinalizer(coordinator, "network").run(_args(), _strategy())
    assert coordinator.calls == []
    assert coordinator.deleted is False


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"networks": None},
        {"networks": [], "items": []},
        {"networks": [], "meta": None},
        {"networks": [], "meta": {"counts": {"remaining": 1}}},
        {"networks": [{"networkName": "BLUE"}], "meta": {"counts": {"total": 2, "remaining": 0}}},
        {"networks": [{"networkName": "BLUE"}, {"networkName": "BLUE"}]},
    ],
)
def test_malformed_or_incomplete_collection_is_not_empty_success(response):
    finalizer = OverlayDeletionFinalizer(_Coordinator(), "network")
    with pytest.raises(ValueError):
        finalizer._collect(lambda _offset, _size: response, "networks", finalizer._definition_identity)


def test_pagination_uses_actual_rows_and_rejects_repeated_scope():
    finalizer = OverlayDeletionFinalizer(_Coordinator(), "network")
    pages = [
        {"networks": [{"networkName": "BLUE"}], "meta": {"counts": {"total": 2, "remaining": 1}}},
        {"networks": [{"networkName": "GREEN"}], "meta": {"counts": {"total": 2, "remaining": 0}}},
    ]
    calls = []

    def fetch(offset, size):
        calls.append((offset, size))
        return pages.pop(0)

    assert [row["networkName"] for row in finalizer._collect(fetch, "networks", finalizer._definition_identity)] == ["BLUE", "GREEN"]
    assert calls == [(0, 500), (1, 500)]


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
