# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Finalization uses the established Network batch filter with exact local scope."""

from copy import deepcopy
from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.networks import NDNetworkOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.overlay_deletion_finalizer import OverlayDeletionFinalizer
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import StandaloneNetworkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_overlay_deletion_finalizer import _Attachments, _Coordinator


class _TypedCoordinator(_Coordinator):
    _network_name_filter = staticmethod(NDNetworkOrchestrator._network_name_filter)

    def __init__(self, names, *, missing_fresh=False):
        super().__init__()
        self.names = names
        self.rows = {name: {"networkName": name, "networkStatus": "notApplicable"} for name in [*names, "FOREIGN_NET"]}
        self.paths = []
        self.removed = []
        self.get_count = 0
        self.missing_fresh = missing_fresh
        self.strategy = StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
        self.module = MockAnsibleModule()
        self.module.params = {"fabric_name": "fab1", "state": "deleted", "config": [{"network_name": name} for name in names]}
        self.orchestrator = NDNetworkOrchestrator(rest_send=RestSend(dict(self.module.params, check_mode=False)), strategy=self.strategy)
        object.__setattr__(self.orchestrator, "_request", self._transport)

    def _factory(self, _args, _strategy):
        return self.orchestrator, None

    _new_network_orchestrator = _factory

    def _new_state_machine(self, _args, _strategy):
        self.state_machine = NDStateMachine(module=self.module, model_orchestrator=self.orchestrator)
        return self.state_machine, self.module.params["config"], "deleted"

    def _transport(self, **kwargs):
        path = kwargs["path"]
        self.paths.append((str(kwargs["verb"]), path, deepcopy(kwargs.get("data"))))
        if "/networkActions/remove" in path:
            names = kwargs["data"]["networkNames"]
            assert set(names) <= set(self.names)
            self.removed.extend(names)
            for name in names:
                self.rows.pop(name, None)
            return {"results": [{"networkName": name, "status": "success"} for name in names]}
        assert "/networks" in path
        self.get_count += 1
        query = parse_qs(urlsplit(path).query)
        selector = query.get("filter", [None])[0]
        # Replay the controller's fielded-OR incompatibility; the established
        # unfielded search may also match unrelated rows, requiring local scope.
        rows = [] if selector and " OR " in selector and "networkName:" in selector else list(self.rows.values())
        if self.missing_fresh and self.get_count >= 2:
            rows = [row for row in rows if row["networkName"] != self.names[0]]
        offset = int(query.get("offset", [0])[0])
        size = int(query.get("max", [500])[0])
        page = deepcopy(rows[offset : offset + size])
        return {"networks": page, "meta": {"counts": {"total": len(rows), "remaining": len(rows) - offset - len(page)}}}

    def _request(self, **kwargs):
        # Existing helper attachment endpoint is an isolated read-only stub.
        if kwargs["path"].startswith("attachments:"):
            return {"attachments": [], "meta": {"counts": {"total": 0, "remaining": 0}}}
        return self._transport(**kwargs)

    def _format_state_machine_output(self, sm):
        return {"changed": bool(sm.removed), "before": sm.before.to_ansible_config(), "after": sm.existing.to_ansible_config()}


def _run(coordinator):
    coordinator.attachments._attachments_query_endpoint_cls = lambda _strategy: _Attachments
    original_make = coordinator.orchestrator._make_endpoint
    object.__setattr__(
        coordinator.orchestrator,
        "_make_endpoint",
        lambda endpoint_type, **kwargs: _Attachments() if endpoint_type is _Attachments else original_make(endpoint_type, **kwargs),
    )
    original_transport = coordinator.orchestrator._request
    object.__setattr__(
        coordinator.orchestrator,
        "_request",
        lambda **kwargs: coordinator._request(**kwargs) if kwargs["path"].startswith("attachments:") else original_transport(**kwargs),
    )
    args = dict(coordinator.module.params, deletion_mode="finalize")
    return OverlayDeletionFinalizer(coordinator, "network").run(args, coordinator.strategy)


@pytest.mark.parametrize("names", [["BLUE_NET"], ["BLUE_NET", "GREEN_NET"]])
def test_real_typed_crud_and_fresh_finalization_use_compatible_exact_scope(names):
    coordinator = _TypedCoordinator(names)
    result = _run(coordinator)
    assert set(coordinator.removed) == set(names)
    assert set(coordinator.rows) == {"FOREIGN_NET"}
    assert set(coordinator.state_machine.removed.keys()) == set(names)
    assert result["deletion_finalization"]["definition_absence_verified"] is True
    assert result["deletion_finalization"]["deployment_attempts"] == 0
    filters = [parse_qs(urlsplit(path).query).get("filter", [None])[0] for _verb, path, _data in coordinator.paths if "/networks" in path]
    expected = NDNetworkOrchestrator._network_names_unfielded_filter(names) if len(names) > 1 else NDNetworkOrchestrator._network_name_filter(names)
    assert all(selector == expected for selector in filters)
    assert not any("deploy" in path.lower() for _verb, path, _data in coordinator.paths)


def test_fresh_target_change_still_rejects_before_actual_definition_crud():
    coordinator = _TypedCoordinator(["BLUE_NET", "GREEN_NET"], missing_fresh=True)
    with pytest.raises(ValueError, match="target set changed"):
        _run(coordinator)
    assert coordinator.removed == []
    assert set(coordinator.rows) == {"BLUE_NET", "GREEN_NET", "FOREIGN_NET"}
