# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""VRF finalization matches typed CRUD discovery and retains exact delete scope."""

from copy import deepcopy
from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.overlay_deletion_finalizer import (
    OverlayDeletionFinalizer,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import (
    StandaloneVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_config_utils import (
    vrf_name_filter,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrfs import (
    NDVrfOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import (
    MockAnsibleModule,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_overlay_deletion_finalizer import (
    _Attachments,
    _Coordinator,
)


class _TypedCoordinator(_Coordinator):
    _vrf_name_filter = staticmethod(vrf_name_filter)

    def __init__(self, names, *, missing_fresh=False):
        super().__init__(resource="vrf")
        self.names = names
        self.rows = {name: {"fabricName": "fab1", "vrfName": name, "vrfStatus": "notApplicable"} for name in ["FOREIGN_VRF", *names]}
        self.paths = []
        self.removed = []
        self.get_count = 0
        self.missing_fresh = missing_fresh
        self.strategy = StandaloneVrfStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
        self.module = MockAnsibleModule()
        # The coordinator supplies composite fabric/name selectors to CRUD.
        self.module.params = {
            "fabric_name": "fab1",
            "state": "deleted",
            "config": [{"vrf_name": name, "fabric_name": "fab1"} for name in names],
        }
        self.orchestrator = NDVrfOrchestrator(
            rest_send=RestSend(dict(self.module.params, check_mode=False)),
            strategy=self.strategy,
        )
        object.__setattr__(self.orchestrator, "_request", self._transport)

    def _factory(self, _args, _strategy):
        return self.orchestrator, None

    _new_vrf_orchestrator = _factory

    def _new_state_machine(self, _args, _strategy):
        self.state_machine = NDStateMachine(module=self.module, model_orchestrator=self.orchestrator)
        return self.state_machine, self.module.params["config"], "deleted"

    def _transport(self, **kwargs):
        path = kwargs["path"]
        self.paths.append((str(kwargs["verb"]), path, deepcopy(kwargs.get("data"))))
        if "/vrfActions/remove" in path:
            names = kwargs["data"]["vrfNames"]
            assert set(names) <= set(self.names)
            self.removed.extend(names)
            for name in names:
                self.rows.pop(name, None)
            return {"results": [{"vrfName": name, "status": "success"} for name in names]}
        assert "/vrfs" in path
        self.get_count += 1
        query = parse_qs(urlsplit(path).query)
        selector = query.get("filter", [None])[0]
        # Replay ND's fielded-OR result while preserving ordinary single-name
        # filtering. Multi-name CRUD already uses an unfiltered discovery query.
        if selector and " OR " in selector and "vrfName:" in selector:
            rows = []
        elif selector:
            rows = [row for row in self.rows.values() if selector == "vrfName:" + row["vrfName"]]
        else:
            rows = list(self.rows.values())
        if self.missing_fresh and self.get_count >= 2:
            rows = [row for row in rows if row["vrfName"] != self.names[0]]
        offset = int(query.get("offset", [0])[0])
        size = int(query.get("max", [500])[0])
        page = deepcopy(rows[offset : offset + size])
        return {
            "vrfs": page,
            "meta": {
                "counts": {
                    "total": len(rows),
                    "remaining": len(rows) - offset - len(page),
                }
            },
        }

    def _request(self, **kwargs):
        if kwargs["path"].startswith("attachments:"):
            return {"attachments": [], "meta": {"counts": {"total": 0, "remaining": 0}}}
        return self._transport(**kwargs)

    def _format_state_machine_output(self, sm):
        return {
            "changed": bool(sm.removed),
            "before": sm.before.to_ansible_config(),
            "after": sm.existing.to_ansible_config(),
        }


def _run(coordinator):
    coordinator.attachments._attachments_query_endpoint_cls = lambda _strategy: _Attachments
    original_make = coordinator.orchestrator._make_endpoint
    object.__setattr__(
        coordinator.orchestrator,
        "_make_endpoint",
        lambda endpoint_type, **kwargs: (_Attachments() if endpoint_type is _Attachments else original_make(endpoint_type, **kwargs)),
    )
    original_transport = coordinator.orchestrator._request
    object.__setattr__(
        coordinator.orchestrator,
        "_request",
        lambda **kwargs: (coordinator._request(**kwargs) if kwargs["path"].startswith("attachments:") else original_transport(**kwargs)),
    )
    args = dict(coordinator.module.params, deletion_mode="finalize")
    return OverlayDeletionFinalizer(coordinator, "vrf").run(args, coordinator.strategy)


@pytest.mark.parametrize(
    "names,page_size",
    [(["BLUE"], 500), (["BLUE", "GREEN"], 500), (["BLUE", "GREEN"], 1)],
)
def test_real_typed_vrf_crud_and_fresh_finalization_use_compatible_exact_scope(names, page_size, monkeypatch):
    monkeypatch.setattr(OverlayDeletionFinalizer, "page_size", page_size)
    coordinator = _TypedCoordinator(names)
    result = _run(coordinator)
    assert set(coordinator.removed) == set(names)
    assert set(coordinator.rows) == {"FOREIGN_VRF"}
    assert {key[0] for key in coordinator.state_machine.removed.keys()} == set(names)
    receipt = result["deletion_finalization"]
    assert receipt["definition_absence_verified"] is True
    assert receipt["detach_attempts"] == receipt["deployment_attempts"] == 0
    queries = [parse_qs(urlsplit(path).query) for _verb, path, _data in coordinator.paths if "/vrfs" in path]
    expected = None if len(names) > 1 else vrf_name_filter(names)
    assert all(query.get("filter", [None])[0] == expected for query in queries)
    if page_size == 1:
        assert {int(query.get("offset", [0])[0]) for query in queries} >= {0, 1, 2}
    assert not any("deploy" in path.lower() or "detach" in path.lower() for _verb, path, _data in coordinator.paths)


def test_real_fresh_vrf_target_change_still_rejects_before_definition_crud():
    coordinator = _TypedCoordinator(["BLUE", "GREEN"], missing_fresh=True)
    with pytest.raises(ValueError, match="target set changed"):
        _run(coordinator)
    assert coordinator.removed == []
    assert set(coordinator.rows) == {"BLUE", "GREEN", "FOREIGN_VRF"}


def test_controller_fielded_or_regression_rejects_the_previous_discovery_path(
    monkeypatch,
):
    def previous_definitions(finalizer, orchestrator, strategy, names):
        def fetch(offset, size):
            endpoint = orchestrator._make_endpoint(strategy.vrfs_get_cls())
            endpoint.endpoint_params.filter = vrf_name_filter(names)
            endpoint.endpoint_params.max = size
            endpoint.endpoint_params.offset = offset
            return orchestrator._request(path=endpoint.path, verb=endpoint.verb, not_found_ok=False)

        return [row for row in finalizer._collect(fetch, "vrfs", finalizer._definition_identity) if row["vrfName"] in names]

    # Genuine CRUD discovers both targets, but the old finalizer's fielded OR
    # sees neither. The same safety guard prevents any delete from that mismatch.
    monkeypatch.setattr(OverlayDeletionFinalizer, "_definitions", previous_definitions)
    coordinator = _TypedCoordinator(["BLUE", "GREEN"])
    with pytest.raises(ValueError, match="target set changed"):
        _run(coordinator)
    assert coordinator.removed == []
    assert set(coordinator.rows) == {"BLUE", "GREEN", "FOREIGN_VRF"}
