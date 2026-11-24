# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Public workflow regressions for interrupted POAP recovery and wait results."""

# pylint: disable=protected-access
from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.manage_switches import nd_switch_resources as resources
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.modules import nd_manage_switches as module_entry
from ansible_collections.cisco.nd.tests.unit.module_utils import test_nd_switch_resources as fixtures


def _recovery_config(operation, state):
    options = {"poap": {"serial_number": "REAL1", "hostname": "real1-host"}}
    if operation == "swap":
        options["preprovision"] = {
            "serial_number": "PRE1",
            "model": "N9K-C93180YC-EX",
            "version": "10.3(1)",
            "hostname": "pre1-host",
            "config_data": {"models": ["N9K-C93180YC-EX"], "gateway": "192.0.2.1/24"},
        }
    return fixtures._cfg(state=state, **options)


@pytest.mark.parametrize("operation", ["poap", "swap"])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("candidate", [False, True])
def test_check_mode_matches_normal_recovery_plan_without_waits_or_writes(operation, state, candidate):
    """A complete read-only observation forecasts repair of the existing identity."""
    cfg = _recovery_config(operation, state)
    selected = []
    for check_mode in (False, True):
        resource = fixtures._resource(
            state=state,
            config=[cfg.to_config()],
            check_mode=check_mode,
            existing=[fixtures._sw("192.0.2.10", "REAL1", discovery_status="unreachable")],
        )
        resource.bootstrap_cache = fixtures.StaticBootstrapCache({"REAL1": fixtures._bootstrap_entry("REAL1")} if candidate else {})
        dispatched = []
        resource.poap_handler = SimpleNamespace(handle=lambda *args: dispatched.append(args))
        resource.manage_state()
        selected.append(len(resource._plan.to_bootstrap + resource._plan.to_swap))
        assert resource.bootstrap_cache.refreshes == 1
        assert not resource.nd.calls
        if check_mode:
            assert not dispatched
            forecast = resource._build_check_mode_output()
            assert forecast["changed"] is candidate
            assert len(forecast["after"]) == 1
            assert forecast["after"][0]["seed_ip"] == "192.0.2.10"
            if candidate:
                assert [entry["_action"] for entry in forecast["diff"]] == ["updated"]
    assert selected == [int(candidate), int(candidate)]


@pytest.mark.parametrize("operation", ["poap", "swap"])
def test_normal_recovery_imports_once_without_replacing_the_completed_serial(operation):
    """Positive bootstrap evidence resumes the import, not the serial replacement."""
    cfg = _recovery_config(operation, "merged")
    resource = fixtures._resource(config=[cfg.to_config()], existing=[fixtures._sw("192.0.2.10", "REAL1", discovery_status="unreachable")])
    resource.bootstrap_cache = fixtures.StaticBootstrapCache({"REAL1": fixtures._bootstrap_entry("REAL1")})
    resource.poap_handler = resources.POAPHandler(resource.ctx, resource.fabric_ops, fixtures.RecordingWait(), resource.bootstrap_cache)
    resource.manage_state()
    assert [entry["action"] for entry in resource.results.metadata] == ["bootstrap"]
    assert len(resource.nd.calls) == 1


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("operation", ["poap", "swap"])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("target_page", [0, 1, 2])
def test_manage_state_uses_complete_paginated_snapshot_for_recovery(state, operation, check_mode, target_page):
    """First/later-page candidates have identical plans after complete observation."""
    cfg = _recovery_config(operation, state)
    resource = fixtures._resource(
        state=state,
        config=[cfg.to_config()],
        check_mode=check_mode,
        existing=[fixtures._sw("192.0.2.10", "REAL1", discovery_status="unreachable")],
    )
    nd = fixtures.FakeND()
    nd.module = resource.module
    paths = []

    def read(path, *, verb, data=None):  # pylint: disable=unused-argument
        assert verb == HttpVerbEnum.GET
        paths.append(path)
        offset = int(parse_qs(urlsplit(path).query)["offset"][0])
        serial = "REAL1" if offset + 1 == target_page else "OTHER" + str(offset)
        return {"switches": [fixtures._bootstrap_entry(serial)], "meta": {"counts": {"total": 2, "remaining": 1 - offset}}}

    nd.request = read
    resource.nd = nd
    resource.ctx.nd = nd
    resource.bootstrap_cache = resources.BootstrapCache(nd, "FAB1", resource.log)
    dispatched = []
    resource.poap_handler = SimpleNamespace(handle=lambda *args: dispatched.append(args))
    resource.manage_state()
    assert len(paths) == 2
    assert len(resource._plan.to_bootstrap + resource._plan.to_swap) == int(bool(target_page))
    if check_mode:
        assert not dispatched
        forecast = resource._build_check_mode_output()
        assert forecast["changed"] is bool(target_page)
        assert len(forecast["after"]) == 1


@pytest.mark.parametrize("check_mode", [False, True])
def test_healthy_physical_identity_does_not_query_bootstrap_or_repeat_import(check_mode):
    """Ordinary replay remains inventory-idempotent without a candidate read."""
    cfg = _recovery_config("swap", "merged")
    resource = fixtures._resource(config=[cfg.to_config()], check_mode=check_mode, existing=[fixtures._sw("192.0.2.10", "REAL1")])
    resource.manage_state()
    assert not resource.nd.calls
    assert resource._build_check_mode_output()["changed"] is False


@pytest.mark.parametrize("state", ["merged", "replaced"])
def test_recovery_forecast_preserves_unrelated_inventory_and_updates_the_existing_role(state):
    """An import repair is neither an orphan removal nor a duplicate add."""
    cfg = fixtures._cfg(state=state, role="spine", poap={"serial_number": "REAL1", "hostname": "real1-host"})
    resource = fixtures._resource(
        state=state,
        config=[cfg.to_config()],
        check_mode=True,
        existing=[fixtures._sw("192.0.2.10", "REAL1", discovery_status="unreachable"), fixtures._sw("192.0.2.99", "OTHER1")],
    )
    resource.bootstrap_cache = fixtures.StaticBootstrapCache({"REAL1": fixtures._bootstrap_entry("REAL1")})
    resource.manage_state()
    forecast = resource._build_check_mode_output()
    assert len(forecast["after"]) == 2
    assert {row["seed_ip"] for row in forecast["after"]} == {"192.0.2.10", "192.0.2.99"}
    assert next(row for row in forecast["after"] if row["seed_ip"] == "192.0.2.10")["role"] == "spine"
    assert [row["_action"] for row in forecast["diff"]] == ["updated"]


class ModuleFinished(SystemExit):
    """Mirror Ansible's fail_json/exit_json SystemExit boundary."""

    def __init__(self, result):
        super().__init__(result)
        self.result = result


class BoundaryModule:
    """Minimal module preserving real termination behavior and public inputs."""

    check_mode = False

    def __init__(self, config, state):
        self.params = {
            "config": config,
            "fabric": "FAB1",
            "state": state,
            "output_level": "normal",
            "config_actions": {"save": False, "deploy": False},
            "bootstrap_wait": {"timeout": 0, "interval": 5},
        }

    def fail_json(self, **kwargs):
        raise ModuleFinished(kwargs)

    def exit_json(self, **kwargs):
        raise AssertionError(f"Unexpected successful module exit: {kwargs}")


class EmptyBootstrapController(fixtures.FakeND):
    """Successful mutations followed by an empty, valid bootstrap collection."""

    def __init__(self, read_failure=False):
        super().__init__()
        self.read_failure = read_failure

    def request(self, path=None, *, verb, data=None):
        read = verb == HttpVerbEnum.GET
        if read and self.read_failure is True:
            raise RuntimeError("Bootstrap snapshot could not be completed")
        self._data = {"switches": []} if read else {}
        if read and self.read_failure == "pagination":
            offset = int(parse_qs(urlsplit(path).query)["offset"][0])
            self._data = {
                "switches": [fixtures._bootstrap_entry("OTHER" + str(offset))],
                "meta": {"counts": {"total": 2 + offset, "remaining": 1 - offset}},
            }
        self._response_current = {"DATA": self._data, "MESSAGE": "OK", "RETURN_CODE": 200}
        self._result_current = {"success": True, "changed": not read}
        return super().request(path=path, verb=verb, data=data)


@pytest.mark.parametrize("accepted", ["update_role", "delete", None])
@pytest.mark.parametrize("read_failure", [False, True, "pagination"])
def test_real_module_boundary_preserves_accepted_changes_when_bootstrap_wait_fails(monkeypatch, accepted, read_failure):
    """Failure remains a failure after prior role updates/removals are accepted."""
    state = "replaced" if accepted == "delete" else "merged"
    cfg = fixtures._cfg("192.0.2.20", state=state, poap={"serial_number": "REAL2", "hostname": "real2-host"})
    config = [cfg.to_config()]
    existing = []
    if accepted == "update_role":
        config.insert(0, fixtures._cfg("192.0.2.10", role="spine", poap={"serial_number": "REAL1", "hostname": "real1-host"}).to_config())
        existing = [fixtures._sw("192.0.2.10", "REAL1", role="leaf")]
    elif accepted == "delete":
        existing = [fixtures._sw("192.0.2.20", "OLD1", discovery_status="unreachable")]
    module = BoundaryModule(config, state)
    controller = EmptyBootstrapController(read_failure)
    controller.module = module
    captured = []

    def resource_factory(nd, results, logger=None):
        resource = fixtures._resource(state=state, config=config, existing=existing, results=results)
        resource.module = module
        resource.nd = nd
        resource.ctx.nd = nd
        resource.log = logger or resource.log
        resource.bootstrap_cache = resources.BootstrapCache(nd, "FAB1", resource.log)
        resource.fabric_ops = resources.SwitchFabricOps(resource.ctx, SimpleNamespace())
        resource.poap_handler = resources.POAPHandler(resource.ctx, resource.fabric_ops, fixtures.RecordingWait(), resource.bootstrap_cache)
        captured.append(resource)
        return resource

    monkeypatch.setattr(module_entry, "AnsibleModule", lambda **kwargs: module)
    monkeypatch.setattr(module_entry, "NDModule", lambda supplied: controller)
    monkeypatch.setattr(module_entry, "NDSwitchResourceModule", resource_factory)
    monkeypatch.setattr(module_entry, "Log", lambda: SimpleNamespace(commit=lambda: None))
    with pytest.raises(ModuleFinished) as outcome:
        module_entry.main()
    result = outcome.value.result
    assert ("Cannot read complete POAP candidates" if read_failure else "Timed out after 0 seconds") in result["msg"]
    assert result["failed"] is True
    assert result["changed"] is (accepted is not None)
    assert [row["action"] for row in result["metadata"]] == ([accepted] if accepted else [])
    assert result["accepted_operations"] == ([{"action": accepted, "sequence_number": 1, "changed": True}] if accepted else [])
    assert result["accepted_operations_truncated"] is False
    failure = {"fabric_name": "FAB1", "timeout": 0}
    failure.update({"reason": "observation_failed", "requested_serials": ["REAL2"]} if read_failure else {"missing_serials": ["REAL2"]})
    assert result["bootstrap_wait_failure"] == failure
    assert "after" not in result and "rollback" not in result
    assert all("importBootstrap" not in row["path"] for row in controller.calls)
    if read_failure == "pagination":
        assert len([row for row in controller.calls if row["verb"] == HttpVerbEnum.GET]) == 2
    assert captured


def test_failed_refresh_discards_previous_complete_bootstrap_snapshot(monkeypatch):
    """A prior positive observation cannot survive a failed fresh observation."""
    controller = fixtures.FakeND()
    calls = []

    def read(nd, fabric, log):  # pylint: disable=unused-argument
        calls.append(True)
        if len(calls) == 2:
            raise resources.SwitchOperationError("Later bootstrap page is inconsistent")
        serial = "OLD1" if len(calls) == 1 else "NEW1"
        return [fixtures._bootstrap_entry(serial)]

    monkeypatch.setattr(resources, "query_bootstrap_switches", read)
    cache = resources.BootstrapCache(controller, "FAB1", fixtures.ListLogger())
    assert set(cache.get_index()) == {"OLD1"}
    with pytest.raises(resources.SwitchOperationError, match="inconsistent"):
        cache.get_index(refresh=True)
    assert set(cache.get_index()) == {"NEW1"}
    assert len(calls) == 3


def test_results_accepted_changes_are_registered_changed_successes_and_are_copied():
    """A diagnostic summary never guesses acceptance from a payload or diff."""
    results = Results()
    for action, changed, success, operation in (
        ("discover", True, True, OperationType.QUERY),
        ("update_role", True, True, OperationType.UPDATE),
        ("delete", True, False, OperationType.DELETE),
        ("bootstrap", False, True, OperationType.CREATE),
    ):
        results.action = action
        results.operation_type = operation
        results.result_current = {"success": success, "changed": changed}
        results.response_current = {"RETURN_CODE": 200}
        results.register_api_call()
    accepted = results.accepted_changes
    assert len(accepted) == 1 and accepted[0]["action"] == "update_role"
    accepted[0]["action"] = "tampered"
    assert results.accepted_changes[0]["action"] == "update_role"


def test_wait_failure_summary_is_bounded_and_excludes_unknown_action_text():
    """Return only known categorical evidence, with honest truncation metadata."""
    results = Results()
    for unused_index in range(102):
        results.action = "update_role"
        results.operation_type = OperationType.UPDATE
        results.result_current = {"success": True, "changed": True}
        results.response_current = {"RETURN_CODE": 200, "DATA": {"password": "secret-canary"}}
        results.register_api_call()
    results.action = "secret-canary"
    results.operation_type = OperationType.CREATE
    results.result_current = {"success": True, "changed": True}
    results.response_current = {"RETURN_CODE": 200}
    results.register_api_call()
    module = BoundaryModule([], "merged")
    error = resources.BootstrapWaitError("FAB1", 0, ["REAL1"])
    with pytest.raises(ModuleFinished) as outcome:
        module_entry._fail_bootstrap_wait(module, results, error)
    summary = outcome.value.result["accepted_operations"]
    assert len(summary) == 100
    assert outcome.value.result["accepted_operations_truncated"] is True
    assert all(set(row) == {"action", "sequence_number", "changed"} and row["action"] == "update_role" for row in summary)
    assert "secret-canary" not in str(summary)
