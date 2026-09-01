# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `NDStateMachine` preflight wiring.

Verifies that `manage_state` invokes the orchestrator's preflight hooks at points that run BEFORE
mutation operations are gated by check mode:

- For create/update states (merged/replaced/overridden) `preflight_create` (policy-required-on-create, issue #350)
  runs FIRST, with only the create subset (proposed items not present in the existing inventory): it is local-only,
  so it fails before any API-backed preflight and before `existing` is mutated (PR #362 review). An already-present
  item re-submitted without a policy is not a create and is not validated.
- `preflight` (capability, PR #275 / issue #273) is then called over the proposed set, in check mode as well as
  normal mode, even though the underlying create/update calls are skipped in check mode.
- For `deleted` state neither preflight is called (removing configuration does not depend on capability, and a
  policy-less item is correct for delete -- the documented out-of-scope decision).

These drive the full `NDStateMachine.manage_state` path with a spy orchestrator instance, so they cover
the seam the per-method capability tests in `test_base_interface.py` cannot: the check-mode skip lives in
`NDStateMachine._execute_operation`, not in the orchestrator.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,unused-argument

from __future__ import absolute_import, annotations, division, print_function

from copy import deepcopy
from typing import ClassVar, Literal

__metaclass__ = type  # pylint: disable=invalid-name

import pytest
import ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine as state_machine_module
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.loopback_interface import LoopbackInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


class _SpyLoopbackOrchestrator(LoopbackInterfaceOrchestrator):
    """Spy subclass that records mutation/preflight calls instead of issuing HTTP.

    `query_all` returns an empty inventory (so `before`/`existing` start empty), and every CRUD plus
    `preflight` method records `(name, args)` on `self._calls`. This lets a test assert exactly which
    orchestrator entry points `manage_state` reached, without driving real REST traffic.
    """

    def model_post_init(self, __context) -> None:
        super().model_post_init(__context)
        self._calls: list[tuple] = []

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        return []

    def preflight(self, model_instances) -> None:
        self._calls.append(("preflight", list(model_instances)))

    def preflight_create(self, model_instances) -> None:
        # Record-only, mirroring the `preflight` spy: the guard's own logic is covered in
        # test_base_interface.py; here we assert only that manage_state reaches it with the create subset.
        self._calls.append(("preflight_create", list(model_instances)))

    def create(self, model_instance, **kwargs) -> ResponseType:
        self._calls.append(("create", model_instance))
        return {}

    def create_bulk(self, model_instances, **kwargs) -> ResponseType:
        self._calls.append(("create_bulk", list(model_instances)))
        return {}

    def update(self, model_instance, **kwargs) -> ResponseType:
        self._calls.append(("update", model_instance))
        return {}

    def delete(self, model_instance, **kwargs) -> None:
        self._calls.append(("delete", model_instance))

    def delete_bulk(self, model_instances, **kwargs) -> None:
        self._calls.append(("delete_bulk", list(model_instances)))


def _build_rest_send() -> RestSend:
    """Build a minimal `RestSend` for spy construction; the spy never exercises it."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(iter(()))

    rest_send = RestSend({"check_mode": False, "fabric_name": "fabric_1"})
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _build_module(state: str, check_mode: bool, config: list[dict]) -> MockAnsibleModule:
    """Build a `MockAnsibleModule` with the params `NDStateMachine` reads."""
    module = MockAnsibleModule()
    module.check_mode = check_mode
    module.no_log_values = set()
    module.params = {
        "state": state,
        "config": config,
        "output_level": "normal",
        "ignore_errors": False,
        "fabric_name": "fabric_1",
    }
    return module


def _build_state_machine(state: str, check_mode: bool, config: list[dict]) -> NDStateMachine:
    """Construct an `NDStateMachine` wired to the spy orchestrator instance."""
    spy = _SpyLoopbackOrchestrator(rest_send=_build_rest_send())
    module = _build_module(state=state, check_mode=check_mode, config=config)
    return NDStateMachine(module=module, model_orchestrator=spy)


_CONFIG = [{"switch_ip": "192.168.12.151", "interface_name": "loopback10"}]


def test_nd_state_machine_00100() -> None:
    """
    # Summary

    Verify `manage_state` runs `preflight` in check mode for `merged`, while the mutation (`create_bulk`)
    is skipped -- proving the preflight executes ahead of the check-mode gate in `_execute_operation`.

    ## Test

    - `state: merged`, `check_mode: True`, one proposed interface (new vs empty inventory)
    - `preflight_create` is recorded first over the create subset, then `preflight` (both run before the check-mode gate)
    - No `create`/`create_bulk` call is recorded (skipped in check mode)

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDBaseInterfaceOrchestrator.preflight()
    - NDBaseInterfaceOrchestrator.preflight_create()
    """
    instance = _build_state_machine(state="merged", check_mode=True, config=_CONFIG)

    with does_not_raise():
        instance.manage_state()

    calls = instance.model_orchestrator._calls
    names = [name for name, _ in calls]
    assert names == ["preflight_create", "preflight"]
    # preflight_create receives the single new item (create subset)
    assert [m.get_identifier_value() for m in calls[0][1]] == [("192.168.12.151", "loopback10")]
    assert len(calls[1][1]) == 1
    assert calls[1][1][0].get_identifier_value() == ("192.168.12.151", "loopback10")


def test_nd_state_machine_00110() -> None:
    """
    # Summary

    Verify `manage_state` runs `preflight` AND the mutation in NORMAL mode for `merged` -- the contrast to
    `test_nd_state_machine_00100` that proves the skipped mutation there is driven by check mode, not by an
    empty work set. `preflight` precedes the mutation.

    ## Test

    - `state: merged`, `check_mode: False`, one proposed interface
    - `preflight_create`, then `preflight`, then `create_bulk` are recorded (loopback supports bulk create)
    - Both preflights precede the mutation

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDStateMachine._manage_create_update_state()
    - NDBaseInterfaceOrchestrator.preflight()
    - NDBaseInterfaceOrchestrator.preflight_create()
    """
    instance = _build_state_machine(state="merged", check_mode=False, config=_CONFIG)

    with does_not_raise():
        instance.manage_state()

    names = [name for name, _ in instance.model_orchestrator._calls]
    assert names == ["preflight_create", "preflight", "create_bulk"]


def test_nd_state_machine_00120() -> None:
    """
    # Summary

    Verify `manage_state` does NOT call `preflight` for `deleted` state, documenting the out-of-scope decision:
    removing configuration does not depend on a switch's capability to host the interface type.

    ## Test

    - `state: deleted`, `check_mode: True`, one proposed interface
    - Neither `preflight` nor `preflight_create` is recorded (a policy-less item is correct for delete)
    - No mutation is recorded either (nothing matches the empty inventory, and check mode skips mutations)

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDStateMachine._manage_delete_state()
    """
    instance = _build_state_machine(state="deleted", check_mode=True, config=_CONFIG)

    with does_not_raise():
        instance.manage_state()

    names = [name for name, _ in instance.model_orchestrator._calls]
    assert "preflight" not in names
    assert "preflight_create" not in names


def test_nd_state_machine_00130() -> None:
    """
    # Summary

    Verify `manage_state` runs `preflight` over the proposed (desired-config) set for `overridden` state in check
    mode. The delete half of `overridden` (`_manage_override_deletions`) is intentionally not preflighted, matching
    the `deleted` scope decision.

    ## Test

    - `state: overridden`, `check_mode: True`, one proposed interface
    - `preflight` is recorded exactly once, with the proposed model, after the policy guard
    - No mutation is recorded (check mode)

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDBaseInterfaceOrchestrator.preflight()
    """
    instance = _build_state_machine(state="overridden", check_mode=True, config=_CONFIG)

    with does_not_raise():
        instance.manage_state()

    calls = instance.model_orchestrator._calls
    names = [name for name, _ in calls]
    assert names.count("preflight") == 1
    assert names[0] == "preflight_create"
    assert names[1] == "preflight"
    assert len(calls[1][1]) == 1


class _ExistingLoopbackSpy(_SpyLoopbackOrchestrator):
    """Spy whose inventory already contains loopback10, so a re-submitted policy-less item is not a create."""

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        return [
            {
                "switchIp": "192.168.12.151",
                "interfaceName": "loopback10",
                "interfaceType": "loopback",
            }
        ]


def test_nd_state_machine_00140() -> None:
    """
    # Summary

    Verify the create-only scoping of `preflight_create`: an interface already present in ND, re-submitted under
    `merged` without a policy, is NOT treated as a create and therefore is NOT passed to `preflight_create`. This is
    the invariant behind issue #350's decision to validate only creates -- a `merged` re-apply (or update) may
    legitimately omit a policy that already exists on the switch.

    ## Test

    - Inventory already contains `loopback10`; proposed re-sends the same identifier-only item under `merged`
    - The item diffs as `no_diff`, so `items_to_create` is empty
    - `preflight_create` is recorded with an empty list and `manage_state` does not raise

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDStateMachine._manage_create_update_state()
    - NDBaseInterfaceOrchestrator.preflight_create()
    """
    spy = _ExistingLoopbackSpy(rest_send=_build_rest_send())
    module = _build_module(state="merged", check_mode=False, config=_CONFIG)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with does_not_raise():
        instance.manage_state()

    calls = instance.model_orchestrator._calls
    preflight_create_calls = [args for name, args in calls if name == "preflight_create"]
    assert preflight_create_calls == [[]]
    # No create was attempted (item already existed)
    assert "create" not in [name for name, _ in calls]
    assert "create_bulk" not in [name for name, _ in calls]


class _RaisingPreflightCreateSpy(_SpyLoopbackOrchestrator):
    """Spy whose `preflight_create` raises for any create item, to assert the error halts the run before mutation."""

    def preflight_create(self, model_instances) -> None:
        self._calls.append(("preflight_create", list(model_instances)))
        if model_instances:
            raise RuntimeError("Cannot create interface(s) without a policy")


def test_nd_state_machine_00150() -> None:
    """
    # Summary

    Verify a `preflight_create` failure propagates out of `manage_state` BEFORE any mutation, even outside check mode.
    This guards the seam: the guard is wired ahead of the create/update execution loops, so a policy-less create fails
    fast with no `create`/`create_bulk` side effect. The raw `RuntimeError` from the guard is normalized to
    `NDStateMachineError` so module entrypoints that catch only `NDStateMachineError` still route through `fail_json`
    (PR #362 review).

    ## Test

    - `state: merged`, `check_mode: False`, one new policy-less item
    - `preflight_create` raises `RuntimeError`, which `manage_state` re-raises as `NDStateMachineError`
    - The original `RuntimeError` is preserved as the exception `__cause__`
    - No `create`/`create_bulk` call is recorded (failed before the mutation loop)

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDStateMachine._manage_create_update_state()
    - NDBaseInterfaceOrchestrator.preflight_create()
    """
    spy = _RaisingPreflightCreateSpy(rest_send=_build_rest_send())
    module = _build_module(state="merged", check_mode=False, config=_CONFIG)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with pytest.raises(NDStateMachineError, match=r"without a policy") as exc_info:
        instance.manage_state()

    assert isinstance(exc_info.value.__cause__, RuntimeError)

    names = [name for name, _ in instance.model_orchestrator._calls]
    assert "preflight_create" in names
    assert "create" not in names
    assert "create_bulk" not in names


def test_nd_state_machine_00160() -> None:
    """
    # Summary

    Verify a `preflight_create` failure leaves the module output unchanged: `changed` is `False` and `after` equals
    `before`, with no phantom item for the rejected create. Guards the PR #362 review finding where `self.existing`
    (aliased by `NDOutput` as `after`) was mutated before the policy guard ran, so a failed policy-less create
    reported `changed=True` and the never-created interface in `after`.

    ## Test

    - `state: merged`, `check_mode: False`, one new policy-less item; `preflight_create` raises `RuntimeError`
    - The error propagates from `manage_state` (normalized to `NDStateMachineError`)
    - `output.format()` reports `changed is False`, `before == []`, and `after == []` (no phantom item)

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDStateMachine._manage_create_update_state()
    - NDOutput.format()
    """
    spy = _RaisingPreflightCreateSpy(rest_send=_build_rest_send())
    module = _build_module(state="merged", check_mode=False, config=_CONFIG)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with pytest.raises(NDStateMachineError, match=r"without a policy"):
        instance.manage_state()

    output = instance.output.format()
    assert output["changed"] is False
    assert output["before"] == []
    assert output["after"] == []


class _CapabilityFailingSpy(_SpyLoopbackOrchestrator):
    """Spy whose capability `preflight` raises, while `preflight_create` delegates to the real policy guard.

    Models the PR #362 review scenario: a policy-less create targeting a switch that fails capability preflight.
    The local-only policy guard must win, so the user sees the clearer `config_data.network_os.policy` error rather
    than a switch/capability error.
    """

    def preflight(self, model_instances) -> None:
        self._calls.append(("preflight", list(model_instances)))
        raise RuntimeError("capability preflight failed: switch not capable")

    def preflight_create(self, model_instances) -> None:
        self._calls.append(("preflight_create", list(model_instances)))
        LoopbackInterfaceOrchestrator.preflight_create(self, model_instances)


def test_nd_state_machine_00170() -> None:
    """
    # Summary

    Verify the local-only policy guard runs BEFORE the API-backed capability preflight, so a policy-less create
    surfaces the policy error even when capability preflight would also fail (PR #362 review finding: the guard
    was previously masked by switch resolution / `capableSwitches` failures that ran first).

    ## Test

    - `state: merged`, `check_mode: False`, one new policy-less item
    - Capability `preflight` is rigged to raise, and `preflight_create` is the real `base_interface` guard
    - The policy error (`without a policy`) propagates (normalized to `NDStateMachineError`), not the capability error
    - The recorded call order shows `preflight_create` first

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDBaseInterfaceOrchestrator.preflight_create()
    """
    spy = _CapabilityFailingSpy(rest_send=_build_rest_send())
    module = _build_module(state="merged", check_mode=False, config=_CONFIG)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with pytest.raises(NDStateMachineError, match=r"without a policy"):
        instance.manage_state()

    names = [name for name, _ in instance.model_orchestrator._calls]
    assert names[0] == "preflight_create"


class _CapabilityOnlyFailingSpy(_SpyLoopbackOrchestrator):
    """Spy whose capability `preflight` raises while `preflight_create` is the record-only no-op inherited from
    `_SpyLoopbackOrchestrator`. Isolates the capability-preflight leg so a test can assert its bare `RuntimeError`
    is normalized to `NDStateMachineError` by `manage_state` -- the latent gap the PR #362 review wrap also closes.
    """

    def preflight(self, model_instances) -> None:
        self._calls.append(("preflight", list(model_instances)))
        raise RuntimeError("capability preflight failed: switch not capable")


def test_nd_state_machine_00180() -> None:
    """
    # Summary

    Verify a capability `preflight` failure is normalized to `NDStateMachineError` by `manage_state`, not left as a
    bare `RuntimeError`. Without this, nd_interface_svi and nd_interface_subinterface_managed/_unmanaged -- which catch
    only `NDStateMachineError` at their entrypoint -- would let a capability-preflight failure escape as an unhandled
    exception, bypassing `fail_json` and the structured before/after/changed output (PR #362 review, gmicol). The
    policy guard passes here (record-only spy) so the capability leg is the raising one, and no mutation runs.

    ## Test

    - `state: merged`, `check_mode: False`, one new item; `preflight_create` is the record-only no-op, capability
      `preflight` raises `RuntimeError`
    - `manage_state` re-raises as `NDStateMachineError` carrying the capability message, with the `RuntimeError` as
      `__cause__`
    - No `create`/`create_bulk` call is recorded (failed before the mutation loop)

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDBaseInterfaceOrchestrator.preflight()
    """
    spy = _CapabilityOnlyFailingSpy(rest_send=_build_rest_send())
    module = _build_module(state="merged", check_mode=False, config=_CONFIG)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with pytest.raises(NDStateMachineError, match=r"capability preflight failed") as exc_info:
        instance.manage_state()

    assert isinstance(exc_info.value.__cause__, RuntimeError)

    names = [name for name, _ in instance.model_orchestrator._calls]
    assert "create" not in names
    assert "create_bulk" not in names


class _FilterModel(NDBaseModel):
    """Small opted-in model used to exercise state-machine routing."""

    identifiers: ClassVar[list[str] | None] = ["name"]
    identifier_strategy: ClassVar[Literal["single"]] = "single"
    supports_gathered_filtering: ClassVar[bool] = True

    name: str
    value: int | None = None

    @classmethod
    def get_argument_spec(cls) -> dict:
        return {
            "config": {
                "type": "list",
                "elements": "dict",
                "options": {
                    "name": {"type": "str"},
                    "value": {"type": "int"},
                },
            }
        }


class _LegacyModel(_FilterModel):
    """Model that deliberately keeps the pre-filtering state-machine path."""

    supports_gathered_filtering: ClassVar[bool] = False


class _FakeOrchestratorBase:
    """Minimal orchestrator accepted through the instance-injection path."""

    supports_bulk_create = False
    supports_bulk_delete = False
    supports_gathered_server_filtering = False
    gathered_transform = None

    def __init__(self, model_class, response_data):
        self.model_class = model_class
        self.response_data = response_data
        self.prepare_calls = []
        self.query_calls = []
        self.results = None

    def query_all(self, **kwargs):
        self.query_calls.append(deepcopy(kwargs))
        return deepcopy(self.response_data)

    def prepare_config_data(self, raw_config):
        self.prepare_calls.append(deepcopy(raw_config))
        return raw_config


class _FakeRestSend:
    """REST holder; no request is made by these state-machine tests."""

    def __init__(self, params):
        self.params = params
        self.sender = None
        self.response_handler = None


class _FakeSender:
    ansible_module = None


class _FakeModule:
    def __init__(self, state, config):
        self.params = {
            "state": state,
            "config": config,
            "output_level": "normal",
        }
        self.check_mode = False
        self.no_log_values = set()


def _build_gathered_state_machine(monkeypatch, model_class, state, config, server_filtering=False):
    monkeypatch.setattr(state_machine_module, "NDBaseOrchestrator", _FakeOrchestratorBase)
    monkeypatch.setattr(state_machine_module, "RestSend", _FakeRestSend)
    monkeypatch.setattr(state_machine_module, "Sender", _FakeSender)

    response_data = [
        {"name": "wanted", "value": 10},
        {"name": "other", "value": 20},
    ]
    orchestrator = _FakeOrchestratorBase(model_class, response_data)
    orchestrator.supports_gathered_server_filtering = server_filtering
    machine = NDStateMachine(
        module=_FakeModule(state=state, config=config),
        model_orchestrator=orchestrator,
    )
    return machine, orchestrator


def test_nd_state_machine_00200(monkeypatch) -> None:
    """
    # Summary

    Verify gathered filtering removes non-matching items from `before` and keeps filter criteria out of `proposed`.

    ## Test

    - `state: gathered`, opted-in `_FilterModel`, config filters for `name: wanted`
    - `before` contains only the matching item; `proposed` is empty (filters are not desired state)
    - `gathered` output matches the filtered `before`

    ## Classes and Methods

    - NDStateMachine.__init__()
    - NDConfigCollection.from_api_response()
    """
    machine, orchestrator = _build_gathered_state_machine(
        monkeypatch,
        model_class=_FilterModel,
        state="gathered",
        config=[{"name": "wanted"}],
    )

    assert machine.before.to_ansible_config() == [{"name": "wanted", "value": 10}]
    assert machine.proposed.to_ansible_config() == []
    assert orchestrator.prepare_calls == [[]]
    assert orchestrator.query_calls == [{}]
    assert machine.output.format()["gathered"] == [{"name": "wanted", "value": 10}]


def test_nd_state_machine_00210(monkeypatch) -> None:
    """
    # Summary

    Verify an opted-in model preserves the normal write-state config flow under `merged`.

    ## Test

    - `state: merged`, opted-in `_FilterModel`, config has `name: wanted, value: 10`
    - `before` contains the full inventory (no filtering for write states)
    - `proposed` contains the user config; `prepare_config_data` receives it unmodified

    ## Classes and Methods

    - NDStateMachine.__init__()
    """
    machine, orchestrator = _build_gathered_state_machine(
        monkeypatch,
        model_class=_FilterModel,
        state="merged",
        config=[{"name": "wanted", "value": 10}],
    )

    assert machine.before.to_ansible_config() == [
        {"name": "wanted", "value": 10},
        {"name": "other", "value": 20},
    ]
    assert machine.proposed.to_ansible_config() == [{"name": "wanted", "value": 10}]
    assert orchestrator.prepare_calls == [[{"name": "wanted", "value": 10}]]
    assert orchestrator.query_calls == [{}]


def test_nd_state_machine_00220(monkeypatch) -> None:
    """
    # Summary

    Verify a model without gathered filtering opt-in preserves the legacy gathered flow.

    ## Test

    - `state: gathered`, `_LegacyModel` (opt-in disabled), config has `name: wanted`
    - `before` contains the full inventory (no filtering applied)
    - `proposed` contains the user config as-is (legacy behavior)

    ## Classes and Methods

    - NDStateMachine.__init__()
    """
    machine, orchestrator = _build_gathered_state_machine(
        monkeypatch,
        model_class=_LegacyModel,
        state="gathered",
        config=[{"name": "wanted"}],
    )

    assert machine.before.to_ansible_config() == [
        {"name": "wanted", "value": 10},
        {"name": "other", "value": 20},
    ]
    assert machine.proposed.to_ansible_config() == [{"name": "wanted"}]
    assert orchestrator.prepare_calls == [[{"name": "wanted"}]]
    assert orchestrator.query_calls == [{}]


def test_nd_state_machine_00230(monkeypatch) -> None:
    """
    # Summary

    Verify gathered filters are forwarded to `query_all` when both model and orchestrator opt in.

    ## Test

    - `state: gathered`, opted-in `_FilterModel`, server filtering enabled
    - `query_all` receives `gathered_filters` with the user config
    - Local filtering still applies; `before` contains only the match; `proposed` is empty

    ## Classes and Methods

    - NDStateMachine.__init__()
    """
    config = [{"name": "wanted"}]
    machine, orchestrator = _build_gathered_state_machine(
        monkeypatch,
        model_class=_FilterModel,
        state="gathered",
        config=config,
        server_filtering=True,
    )

    assert orchestrator.query_calls == [{"gathered_filters": config}]
    # Server-side filtering remains candidate reduction; local matching is
    # still authoritative and keeps criteria out of proposed configuration.
    assert machine.before.to_ansible_config() == [{"name": "wanted", "value": 10}]
    assert machine.proposed.to_ansible_config() == []


def test_nd_state_machine_00240(monkeypatch) -> None:
    """
    # Summary

    Verify an empty gathered config is forwarded explicitly as an empty list.

    ## Test

    - `state: gathered`, opted-in `_FilterModel`, empty config, server filtering enabled
    - `query_all` receives `gathered_filters: []` (not omitted)
    - `before` contains the full inventory (no filter criteria to apply)

    ## Classes and Methods

    - NDStateMachine.__init__()
    """
    machine, orchestrator = _build_gathered_state_machine(
        monkeypatch,
        model_class=_FilterModel,
        state="gathered",
        config=[],
        server_filtering=True,
    )

    assert orchestrator.query_calls == [{"gathered_filters": []}]
    assert machine.before.to_ansible_config() == [
        {"name": "wanted", "value": 10},
        {"name": "other", "value": 20},
    ]


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "deleted"])
def test_nd_state_machine_00250(monkeypatch, state) -> None:
    """
    # Summary

    Verify write states never receive `gathered_filters` even when server filtering is enabled.

    ## Test

    - Parametrized over `merged`, `replaced`, `overridden`, `deleted`
    - Server filtering enabled, but `query_all` receives no `gathered_filters`

    ## Classes and Methods

    - NDStateMachine.__init__()
    """
    machine, orchestrator = _build_gathered_state_machine(
        monkeypatch,
        model_class=_FilterModel,
        state=state,
        config=[{"name": "wanted", "value": 10}],
        server_filtering=True,
    )

    assert machine.state == state
    assert orchestrator.query_calls == [{}]


def test_nd_state_machine_00260(monkeypatch) -> None:
    """
    # Summary

    Verify a legacy model does not forward gathered filters even when the orchestrator opts in.

    ## Test

    - `state: gathered`, `_LegacyModel` (opt-in disabled), server filtering enabled
    - `query_all` receives no `gathered_filters` (model gate prevents forwarding)

    ## Classes and Methods

    - NDStateMachine.__init__()
    """
    machine, orchestrator = _build_gathered_state_machine(
        monkeypatch,
        model_class=_LegacyModel,
        state="gathered",
        config=[{"name": "wanted"}],
        server_filtering=True,
    )

    assert machine.state == "gathered"
    assert orchestrator.query_calls == [{}]
