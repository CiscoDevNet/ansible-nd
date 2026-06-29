# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `NDStateMachine` preflight wiring.

Verifies that `manage_state` invokes the orchestrator's preflight hooks at points that run BEFORE
mutation operations are gated by check mode:

- For create/update states (merged/replaced/overridden) `preflight` (capability, PR #275 / issue #273) is
  called over the proposed set, in check mode as well as normal mode, even though the underlying create/update
  calls are skipped in check mode.
- `preflight_create` (policy-required-on-create, issue #350) is called with only the create (`new`) subset,
  ahead of the mutation loops; an already-present item re-submitted without a policy is not a create and is
  not validated, and a failure propagates before any mutation.
- For `deleted` state neither preflight is called (removing configuration does not depend on capability, and a
  policy-less item is correct for delete -- the documented out-of-scope decision).

These drive the full `NDStateMachine.manage_state` path with a spy orchestrator instance, so they cover
the seam the per-method capability tests in `test_base_interface.py` cannot: the check-mode skip lives in
`NDStateMachine._execute_operation`, not in the orchestrator.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,unused-argument

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest
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
    - `preflight` is recorded, then `preflight_create` over the create subset (both run before the check-mode gate)
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
    assert names == ["preflight", "preflight_create"]
    assert len(calls[0][1]) == 1
    assert calls[0][1][0].get_identifier_value() == ("192.168.12.151", "loopback10")
    # preflight_create receives the same single new item (create subset)
    assert [m.get_identifier_value() for m in calls[1][1]] == [("192.168.12.151", "loopback10")]


def test_nd_state_machine_00110() -> None:
    """
    # Summary

    Verify `manage_state` runs `preflight` AND the mutation in NORMAL mode for `merged` -- the contrast to
    `test_nd_state_machine_00100` that proves the skipped mutation there is driven by check mode, not by an
    empty work set. `preflight` precedes the mutation.

    ## Test

    - `state: merged`, `check_mode: False`, one proposed interface
    - `preflight`, then `preflight_create`, then `create_bulk` are recorded (loopback supports bulk create)
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
    assert names == ["preflight", "preflight_create", "create_bulk"]


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
    - `preflight` is recorded exactly once, with the proposed model
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
    assert names[0] == "preflight"
    assert len(calls[0][1]) == 1


class _ExistingLoopbackSpy(_SpyLoopbackOrchestrator):
    """Spy whose inventory already contains loopback10, so a re-submitted policy-less item is not a create."""

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        return [{"switchIp": "192.168.12.151", "interfaceName": "loopback10", "interfaceType": "loopback"}]


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
    fast with no `create`/`create_bulk` side effect.

    ## Test

    - `state: merged`, `check_mode: False`, one new policy-less item
    - `preflight_create` raises `RuntimeError`, which propagates from `manage_state`
    - No `create`/`create_bulk` call is recorded (failed before the mutation loop)

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDStateMachine._manage_create_update_state()
    - NDBaseInterfaceOrchestrator.preflight_create()
    """
    spy = _RaisingPreflightCreateSpy(rest_send=_build_rest_send())
    module = _build_module(state="merged", check_mode=False, config=_CONFIG)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with pytest.raises(RuntimeError, match=r"without a policy"):
        instance.manage_state()

    names = [name for name, _ in instance.model_orchestrator._calls]
    assert "preflight_create" in names
    assert "create" not in names
    assert "create_bulk" not in names
