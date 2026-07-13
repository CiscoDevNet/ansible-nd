# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `NDStateMachine` capability-preflight wiring.

Verifies that `manage_state` invokes the orchestrator's `preflight` hook at a point that runs BEFORE
mutation operations are gated by check mode (PR #275 / issue #273):

- For create/update states (merged/replaced/overridden) `preflight` is called over the proposed set,
  in check mode as well as normal mode, even though the underlying create/update calls are skipped in
  check mode.
- For `deleted` state `preflight` is NOT called (removing configuration does not depend on a switch's
  capability to host the interface type -- the documented out-of-scope decision).

These drive the full `NDStateMachine.manage_state` path with a spy orchestrator instance, so they cover
the seam the per-method capability tests in `test_base_interface.py` cannot: the check-mode skip lives in
`NDStateMachine._execute_operation`, not in the orchestrator.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,unused-argument

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

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
    - `preflight` is recorded exactly once, with the single proposed model
    - No `create`/`create_bulk` call is recorded (skipped in check mode)

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDBaseInterfaceOrchestrator.preflight()
    """
    instance = _build_state_machine(state="merged", check_mode=True, config=_CONFIG)

    with does_not_raise():
        instance.manage_state()

    calls = instance.model_orchestrator._calls
    names = [name for name, _ in calls]
    assert names == ["preflight"]
    assert len(calls[0][1]) == 1
    assert calls[0][1][0].get_identifier_value() == ("192.168.12.151", "loopback10")


def test_nd_state_machine_00110() -> None:
    """
    # Summary

    Verify `manage_state` runs `preflight` AND the mutation in NORMAL mode for `merged` -- the contrast to
    `test_nd_state_machine_00100` that proves the skipped mutation there is driven by check mode, not by an
    empty work set. `preflight` precedes the mutation.

    ## Test

    - `state: merged`, `check_mode: False`, one proposed interface
    - `preflight` is recorded, then `create_bulk` is recorded (loopback supports bulk create)
    - `preflight` appears before `create_bulk`

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDStateMachine._manage_create_update_state()
    - NDBaseInterfaceOrchestrator.preflight()
    """
    instance = _build_state_machine(state="merged", check_mode=False, config=_CONFIG)

    with does_not_raise():
        instance.manage_state()

    names = [name for name, _ in instance.model_orchestrator._calls]
    assert names == ["preflight", "create_bulk"]


def test_nd_state_machine_00120() -> None:
    """
    # Summary

    Verify `manage_state` does NOT call `preflight` for `deleted` state, documenting the out-of-scope decision:
    removing configuration does not depend on a switch's capability to host the interface type.

    ## Test

    - `state: deleted`, `check_mode: True`, one proposed interface
    - No `preflight` call is recorded
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
