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
- For `deleted` state neither `preflight` nor `preflight_create` is called (removing configuration does not depend on
  capability, and a policy-less item is correct for delete -- the documented out-of-scope decision); instead
  `preflight_delete` (PR #550 review) runs over the existing items about to be deleted, before the check-mode gate, so
  delete-specific guards (ethernet's port-channel member refusal, switch resolution) fire in a dry run too. The
  fabric-wide `overridden` delete set is not routed through it.

These drive the full `NDStateMachine.manage_state` path with a spy orchestrator instance, so they cover
the seam the per-method capability tests in `test_base_interface.py` cannot: the check-mode skip lives in
`NDStateMachine._execute_operation`, not in the orchestrator.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,too-many-lines,unused-argument

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

from typing import ClassVar

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
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
        self._update_kwargs: list[dict] = []
        self._reconcile_no_diff_changed = False
        self._reconcile_no_diff_error: Exception | None = None
        self._reconcile_absent_delete_changed = False

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        return []

    def preflight(self, model_instances) -> None:
        self._calls.append(("preflight", list(model_instances)))

    def preflight_create(self, model_instances) -> None:
        # Record-only, mirroring the `preflight` spy: the guard's own logic is covered in
        # test_base_interface.py; here we assert only that manage_state reaches it with the create subset.
        self._calls.append(("preflight_create", list(model_instances)))

    def preflight_delete(self, model_instances) -> None:
        self._calls.append(("preflight_delete", list(model_instances)))

    def reconcile_no_diff(self, model_instances) -> bool:
        self._calls.append(("reconcile_no_diff", list(model_instances)))
        if self._reconcile_no_diff_error is not None:
            raise self._reconcile_no_diff_error
        return self._reconcile_no_diff_changed

    def reconcile_absent_deletes(self, model_instances) -> bool:
        self._calls.append(("reconcile_absent_deletes", list(model_instances)))
        return self._reconcile_absent_delete_changed

    def create(self, model_instance, **kwargs) -> ResponseType:
        self._calls.append(("create", model_instance))
        return {}

    def create_bulk(self, model_instances, **kwargs) -> ResponseType:
        self._calls.append(("create_bulk", list(model_instances)))
        return {}

    def update(self, model_instance, **kwargs) -> ResponseType:
        self._calls.append(("update", model_instance))
        self._update_kwargs.append(kwargs)
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

    Verify `manage_state` does NOT call `preflight` or `preflight_create` for `deleted` state, documenting the out-of-scope
    decision: removing configuration does not depend on a switch's capability to host the interface type. The delete-specific
    `preflight_delete` hook IS called (see 00170).

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


def test_nd_state_machine_00125() -> None:
    """
    # Summary

    Verify a real `deleted` operation records the removed items into `removed`, so
    downstream save/deploy gates (e.g. nd_manage_tor) trigger on removals -- not
    just create/update. `sent` must stay create/update-only: fabric and policy
    group modules treat it as "objects that still exist and can be saved/deployed".

    ## Test

    - `state: deleted`, one proposed item that matches a seeded existing item
    - `delete_bulk` is recorded, `removed` contains the deleted item, `sent` is empty

    ## Classes and Methods

    - NDStateMachine._manage_delete_state()
    """
    instance = _build_state_machine(state="deleted", check_mode=False, config=_CONFIG)
    # Seed existing so the proposed item resolves to a real deletion.
    instance.existing = instance.proposed.copy()
    instance.before = instance.existing.copy()

    with does_not_raise():
        instance._manage_delete_state()

    names = [name for name, _ in instance.model_orchestrator._calls]
    assert "delete_bulk" in names
    assert len(instance.removed) == 1
    assert len(instance.sent) == 0


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


def test_nd_state_machine_00135() -> None:
    """
    # Summary

    Verify an `overridden` run that only removes items records those removals
    into `removed`, so save/deploy gates (e.g. nd_manage_tor) trigger on override
    deletions. `sent` must stay empty so fabric modules, which build their
    save/deploy target list from `sent`, never target a just-deleted fabric.

    ## Test

    - Seed an existing association absent from the (empty) proposed config
    - `_manage_override_deletions` deletes it and records it in `removed`

    ## Classes and Methods

    - NDStateMachine._manage_override_deletions()
    """
    donor = _build_state_machine(state="deleted", check_mode=False, config=_CONFIG)
    instance = _build_state_machine(state="overridden", check_mode=False, config=[])
    # before/existing hold an association that is not in the (empty) proposed.
    instance.existing = donor.proposed.copy()
    instance.before = donor.proposed.copy()

    with does_not_raise():
        instance._manage_override_deletions()

    names = [name for name, _ in instance.model_orchestrator._calls]
    assert "delete_bulk" in names
    assert len(instance.removed) == 1
    assert len(instance.sent) == 0


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
    reconcile_calls = [args for name, args in calls if name == "reconcile_no_diff"]
    assert len(reconcile_calls) == 1
    assert [item.get_identifier_value() for item in reconcile_calls[0]] == [("192.168.12.151", "loopback10")]
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


def test_policy_guard_precedes_capability_preflight() -> None:
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


def test_capability_preflight_runtime_error_is_normalized() -> None:
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


class _ExistingConfiguredLoopbackSpy(_SpyLoopbackOrchestrator):
    """Spy whose inventory contains loopback10 with a configured policy carrying a description.

    Used by the issue #410 tests: a proposed item that omits `description` is a removal-only change that
    `replaced`/`overridden` must classify as an update, while `merged` must leave it untouched.
    """

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        return [
            {
                "switchIp": "192.168.12.151",
                "interfaceName": "loopback10",
                "interfaceType": "loopback",
                "configData": {
                    "networkOS": {
                        "networkOSType": "nx-os",
                        "policy": {"policyType": "loopback", "adminState": True, "description": "stale description"},
                    }
                },
            }
        ]


_REMOVAL_CONFIG = [
    {
        "switch_ip": "192.168.12.151",
        "interface_name": "loopback10",
        "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": "loopback", "admin_state": True}}},
    }
]


def _loopback_wire(interface_name: str, description: str) -> dict:
    """Wire-shape loopback record for a spy `query_all` inventory, on switch 192.168.12.151."""
    return {
        "switchIp": "192.168.12.151",
        "interfaceName": interface_name,
        "interfaceType": "loopback",
        "configData": {
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {"policyType": "loopback", "adminState": True, "description": description},
            }
        },
    }


def _loopback_config(interface_name: str, description: str) -> dict:
    """Module `config` item for a loopback with a policy carrying `description`, on switch 192.168.12.151."""
    return {
        "switch_ip": "192.168.12.151",
        "interface_name": interface_name,
        "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": "loopback", "admin_state": True, "description": description}}},
    }


def _description(instance: NDStateMachine, interface_name: str) -> str | None:
    """Return the policy description of `interface_name` in the state machine's `existing` collection, or None if absent."""
    item = instance.existing.get(("192.168.12.151", interface_name))
    if item is None:
        return None
    return item.config_data.network_os.policy.description


class _TwoExistingSpy(_SpyLoopbackOrchestrator):
    """Spy whose inventory holds loopback10 and loopback11, each with a stale description (issue #597 tests)."""

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        return [_loopback_wire("loopback10", "stale 10"), _loopback_wire("loopback11", "stale 11")]


class _UnacceptedRemovalSpy(_TwoExistingSpy):
    """Spy whose `unaccepted_removals` names loopback11 as a removal the controller has not accepted."""

    def unaccepted_removals(self, model_instances):
        return [item for item in model_instances if item.interface_name == "loopback11"]


class _FailingBulkCreateSpy(_SpyLoopbackOrchestrator):
    """Spy whose `create_bulk` raises; `accepted_mutations` names the items in `_accepted_identifiers` as controller-accepted.

    The hook is overridden here so these tests never reach the interface implementation (which resolves switch IDs via
    `FabricContext`); the interface implementation is covered in test_base_interface.py.
    """

    def model_post_init(self, __context) -> None:
        super().model_post_init(__context)
        self._accepted_identifiers: set = set()

    def create_bulk(self, model_instances, **kwargs) -> ResponseType:
        self._calls.append(("create_bulk", list(model_instances)))
        raise RuntimeError("Bulk create failed: Request failed (400): Bad Request")

    def accepted_mutations(self, model_instances):
        return [item for item in model_instances if item.get_identifier_value() in self._accepted_identifiers]


class _NoBulkFailingCreateSpy(_SpyLoopbackOrchestrator):
    """Spy without bulk-create support whose individual `create` raises."""

    supports_bulk_create: ClassVar[bool] = False

    def create(self, model_instance, **kwargs) -> ResponseType:
        self._calls.append(("create", model_instance))
        raise RuntimeError("Create failed: Request failed (400): Bad Request")


class _SecondUpdateFailsSpy(_TwoExistingSpy):
    """Spy whose `update` succeeds for loopback10 and raises for loopback11."""

    def update(self, model_instance, **kwargs) -> ResponseType:
        self._calls.append(("update", model_instance))
        if model_instance.interface_name == "loopback11":
            raise RuntimeError("Update failed: Request failed (400): Bad Request")
        return {}


class _UpdateFailsSpy(_ExistingConfiguredLoopbackSpy):
    """Spy whose `update` always raises; inventory is loopback10 with 'stale description'."""

    def update(self, model_instance, **kwargs) -> ResponseType:
        self._calls.append(("update", model_instance))
        raise RuntimeError("Update failed: Request failed (400): Bad Request")


def test_replaced_update_forwards_previous_model() -> None:
    """
    # Summary

    Verify `replaced` state classifies a removal-only proposed item as an update (issue #410): the existing
    interface carries a policy `description` the proposed config omits, so `manage_state` must issue the
    `update` that resets it -- not silently classify the item `no_diff`.

    ## Test

    - Inventory contains `loopback10` with `admin_state` and a stale `description`; proposed re-sends the same
      identifier with `admin_state` only under `replaced`
    - An `update` call is recorded with the proposed (description-less) model
    - No create is recorded (the item already exists)

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDStateMachine._manage_create_update_state()
    - NDBaseModel.get_diff()
    """
    spy = _ExistingConfiguredLoopbackSpy(rest_send=_build_rest_send())
    module = _build_module(state="replaced", check_mode=False, config=_REMOVAL_CONFIG)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with does_not_raise():
        instance.manage_state()

    calls = instance.model_orchestrator._calls
    names = [name for name, _ in calls]
    assert "update" in names
    assert "create" not in names
    assert "create_bulk" not in names
    updated = [args for name, args in calls if name == "update"][0]
    assert updated.get_identifier_value() == ("192.168.12.151", "loopback10")
    assert updated.config_data.network_os.policy.description is None
    previous_model = instance.model_orchestrator._update_kwargs[0]["previous_model"]
    assert previous_model.config_data.network_os.policy.description == "stale description"


def test_nd_state_machine_00200() -> None:
    """
    # Summary

    Verify `merged` state still classifies the same removal-only proposed item as `no_diff`: omitted fields mean
    "leave untouched" under `merged`, so the issue #410 reverse pass must not fire on the `exclude_unset=True` path.

    ## Test

    - The identical inventory/config pair from `test_nd_state_machine_00190`, under `merged`
    - No mutation is recorded (only the preflights run)

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDStateMachine._manage_create_update_state()
    - NDBaseModel.get_diff()
    """
    spy = _ExistingConfiguredLoopbackSpy(rest_send=_build_rest_send())
    module = _build_module(state="merged", check_mode=False, config=_REMOVAL_CONFIG)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with does_not_raise():
        instance.manage_state()

    names = [name for name, _ in instance.model_orchestrator._calls]
    assert names == ["preflight_create", "preflight", "reconcile_no_diff"]


def test_nd_state_machine_00205() -> None:
    """Check mode previews unchanged deploy state without mutating it."""

    spy = _ExistingConfiguredLoopbackSpy(rest_send=_build_rest_send())
    module = _build_module(state="merged", check_mode=True, config=_REMOVAL_CONFIG)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with does_not_raise():
        instance.manage_state()

    names = [name for name, _ in instance.model_orchestrator._calls]
    assert names == ["preflight_create", "preflight", "reconcile_no_diff"]
    assert instance.output.format()["changed"] is False


@pytest.mark.parametrize("check_mode", [False, True])
def test_nd_state_machine_00206(check_mode: bool) -> None:
    """Pending deployment on unchanged intent reports changed in normal and check mode."""

    spy = _ExistingConfiguredLoopbackSpy(rest_send=_build_rest_send())
    spy._reconcile_no_diff_changed = True
    module = _build_module(state="merged", check_mode=check_mode, config=_REMOVAL_CONFIG)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with does_not_raise():
        instance.manage_state()

    assert instance.output.format()["changed"] is True
    assert [name for name, _ in spy._calls] == [
        "preflight_create",
        "preflight",
        "reconcile_no_diff",
    ]


def test_nd_state_machine_00207() -> None:
    """A failed no-diff preview restores the execution baseline in failure output."""

    spy = _ExistingConfiguredLoopbackSpy(rest_send=_build_rest_send())
    spy._reconcile_no_diff_error = RuntimeError("contradictory preview")
    config = [
        {
            "switch_ip": "192.168.12.151",
            "interface_name": "loopback10",
            "config_data": {
                "network_os": {
                    "network_os_type": "nx-os",
                    "policy": {
                        "policy_type": "loopback",
                        "admin_state": True,
                        "description": "stale description",
                    },
                }
            },
        },
        {
            "switch_ip": "192.168.12.151",
            "interface_name": "loopback20",
            "config_data": {
                "network_os": {
                    "network_os_type": "nx-os",
                    "policy": {"policy_type": "loopback", "admin_state": True},
                }
            },
        },
    ]
    module = _build_module(state="merged", check_mode=False, config=config)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with pytest.raises(NDStateMachineError, match="contradictory preview"):
        instance.manage_state()

    output = instance.output.format()
    assert output["changed"] is False
    assert [item["interface_name"] for item in output["after"]] == ["loopback10"]
    assert "create_bulk" not in [name for name, _ in spy._calls]


def test_nd_state_machine_00210() -> None:
    """
    # Summary

    Verify `overridden` state classifies the removal-only proposed item as an update too (its update-classification
    phase shares `_manage_create_update_state` with `replaced`), and does not delete the surviving item.

    ## Test

    - The identical inventory/config pair from `test_nd_state_machine_00190`, under `overridden`
    - An `update` call is recorded; no delete is recorded (the identifier is still proposed)

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDStateMachine._manage_create_update_state()
    - NDStateMachine._manage_override_deletions()
    """
    spy = _ExistingConfiguredLoopbackSpy(rest_send=_build_rest_send())
    module = _build_module(state="overridden", check_mode=False, config=_REMOVAL_CONFIG)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with does_not_raise():
        instance.manage_state()

    names = [name for name, _ in instance.model_orchestrator._calls]
    assert "update" in names
    assert "delete" not in names
    assert "delete_bulk" not in names


def test_nd_state_machine_00170() -> None:
    """
    # Summary

    Verify `manage_state` calls `preflight_delete` for `deleted` state in check mode, ahead of the check-mode gate that skips
    the delete mutation (PR #550 review), so delete-specific guards surface in a dry run.

    ## Test

    - `state: deleted`, `check_mode: True`, one proposed interface; the inventory is empty
    - `preflight_delete` is recorded exactly once, with the exact absent requested item
    - The exact absent request is passed to deploy-recovery reconciliation in check mode
    - No delete mutation is recorded

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDStateMachine._manage_delete_state()
    - NDBaseOrchestrator.preflight_delete()
    """
    instance = _build_state_machine(state="deleted", check_mode=True, config=_CONFIG)

    with does_not_raise():
        instance.manage_state()

    calls = instance.model_orchestrator._calls
    assert [name for name, _ in calls] == [
        "preflight_delete",
        "reconcile_absent_deletes",
    ]
    assert [item.get_identifier_value() for item in calls[0][1]] == [("192.168.12.151", "loopback10")]
    assert [item.get_identifier_value() for item in calls[1][1]] == [("192.168.12.151", "loopback10")]


@pytest.mark.parametrize("check_mode", [False, True])
def test_nd_state_machine_00175(check_mode: bool) -> None:
    """An absent explicit delete can recover pending deployment in either mode."""

    spy = _SpyLoopbackOrchestrator(rest_send=_build_rest_send())
    spy._reconcile_absent_delete_changed = True
    module = _build_module(state="deleted", check_mode=check_mode, config=_CONFIG)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with does_not_raise():
        instance.manage_state()

    assert instance.output.format()["changed"] is True
    assert [name for name, _ in spy._calls] == [
        "preflight_delete",
        "reconcile_absent_deletes",
    ]


def test_nd_state_machine_00180() -> None:
    """
    # Summary

    Verify the fabric-wide `overridden` delete set is NOT routed through `preflight_delete`: ethernet's `delete_bulk` skips
    port-channel members silently there, so the explicit-delete refusal must not fire on convergence.

    ## Test

    - `state: overridden`, `check_mode: True`, one proposed interface
    - `preflight_create` and `preflight` are recorded; `preflight_delete` is not

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDStateMachine._manage_override_deletions()
    """
    instance = _build_state_machine(state="overridden", check_mode=True, config=_CONFIG)

    with does_not_raise():
        instance.manage_state()

    names = [name for name, _ in instance.model_orchestrator._calls]
    assert "preflight_delete" not in names
    assert names[:2] == ["preflight_create", "preflight"]


class _RaisingDeletePreflightSpy(_SpyLoopbackOrchestrator):
    """Spy whose `preflight_delete` raises, to assert the error is normalized and halts the run before any delete."""

    def preflight_delete(self, model_instances) -> None:
        self._calls.append(("preflight_delete", list(model_instances)))
        raise RuntimeError("Interface Ethernet1/7 is a member of port-channel 10")


def test_nd_state_machine_00190() -> None:
    """
    # Summary

    Verify a `preflight_delete` failure propagates as `NDStateMachineError` (same normalization as the create/update preflights)
    and no delete mutation is attempted, in normal mode.

    ## Test

    - `state: deleted`, `check_mode: False`; `preflight_delete` raises `RuntimeError`
    - `manage_state` raises `NDStateMachineError` matching `Preflight failed`
    - `delete_bulk` / `delete` are not recorded

    ## Classes and Methods

    - NDStateMachine._manage_delete_state()
    """
    spy = _RaisingDeletePreflightSpy(rest_send=_build_rest_send())
    module = _build_module(state="deleted", check_mode=False, config=_CONFIG)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with pytest.raises(NDStateMachineError, match=r"Preflight failed: Interface Ethernet1/7 is a member of port-channel 10"):
        instance.manage_state()

    names = [name for name, _ in spy._calls]
    assert names == ["preflight_delete"]


# =============================================================================
# Issue #597: a failed create/update must not appear in `after`, `sent`, or `changed`
# =============================================================================


def test_nd_state_machine_00300() -> None:
    """
    # Summary

    Verify a failed bulk create leaves `after` equal to `before`, `changed` false and `sent` empty (issue #597): the classification
    loop no longer mutates `existing`, and nothing is applied when the orchestrator reports no accepted items.

    ## Test

    - `state: merged`, inventory empty, one proposed loopback; `create_bulk` raises; `accepted_mutations` returns `[]`
    - `manage_state` raises `NDStateMachineError` mentioning `Failed to create in bulk`
    - `existing` is empty, `sent` is empty, `output.format()["changed"]` is False and `["after"] == []`

    ## Classes and Methods

    - NDStateMachine._manage_create_update_state()
    - NDStateMachine._create_bulk_deferred()
    """
    spy = _FailingBulkCreateSpy(rest_send=_build_rest_send())
    module = _build_module(state="merged", check_mode=False, config=[_loopback_config("loopback10", "new")])
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with pytest.raises(NDStateMachineError, match=r"Failed to create in bulk"):
        instance.manage_state()

    assert len(instance.existing) == 0
    assert len(instance.sent) == 0
    output = instance.output.format()
    assert output["changed"] is False
    assert output["after"] == []
    assert output["before"] == []


def test_nd_state_machine_00310() -> None:
    """
    # Summary

    Verify a failed bulk create applies only the subset the orchestrator reports as accepted (issue #597, mixed 207): the accepted
    item is in `after` and `sent`, the rejected one is not, and `changed` is true.

    ## Test

    - `state: merged`, inventory empty, two proposed loopbacks; `create_bulk` raises; `accepted_mutations` names loopback10 only
    - `manage_state` raises `NDStateMachineError`
    - `existing` holds loopback10 only; `sent` holds loopback10 only; `changed` is True

    ## Classes and Methods

    - NDStateMachine._create_bulk_deferred()
    - NDStateMachine._apply_accepted()
    """
    spy = _FailingBulkCreateSpy(rest_send=_build_rest_send())
    spy._accepted_identifiers = {("192.168.12.151", "loopback10")}  # pylint: disable=attribute-defined-outside-init
    config = [_loopback_config("loopback10", "new 10"), _loopback_config("loopback11", "new 11")]
    module = _build_module(state="merged", check_mode=False, config=config)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with pytest.raises(NDStateMachineError, match=r"Failed to create in bulk"):
        instance.manage_state()

    assert _description(instance, "loopback10") == "new 10"
    assert _description(instance, "loopback11") is None
    assert [item.interface_name for item in instance.sent] == ["loopback10"]
    assert instance.output.format()["changed"] is True


def test_nd_state_machine_00320() -> None:
    """
    # Summary

    Verify individual updates apply one at a time (issue #597): when the second of two updates fails, the first is in `after` and
    `sent` and the second keeps its existing values.

    ## Test

    - `state: replaced`, inventory loopback10/loopback11 with stale descriptions; both proposed with new descriptions
    - `update` succeeds for loopback10 and raises for loopback11
    - `manage_state` raises `NDStateMachineError` naming loopback11
    - loopback10 shows the new description, loopback11 the stale one; `sent` holds loopback10 only; `changed` is True

    ## Classes and Methods

    - NDStateMachine._manage_create_update_state()
    - NDStateMachine._execute_operation()
    """
    spy = _SecondUpdateFailsSpy(rest_send=_build_rest_send())
    config = [_loopback_config("loopback10", "new 10"), _loopback_config("loopback11", "new 11")]
    module = _build_module(state="replaced", check_mode=False, config=config)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with pytest.raises(NDStateMachineError, match=r"Failed to update \('192.168.12.151', 'loopback11'\)"):
        instance.manage_state()

    assert _description(instance, "loopback10") == "new 10"
    assert _description(instance, "loopback11") == "stale 11"
    assert [item.interface_name for item in instance.sent] == ["loopback10"]
    assert instance.output.format()["changed"] is True


def test_nd_state_machine_00325() -> None:
    """
    # Summary

    Verify a failed individual create (orchestrator without bulk support) is not applied to `after` (issue #597).

    ## Test

    - `state: merged`, inventory empty, one proposed loopback; `supports_bulk_create` is False and `create` raises
    - `manage_state` raises `NDStateMachineError` mentioning `Failed to create`
    - `existing` and `sent` are empty; `changed` is False

    ## Classes and Methods

    - NDStateMachine._manage_create_update_state()
    """
    spy = _NoBulkFailingCreateSpy(rest_send=_build_rest_send())
    module = _build_module(state="merged", check_mode=False, config=[_loopback_config("loopback10", "new")])
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with pytest.raises(NDStateMachineError, match=r"Failed to create \('192.168.12.151', 'loopback10'\)"):
        instance.manage_state()

    assert len(instance.existing) == 0
    assert len(instance.sent) == 0
    assert instance.output.format()["changed"] is False


def test_nd_state_machine_00330() -> None:
    """
    # Summary

    Verify `ignore_errors: true` follows the same contract as a failed run (issue #597): a swallowed bulk-create failure raises
    nothing, and the items are absent from `after` and `sent`.

    ## Test

    - `state: merged`, `ignore_errors: True`, inventory empty, one proposed loopback; `create_bulk` raises
    - `manage_state` does not raise
    - `existing` and `sent` are empty; `changed` is False

    ## Classes and Methods

    - NDStateMachine._execute_operation()
    - NDStateMachine._create_bulk_deferred()
    """
    spy = _FailingBulkCreateSpy(rest_send=_build_rest_send())
    module = _build_module(state="merged", check_mode=False, config=[_loopback_config("loopback10", "new")])
    module.params["ignore_errors"] = True
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with does_not_raise():
        instance.manage_state()

    assert len(instance.existing) == 0
    assert len(instance.sent) == 0
    assert instance.output.format()["changed"] is False


def test_nd_state_machine_00340() -> None:
    """
    # Summary

    Verify a merged-state update merges into a deep copy (issue #597): when the PUT fails, the existing object still carries its
    original values, while the item handed to `update` carries the merged values.

    ## Test

    - `state: merged`, inventory loopback10 with 'stale description'; proposed loopback10 with description 'fresh'
    - `update` raises
    - The `update` call received description 'fresh'; `existing` still shows 'stale description'; `changed` is False

    ## Classes and Methods

    - NDStateMachine._manage_create_update_state()
    - NDBaseModel.merge()
    """
    spy = _UpdateFailsSpy(rest_send=_build_rest_send())
    module = _build_module(state="merged", check_mode=False, config=[_loopback_config("loopback10", "fresh")])
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with pytest.raises(NDStateMachineError, match=r"Failed to update"):
        instance.manage_state()

    updated = [args for name, args in spy._calls if name == "update"][0]
    assert updated.config_data.network_os.policy.description == "fresh"
    assert _description(instance, "loopback10") == "stale description"
    assert instance.output.format()["changed"] is False


def test_nd_state_machine_00350() -> None:
    """
    # Summary

    Verify check mode still reports every proposed mutation in `after` with `changed: true` after the deferral (issue #597
    regression guard): a dry run sends nothing, so every operation counts as accepted intent.

    ## Test

    - `state: merged`, `check_mode: True`, inventory loopback10 'stale description'; proposed loopback10 'fresh' and new loopback11
    - `manage_state` does not raise and records no `update`/`create_bulk` call
    - `existing` shows loopback10 'fresh' and loopback11 present; `sent` holds both; `changed` is True

    ## Classes and Methods

    - NDStateMachine._execute_operation()
    - NDStateMachine._apply_accepted()
    """
    spy = _ExistingConfiguredLoopbackSpy(rest_send=_build_rest_send())
    config = [_loopback_config("loopback10", "fresh"), _loopback_config("loopback11", "new 11")]
    module = _build_module(state="merged", check_mode=True, config=config)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with does_not_raise():
        instance.manage_state()

    names = [name for name, _ in spy._calls]
    assert "update" not in names
    assert "create_bulk" not in names
    assert _description(instance, "loopback10") == "fresh"
    assert _description(instance, "loopback11") == "new 11"
    assert sorted(item.interface_name for item in instance.sent) == ["loopback10", "loopback11"]
    assert instance.output.format()["changed"] is True


def test_nd_state_machine_00370() -> None:
    """
    # Summary

    Verify `reconcile_after_failure` restores an unaccepted removal to `after` from `before` and drops it from `removed`, and is
    idempotent (issue #597 delete side).

    ## Test

    - `state: deleted`, inventory loopback10/loopback11, both proposed; `delete_bulk` records (interface delete only queues)
    - After `manage_state`, `existing` is empty and `removed` holds both
    - `unaccepted_removals` names loopback11; `reconcile_after_failure` restores it with its `before` values; `removed` keeps loopback10
    - `changed` is True (loopback10 is gone); a second call changes nothing

    ## Classes and Methods

    - NDStateMachine.reconcile_after_failure()
    - NDStateMachine._delete_items()
    """
    spy = _UnacceptedRemovalSpy(rest_send=_build_rest_send())
    config = [{"switch_ip": "192.168.12.151", "interface_name": "loopback10"}, {"switch_ip": "192.168.12.151", "interface_name": "loopback11"}]
    module = _build_module(state="deleted", check_mode=False, config=config)
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with does_not_raise():
        instance.manage_state()
    assert len(instance.existing) == 0
    assert sorted(item.interface_name for item in instance.removed) == ["loopback10", "loopback11"]

    with does_not_raise():
        instance.reconcile_after_failure()

    assert [item.interface_name for item in instance.existing] == ["loopback11"]
    assert _description(instance, "loopback11") == "stale 11"
    assert instance.existing.get(("192.168.12.151", "loopback11")) is not instance.before.get(("192.168.12.151", "loopback11"))
    assert [item.interface_name for item in instance.removed] == ["loopback10"]
    output = instance.output.format()
    assert output["changed"] is True
    assert [item["interface_name"] for item in output["after"]] == ["loopback11"]

    with does_not_raise():
        instance.reconcile_after_failure()
    assert [item.interface_name for item in instance.existing] == ["loopback11"]
    assert [item.interface_name for item in instance.removed] == ["loopback10"]


def test_nd_state_machine_00375() -> None:
    """
    # Summary

    Verify `reconcile_after_failure` is a no-op when the orchestrator reports every removal accepted (the base default) and when
    nothing was removed.

    ## Test

    - `state: deleted` with the two-item inventory and the plain spy (the interface `unaccepted_removals` override with empty delete-side
      queues): after `manage_state`, `reconcile_after_failure` leaves `existing` empty and `removed` with both items
    - `state: merged` with an empty inventory: `reconcile_after_failure` before any mutation does not raise

    ## Classes and Methods

    - NDStateMachine.reconcile_after_failure()
    - NDBaseOrchestrator.unaccepted_removals()
    """
    spy = _TwoExistingSpy(rest_send=_build_rest_send())
    config = [{"switch_ip": "192.168.12.151", "interface_name": "loopback10"}, {"switch_ip": "192.168.12.151", "interface_name": "loopback11"}]
    module = _build_module(state="deleted", check_mode=False, config=config)
    instance = NDStateMachine(module=module, model_orchestrator=spy)
    instance.manage_state()

    with does_not_raise():
        instance.reconcile_after_failure()
    assert len(instance.existing) == 0
    assert len(instance.removed) == 2

    fresh = _build_state_machine(state="merged", check_mode=False, config=_CONFIG)
    with does_not_raise():
        fresh.reconcile_after_failure()
    assert len(fresh.existing) == 0


class _SecondDeleteFailsSpy(_TwoExistingSpy):
    """Spy without bulk-delete support whose synchronous per-item `delete` succeeds for loopback10 and raises for loopback11."""

    supports_bulk_delete: ClassVar[bool] = False

    def delete(self, model_instance, **kwargs) -> None:
        self._calls.append(("delete", model_instance))
        if model_instance.interface_name == "loopback11":
            raise RuntimeError("Delete failed: Request failed (500): Internal Server Error")


def _two_loopback_delete_config() -> list[dict]:
    """Identifier-only `deleted` config for loopback10 then loopback11 on switch 192.168.12.151."""
    return [{"switch_ip": "192.168.12.151", "interface_name": "loopback10"}, {"switch_ip": "192.168.12.151", "interface_name": "loopback11"}]


def test_nd_state_machine_00380() -> None:
    """
    # Summary

    Verify a per-item delete failure applies the removals accepted before it (issue #597, final review): loopback10 was deleted on
    the controller, so it leaves `after` and joins `removed`; loopback11 failed, so it stays in `after` and is not reported removed.

    ## Test

    - `state: deleted`, inventory loopback10/loopback11, both proposed; no bulk delete; `delete` raises for loopback11
    - `manage_state` raises `NDStateMachineError` naming loopback11
    - `removed` holds loopback10 only; `existing` holds loopback11 only; `changed` is True

    ## Classes and Methods

    - NDStateMachine._delete_items()
    - NDStateMachine._apply_removed()
    """
    spy = _SecondDeleteFailsSpy(rest_send=_build_rest_send())
    module = _build_module(state="deleted", check_mode=False, config=_two_loopback_delete_config())
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with pytest.raises(NDStateMachineError, match=r"Failed to delete \('192.168.12.151', 'loopback11'\)"):
        instance.manage_state()

    assert [item.interface_name for item in instance.removed] == ["loopback10"]
    assert [item.interface_name for item in instance.existing] == ["loopback11"]
    assert instance.output.format()["changed"] is True


def test_nd_state_machine_00385() -> None:
    """
    # Summary

    Verify a per-item delete failure swallowed by `ignore_errors` is not recorded as removed (issue #597, final review): only the
    accepted loopback10 removal is applied.

    ## Test

    - Same spy and config as 00380, with `ignore_errors` true
    - `manage_state` does not raise
    - `removed` holds loopback10 only; `existing` holds loopback11 only

    ## Classes and Methods

    - NDStateMachine._delete_items()
    - NDStateMachine._apply_removed()
    """
    spy = _SecondDeleteFailsSpy(rest_send=_build_rest_send())
    module = _build_module(state="deleted", check_mode=False, config=_two_loopback_delete_config())
    module.params["ignore_errors"] = True
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    with does_not_raise():
        instance.manage_state()

    assert [item.interface_name for item in instance.removed] == ["loopback10"]
    assert [item.interface_name for item in instance.existing] == ["loopback11"]
