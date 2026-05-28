# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `MaintenanceModeOrchestrator`.

Verifies that the orchestrator drives `RestSend` correctly for the changeSystemMode switch action:
per-switch GET fan-out and snapshot construction in `query_all`, migration hard-fail, idempotency
filtering in `update`, and per-switch 207-failure parsing.

Scope: methods defined in `maintenance_mode.py` only. Inherited `FabricContext` plumbing is
exercised through `query_all` but tested in detail by `test_fabric_context.py`.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,too-many-lines
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.maintenance_mode.maintenance_mode import MaintenanceModeModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.maintenance_mode import MaintenanceModeOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_maintenance_mode(key: str):
    """Load fixture data for test_maintenance_mode tests."""
    return load_fixture("test_maintenance_mode")[key]


def _build_rest_send(gen_responses: ResponseGenerator, config: list | None = None) -> RestSend:
    """Build a `RestSend` wired to a file-based `Sender` and `ResponseHandler`."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    params = {"check_mode": False, "fabric_name": "SITE1", "config": config or []}
    rest_send = RestSend(params)
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


# =============================================================================
# Test: initialization
# =============================================================================


def test_maintenance_mode_00010() -> None:
    """
    # Summary

    Verify `MaintenanceModeOrchestrator` instantiates and exposes expected ClassVars.

    ## Classes and Methods

    - MaintenanceModeOrchestrator.__init__
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = MaintenanceModeOrchestrator(rest_send=rest_send)

    assert instance.model_class is MaintenanceModeModel
    assert instance.supports_bulk_create is False
    assert instance.supports_bulk_delete is False
    assert instance.fabric_name == "SITE1"


# =============================================================================
# Test: _user_switches helper
# =============================================================================


def test_maintenance_mode_00020() -> None:
    """
    # Summary

    `_user_switches` returns the switches list from the wrapped config dict.

    ## Classes and Methods

    - MaintenanceModeOrchestrator._user_switches
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    config = [{"mode": "maintenance", "switches": [{"switch_ip": "192.168.12.131"}]}]
    rest_send = _build_rest_send(gen_responses, config=config)
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)

    assert instance._user_switches() == [{"switch_ip": "192.168.12.131"}]


def test_maintenance_mode_00030() -> None:
    """
    # Summary

    `_user_switches` returns [] when config is empty or malformed.

    ## Classes and Methods

    - MaintenanceModeOrchestrator._user_switches
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, config=[])
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)

    assert instance._user_switches() == []


# =============================================================================
# Test: query_all
# =============================================================================


def test_maintenance_mode_00100() -> None:
    """
    # Summary

    Verify `query_all` returns a singleton snapshot with per-switch `intendedSystemMode`.

    ## Test

    - 2 switches in config
    - Fabric summary and one bulk /switches GET are consumed in order
    - Snapshot contains both IPs with their current `intendedSystemMode`

    ## Classes and Methods

    - MaintenanceModeOrchestrator.query_all
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_maintenance_mode(f"{method_name}a")  # fabric summary
        yield responses_maintenance_mode(f"{method_name}b")  # bulk switches GET

    gen_responses = ResponseGenerator(responses())
    config = [
        {
            "mode": "maintenance",
            "switches": [
                {"switch_ip": "192.168.12.131"},
                {"switch_ip": "192.168.12.151"},
            ],
        }
    ]
    rest_send = _build_rest_send(gen_responses, config=config)
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert isinstance(result, list)
    assert len(result) == 1
    snapshot = result[0]
    assert snapshot["switch_modes"] == {
        "192.168.12.131": "normal",
        "192.168.12.151": "maintenance",
    }
    assert {s["switch_ip"] for s in snapshot["switches"]} == {"192.168.12.131", "192.168.12.151"}


def test_maintenance_mode_00110() -> None:
    """
    # Summary

    Verify `query_all` hard-fails with the remediation message when any switch is in migration mode.

    ## Test

    - 1 switch in config
    - Switch's discoveredSystemMode is `migration`
    - `RuntimeError` raised; message contains exact remediation text and the switch IP

    ## Classes and Methods

    - MaintenanceModeOrchestrator.query_all
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_maintenance_mode(f"{method_name}a")  # summary
        yield responses_maintenance_mode(f"{method_name}b")  # bulk switches GET (switch in migration)

    gen_responses = ResponseGenerator(responses())
    config = [{"mode": "maintenance", "switches": [{"switch_ip": "192.168.12.131"}]}]
    rest_send = _build_rest_send(gen_responses, config=config)
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)

    match = r"Switch\(es\) are in 'migration' mode:.*192\.168\.12\.131.*Recalculate and Deploy"
    with pytest.raises(RuntimeError, match=match):
        instance.query_all()


def test_maintenance_mode_00120() -> None:
    """
    # Summary

    Verify `query_all` raises when a user-supplied switch_ip is not found in the fabric.

    ## Test

    - 1 switch in config with IP not in the switches list
    - `RuntimeError` raised with FabricContext-style message

    ## Classes and Methods

    - MaintenanceModeOrchestrator.query_all
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_maintenance_mode(f"{method_name}a")  # summary
        yield responses_maintenance_mode(f"{method_name}b")  # bulk switches GET with different IP

    gen_responses = ResponseGenerator(responses())
    config = [{"mode": "maintenance", "switches": [{"switch_ip": "192.168.12.131"}]}]
    rest_send = _build_rest_send(gen_responses, config=config)
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)

    match = r"No switch found with fabricManagementIp '192\.168\.12\.131'"
    with pytest.raises(RuntimeError, match=match):
        instance.query_all()


def test_maintenance_mode_00130() -> None:
    """
    # Summary

    Verify `query_all` returns an empty snapshot when config has no switches (defensive path; argspec
    normally prevents this).

    ## Classes and Methods

    - MaintenanceModeOrchestrator.query_all
    """

    def responses():
        yield responses_maintenance_mode("summary_ok")  # only summary is consumed

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, config=[])
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert result == [{"switches": [], "switch_modes": {}}]


# =============================================================================
# Test: update
# =============================================================================


def test_maintenance_mode_00200() -> None:
    """
    # Summary

    Verify `update` resolves IPs, filters to switches needing change, sets query params, and POSTs.

    ## Test

    - 1 switch in config with desired mode=maintenance, currently normal
    - POST issued to /switchActions/changeSystemMode with switchIds=[serial]
    - Query params deploy/blocking/ticketId appended

    ## Classes and Methods

    - MaintenanceModeOrchestrator.update
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_maintenance_mode(f"{method_name}a")  # summary
        yield responses_maintenance_mode(f"{method_name}b")  # bulk switches GET (switch A normal)
        yield responses_maintenance_mode(f"{method_name}c")  # POST 207 success

    gen_responses = ResponseGenerator(responses())
    config = [
        {
            "mode": "maintenance",
            "deploy": True,
            "blocking": True,
            "ticket_id": "CHG-1",
            "switches": [{"switch_ip": "192.168.12.131"}],
        }
    ]
    rest_send = _build_rest_send(gen_responses, config=config)
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)

    model = MaintenanceModeModel.from_config(config[0])

    with does_not_raise():
        instance.update(model)

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert "switchActions/changeSystemMode" in rest_send.path
    assert "deploy=true" in rest_send.path
    assert "blocking=true" in rest_send.path
    assert "ticketId=CHG-1" in rest_send.path

    body = rest_send.committed_payload
    assert body == {"mode": "maintenance", "switchIds": ["9UOJ3E8A6O9"]}


def test_maintenance_mode_00210() -> None:
    """
    # Summary

    Verify `update` short-circuits (no POST) when every switch already has the desired intent.

    ## Test

    - Snapshot says switch is already in maintenance, model requests maintenance
    - No POST is issued; only the snapshot GETs are consumed

    ## Classes and Methods

    - MaintenanceModeOrchestrator.update
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_maintenance_mode(f"{method_name}a")  # summary
        yield responses_maintenance_mode(f"{method_name}b")  # bulk switches GET (switch A already maintenance)

    gen_responses = ResponseGenerator(responses())
    config = [{"mode": "maintenance", "switches": [{"switch_ip": "192.168.12.131"}]}]
    rest_send = _build_rest_send(gen_responses, config=config)
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)

    model = MaintenanceModeModel.from_config(config[0])

    with does_not_raise():
        result = instance.update(model)

    assert result == {}
    # If a POST had been issued we'd see verb=POST; instead the last call was the bulk switches GET.
    assert rest_send.verb == HttpVerbEnum.GET.value


def test_maintenance_mode_00220() -> None:
    """
    # Summary

    Verify `update` raises with switch IPs when the 207 body contains per-switch failures.

    ## Test

    - POST returns 207 with one item status=failed
    - `RuntimeError` raised; message names the offending switch IP (resolved from switchId)

    ## Classes and Methods

    - MaintenanceModeOrchestrator.update
    - MaintenanceModeOrchestrator._raise_on_207_failures
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_maintenance_mode(f"{method_name}a")  # summary
        yield responses_maintenance_mode(f"{method_name}b")  # bulk switches GET (switch A normal)
        yield responses_maintenance_mode(f"{method_name}c")  # POST 207 with failure

    gen_responses = ResponseGenerator(responses())
    config = [{"mode": "maintenance", "switches": [{"switch_ip": "192.168.12.131"}]}]
    rest_send = _build_rest_send(gen_responses, config=config)
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)

    model = MaintenanceModeModel.from_config(config[0])

    match = r"changeSystemMode reported per-switch failures:.*192\.168\.12\.131.*deploy aborted"
    with pytest.raises(RuntimeError, match=match):
        instance.update(model)


def test_maintenance_mode_00230() -> None:
    """
    # Summary

    `update` returns early when the model has no mode or no switches (defensive — argspec normally
    rejects both).

    ## Classes and Methods

    - MaintenanceModeOrchestrator.update
    """

    def responses():
        # Only the fabric-summary call from validate_prerequisites is consumed before the early-return.
        yield responses_maintenance_mode("summary_ok")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, config=[{"mode": None, "switches": []}])
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)

    model = MaintenanceModeModel()  # mode=None, switches=[]

    with does_not_raise():
        result = instance.update(model)

    assert result == {}


def test_maintenance_mode_00240() -> None:
    """
    # Summary

    Verify that `update` reuses the snapshot cached by `query_all` and does NOT re-issue per-switch
    GETs when called after `query_all`. Together they should consume exactly one snapshot pass
    (summary + switches list + per-switch GET) and one POST.

    ## Test

    - Call `query_all` first (consumes summary and the bulk /switches GET).
    - Call `update`. Fixture generator yields only the POST next; if `update` re-queried, the
      generator would underflow and raise.

    ## Classes and Methods

    - MaintenanceModeOrchestrator.query_all
    - MaintenanceModeOrchestrator.update
    """
    # Reuse 00200's response sequence: summary, bulk /switches GET, POST.
    method_name = "test_maintenance_mode_00200"

    def responses():
        yield responses_maintenance_mode(f"{method_name}a")  # summary
        yield responses_maintenance_mode(f"{method_name}b")  # bulk switches GET (switch A normal)
        yield responses_maintenance_mode(f"{method_name}c")  # POST 207 success

    gen_responses = ResponseGenerator(responses())
    config = [
        {
            "mode": "maintenance",
            "deploy": True,
            "blocking": True,
            "ticket_id": "CHG-1",
            "switches": [{"switch_ip": "192.168.12.131"}],
        }
    ]
    rest_send = _build_rest_send(gen_responses, config=config)
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)
    model = MaintenanceModeModel.from_config(config[0])

    with does_not_raise():
        instance.query_all()
        instance.update(model)

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert "switchActions/changeSystemMode" in rest_send.path
    assert rest_send.committed_payload == {"mode": "maintenance", "switchIds": ["9UOJ3E8A6O9"]}


def test_maintenance_mode_00250() -> None:
    """
    # Summary

    Verify `update` does NOT emit `deploy=false` / `blocking=false` on the URL when the user did
    not opt into them. The model defaults both fields to `False`; the endpoint's `to_query_string`
    excludes None but not False, so an unconditional push would put `?deploy=false&blocking=false`
    on every request.

    ## Test

    - Config with mode only (no deploy, no blocking, no ticket_id)
    - POST URL must not contain any query string at all

    ## Classes and Methods

    - MaintenanceModeOrchestrator.update
    """
    # Reuse 00200's response sequence: summary, bulk switches GET, POST.
    method_name = "test_maintenance_mode_00200"

    def responses():
        yield responses_maintenance_mode(f"{method_name}a")  # summary
        yield responses_maintenance_mode(f"{method_name}b")  # bulk switches GET (switch A normal)
        yield responses_maintenance_mode(f"{method_name}c")  # POST 207 success

    gen_responses = ResponseGenerator(responses())
    config = [{"mode": "maintenance", "switches": [{"switch_ip": "192.168.12.131"}]}]
    rest_send = _build_rest_send(gen_responses, config=config)
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)
    model = MaintenanceModeModel.from_config(config[0])

    with does_not_raise():
        instance.update(model)

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert "deploy" not in rest_send.path
    assert "blocking" not in rest_send.path
    assert "?" not in rest_send.path


# =============================================================================
# Test: create / delete / query_one delegation
# =============================================================================


def test_maintenance_mode_00300() -> None:
    """
    # Summary

    `create` delegates to `update`.

    ## Classes and Methods

    - MaintenanceModeOrchestrator.create
    """
    method_name = "test_maintenance_mode_00200"  # reuse 00200's response sequence (create == update)

    def responses():
        yield responses_maintenance_mode(f"{method_name}a")
        yield responses_maintenance_mode(f"{method_name}b")
        yield responses_maintenance_mode(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())
    config = [
        {
            "mode": "maintenance",
            "deploy": True,
            "blocking": True,
            "ticket_id": "CHG-1",
            "switches": [{"switch_ip": "192.168.12.131"}],
        }
    ]
    rest_send = _build_rest_send(gen_responses, config=config)
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)
    model = MaintenanceModeModel.from_config(config[0])

    with does_not_raise():
        instance.create(model)

    assert rest_send.verb == HttpVerbEnum.POST.value


def test_maintenance_mode_00310() -> None:
    """
    # Summary

    `delete` always raises `NotImplementedError`.

    ## Classes and Methods

    - MaintenanceModeOrchestrator.delete
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)
    model = MaintenanceModeModel(mode="normal")

    match = r"state 'deleted' is not supported"
    with pytest.raises(NotImplementedError, match=match):
        instance.delete(model)


def test_maintenance_mode_00320() -> None:
    """
    # Summary

    `query_one` delegates to `query_all`.

    ## Classes and Methods

    - MaintenanceModeOrchestrator.query_one
    """
    method_name = "test_maintenance_mode_00100"  # reuse the query_all happy-path fixtures

    def responses():
        yield responses_maintenance_mode(f"{method_name}a")
        yield responses_maintenance_mode(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    config = [
        {
            "mode": "maintenance",
            "switches": [{"switch_ip": "192.168.12.131"}, {"switch_ip": "192.168.12.151"}],
        }
    ]
    rest_send = _build_rest_send(gen_responses, config=config)
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)
    model = MaintenanceModeModel.from_config(config[0])

    with does_not_raise():
        result = instance.query_one(model)

    assert isinstance(result, list)
    assert len(result) == 1


# =============================================================================
# Test: 207 parser helper (direct)
# =============================================================================


@pytest.mark.parametrize(
    "body,should_raise",
    [
        ({"items": [{"status": "success", "switchId": "X"}]}, False),
        ({"items": []}, False),
        ({"items": [{"status": "SUCCESS", "switchId": "X"}]}, False),  # case-insensitive
        ({"unrelated": "no items key"}, False),
        ("not a dict", False),
        (None, False),
    ],
    ids=["all-success", "empty-items", "case-insensitive", "missing-items-key", "non-dict", "none"],
)
def test_maintenance_mode_00400(body, should_raise: bool) -> None:
    """
    # Summary

    Verify `_raise_on_207_failures` is permissive about malformed/successful bodies and only raises on
    real per-switch failures.

    ## Classes and Methods

    - MaintenanceModeOrchestrator._raise_on_207_failures
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = MaintenanceModeOrchestrator(rest_send=rest_send)

    if should_raise:
        with pytest.raises(RuntimeError):
            instance._raise_on_207_failures(body, ["1.1.1.1"], ["X"])
    else:
        with does_not_raise():
            instance._raise_on_207_failures(body, ["1.1.1.1"], ["X"])
