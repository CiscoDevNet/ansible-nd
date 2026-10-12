# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""An opt-in send cap leaves existing transport retry defaults untouched."""

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def make_transport(codes):
    """Build a real shared response handler around a synthetic sender."""
    path = "/api/v1/manage/fabrics/fab1/interfaceActions/breakout"
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(
        iter({"RETURN_CODE": code, "METHOD": "POST", "REQUEST_PATH": path, "MESSAGE": "OK" if code == 200 else "Error", "DATA": {}} for code in codes)
    )
    rest = RestSend({})
    rest.sender = sender
    rest.response_handler = ResponseHandler()
    rest.unit_test = True
    rest.timeout = 10
    rest.send_interval = 1
    rest.path = path
    rest.verb = HttpVerbEnum.POST
    rest.payload = {"interfaces": []}
    return rest


def test_legacy_default_still_retries_retryable_response():
    rest = make_transport([500, 200])
    assert rest.max_attempts is None
    rest.commit()
    assert rest.return_code == 200
    assert rest.success


def test_one_attempt_retains_first_failure_without_replaying():
    rest = make_transport([500, 200])
    rest.max_attempts = 1
    rest.commit()
    assert rest.return_code == 500
    assert not rest.success
    assert rest.response_count == 1


def test_two_attempt_cap_stops_before_third_response():
    rest = make_transport([500, 500, 200])
    rest.max_attempts = 2
    rest.commit()
    assert rest.return_code == 500


@pytest.mark.parametrize("value", [0, -1, True, False, "1", 1.5])
def test_invalid_attempt_cap_rejected(value):
    with pytest.raises(ValueError, match="positive integer"):
        RestSend({}).max_attempts = value


def test_cap_can_be_restored_to_default():
    rest = RestSend({})
    rest.max_attempts = 1
    rest.max_attempts = None
    assert rest.max_attempts is None


def test_retained_payload_can_be_cleared_before_diagnostic_get():
    rest = RestSend({})
    rest.payload = {"interfaces": [{"switchId": "S", "interfaceName": "Ethernet1/50"}]}
    rest.clear_payload()
    assert rest.payload is None


def test_response_generation_advances_per_reply_not_per_completed_commit():
    rest = make_transport([500, 200])
    assert rest.response_generation == 0
    rest.commit()
    assert rest.response_count == 1
    assert rest.response_generation == 2
    assert rest.return_code == 200


def test_first_attempt_transport_loss_does_not_advance_response_generation(monkeypatch):
    rest = make_transport([200])

    def timeout():
        raise TimeoutError("No response received")

    monkeypatch.setattr(rest.sender, "commit", timeout)
    with pytest.raises(TimeoutError, match="No response"):
        rest.commit()
    assert rest.response_count == 0
    assert rest.response_generation == 0


def test_retry_transport_loss_keeps_actual_received_response_token(monkeypatch):
    rest = make_transport([500, 200])
    rest.verb = HttpVerbEnum.GET
    commit = rest.sender.commit
    attempts = []

    def receive_then_timeout():
        attempts.append(1)
        if len(attempts) == 2:
            raise TimeoutError("Retry response lost")
        commit()

    monkeypatch.setattr(rest.sender, "commit", receive_then_timeout)
    with pytest.raises(TimeoutError, match="Retry response"):
        rest.commit()
    assert len(attempts) == 2
    assert rest.response_count == 0
    assert rest.response_generation == 1
    assert rest.return_code == 500


def test_handler_error_after_received_response_still_advances_token(monkeypatch):
    rest = make_transport([200])

    def handler_error():
        raise ValueError("Unable to handle received response")

    monkeypatch.setattr(rest.response_handler, "commit", handler_error)
    with pytest.raises(ValueError, match="Unable to handle"):
        rest.commit()
    assert rest.response_count == 0
    assert rest.response_generation == 1
    assert rest.return_code == 200
