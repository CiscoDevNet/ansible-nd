# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Representative nd-4.3.1-manage HA response fixtures and a recording sender."""

from collections.abc import Iterable
from copy import deepcopy
from typing import Any
from urllib.parse import urlsplit

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

# Scripted controller transport

ControllerResponse = dict[str, Any]
RecordedCall = tuple[HttpVerbEnum, str, dict[str, Any] | None]


class RecordingHaSender(Sender):
    """Record each controller request and serve its scripted response."""

    def __init__(self, responses: Iterable[ControllerResponse | Exception] = ()) -> None:
        super().__init__()
        self.calls: list[RecordedCall] = []
        self._scripted_responses = tuple(responses)

    def commit(self) -> None:
        self.calls.append((self.verb, self.path, deepcopy(self.payload)))

    @property
    def response(self) -> ControllerResponse:
        if not self.calls:
            raise AssertionError("No controller request has been committed")
        verb, path, _payload = self.calls[-1]
        request_number = len(self.calls)
        if request_number > len(self._scripted_responses):
            raise AssertionError(f"No scripted response for request {request_number}: {verb.value} {path}")
        scripted_response = self._scripted_responses[request_number - 1]
        if isinstance(scripted_response, Exception):
            raise scripted_response
        # The real HttpApi plugin attaches this request context before response handling.
        return {**deepcopy(scripted_response), "METHOD": verb.value, "REQUEST_PATH": path}


def posted_action_payloads(calls: Iterable[RecordedCall]) -> list[tuple[str, dict[str, Any] | None]]:
    """Extract the action name and payload from each recorded POST."""
    return [(urlsplit(path).path.rsplit("/", 1)[-1], payload) for verb, path, payload in calls if verb == HttpVerbEnum.POST]


# Manage API response builders


def controller_response(data: object, code: int = 200) -> ControllerResponse:
    return {"RETURN_CODE": code, "MESSAGE": "test response", "DATA": data}


def ha_switch_row(
    switch_id: str, peer_id: str | None = None, status: str | None = "unpaired", *, topology: str = "nonVpc", role: str | None = None, **overrides: Any
) -> dict[str, Any]:
    info = {
        "id": switch_id,
        "name": f"leaf-{switch_id}",
        "ip": "10.1.1.1",
        "operStatus": "connected",
        "peerId": peer_id,
        "peerIp": "10.1.1.2" if peer_id else None,
        "peerName": f"leaf-{peer_id}" if peer_id else None,
        "vpcRole": (role or "primary") if topology == "vpc" else "notApplicable",
        "haPaired": status,
        **overrides,
    }
    if topology == "vpc":
        info.setdefault("vpcDomain", 1)
    return {"pairingType": topology, "switchInfo": info}


def inventory_responses(*rows: dict[str, Any]) -> list[ControllerResponse]:
    """Return an optional populated page followed by the empty terminal page."""
    pages = [controller_response({"rows": list(rows)})] if rows else []
    return [*pages, controller_response({"rows": []})]


def recommendations_response(*rows: dict[str, Any]) -> ControllerResponse:
    return controller_response({"rows": list(rows)})


def action_response(success: Iterable[str] = (), failure: Iterable[str] = (), *, rows: Iterable[dict[str, Any]] = ()) -> ControllerResponse:
    return controller_response(
        {
            "rows": list(rows),
            "configPreviewRows": [],
            "results": {
                "successResults": [{"name": name, "status": "success", "message": "accepted"} for name in success],
                "failureResults": [{"name": name, "status": "failed", "message": "rejected"} for name in failure],
            },
        },
        202,
    )


# Ansible pair configuration


def pair_config(switch_id: str, peer_switch_id: str) -> dict[str, str]:
    return {"switch_id": switch_id, "peer_switch_id": peer_switch_id}
