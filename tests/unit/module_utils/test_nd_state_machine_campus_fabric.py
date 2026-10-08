# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""State-machine coverage for Campus iBGP VXLAN fabric CRUD and idempotence."""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_campus_ibgp_vxlan import (
    ManageCampusIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    ResponseType,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import (
    MockAnsibleModule,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import (
    ResponseGenerator,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def _fabric_response(fabric_name: str = "campus1", **overrides) -> dict:
    response = {
        "name": fabric_name,
        "category": "fabric",
        "licenseTier": "essentials",
        # ND returns this deterministic location even when minimal desired
        # config omits location entirely.
        "location": {"latitude": 37.33939, "longitude": -121.89496},
        "management": {
            "type": "vxlanCampus",
            "bgpAsn": "65001",
            # Deterministic management echoes that previously caused
            # replaced/overridden to update on every run.
            "siteId": "65001",
            "bgpFastConvergence": False,
        },
    }
    response.update(overrides)
    return response


def _rest_send() -> RestSend:
    module = MockAnsibleModule()
    sender = Sender()
    sender.ansible_module = module
    sender.gen = ResponseGenerator(iter(()))

    rest_send = RestSend({"check_mode": False})
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _module(state: str, config: list[dict]) -> MockAnsibleModule:
    module = MockAnsibleModule()
    module.check_mode = False
    module.no_log_values = set()
    module.params = {
        "state": state,
        "config": config,
        "output_level": "normal",
        "ignore_errors": False,
    }
    return module


def _spy(existing: list[dict]) -> ManageCampusIbgpVxlanFabricOrchestrator:
    class CampusFabricSpy(ManageCampusIbgpVxlanFabricOrchestrator):
        def model_post_init(self, __context) -> None:
            super().model_post_init(__context)
            self._calls: list[tuple[str, object]] = []

        def query_all(self) -> ResponseType:
            return deepcopy(existing)

        def create(self, model_instance, **kwargs) -> ResponseType:
            self._calls.append(("create", model_instance))
            return {}

        def update(self, model_instance, **kwargs) -> ResponseType:
            self._calls.append(("update", model_instance))
            return {}

        def delete(self, model_instance, **kwargs) -> ResponseType:
            self._calls.append(("delete", model_instance))
            return {}

    return CampusFabricSpy(rest_send=_rest_send())


def _minimal_config(fabric_name: str = "campus1") -> dict:
    return {"fabric_name": fabric_name, "management": {"bgp_asn": "65001"}}


def _run(state: str, config: list[dict], existing: list[dict]) -> NDStateMachine:
    instance = NDStateMachine(
        module=_module(state, config),
        model_orchestrator=_spy(existing),
    )
    instance.manage_state()
    return instance


def test_nd_state_machine_campus_fabric_00010() -> None:
    """A missing Campus fabric is created through the standard state machine."""
    instance = _run("merged", [_minimal_config()], [])

    calls = instance.model_orchestrator._calls
    assert [operation_name for operation_name, _model in calls] == ["create"]
    created = calls[0][1]
    assert created.get_identifier_value() == "campus1"
    assert created.to_payload()["management"]["siteId"] == "65001"
    assert len(instance.sent) == 1
    assert instance.output.format()["changed"] is True


def test_nd_state_machine_campus_fabric_00020() -> None:
    """A changed Campus fabric is updated through the exact-state path."""
    config = _minimal_config()
    config["license_tier"] = "premier"

    instance = _run("replaced", [config], [_fabric_response()])

    calls = instance.model_orchestrator._calls
    assert [operation_name for operation_name, _model in calls] == ["update"]
    updated = calls[0][1]
    assert updated.license_tier == "premier"
    assert len(instance.sent) == 1
    assert instance.output.format()["changed"] is True


@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_nd_state_machine_campus_fabric_00030(state: str) -> None:
    """Omitted location and deterministic controller echoes stay idempotent."""
    desired = _minimal_config()
    controller_response = _fabric_response()

    assert "location" not in desired
    assert controller_response["location"] == {
        "latitude": 37.33939,
        "longitude": -121.89496,
    }

    instance = _run(state, [desired], [controller_response])

    assert instance.model_orchestrator._calls == []
    assert len(instance.sent) == 0
    assert len(instance.removed) == 0
    assert instance.output.format()["changed"] is False


def test_nd_state_machine_campus_fabric_00040() -> None:
    """Overridden retains the proposed Campus fabric and deletes other Campus fabrics."""
    instance = _run(
        "overridden",
        [_minimal_config("campus1")],
        [_fabric_response("campus1"), _fabric_response("campus2")],
    )

    calls = instance.model_orchestrator._calls
    assert [operation_name for operation_name, _model in calls] == ["delete"]
    deleted = calls[0][1]
    assert deleted.get_identifier_value() == "campus2"
    assert len(instance.sent) == 0
    assert len(instance.removed) == 1
    assert instance.output.format()["changed"] is True


def test_nd_state_machine_campus_fabric_00050() -> None:
    """Deleted resolves an identifier-only config to the existing Campus fabric."""
    instance = _run("deleted", [{"fabric_name": "campus1"}], [_fabric_response()])

    calls = instance.model_orchestrator._calls
    assert [operation_name for operation_name, _model in calls] == ["delete"]
    deleted = calls[0][1]
    assert deleted.get_identifier_value() == "campus1"
    assert len(instance.sent) == 0
    assert len(instance.removed) == 1
    assert instance.output.format()["changed"] is True


def test_nd_state_machine_campus_fabric_00060() -> None:
    """A partial merged update preserves the ASN already stored on the fabric."""
    instance = _run(
        "merged",
        [{"fabric_name": "campus1", "management": {"performance_monitoring": True}}],
        [_fabric_response()],
    )

    calls = instance.model_orchestrator._calls
    assert [operation_name for operation_name, _model in calls] == ["update"]
    updated = calls[0][1]
    assert updated.management.bgp_asn == "65001"
    assert updated.management.performance_monitoring is True


def test_nd_state_machine_campus_fabric_00070() -> None:
    """The same partial input fails locally when the named fabric does not exist."""
    with pytest.raises(NDStateMachineError, match=r"management\.bgp_asn is required when creating.*campus1"):
        _run(
            "merged",
            [{"fabric_name": "campus1", "management": {"performance_monitoring": True}}],
            [],
        )


@pytest.mark.parametrize("bgp_asn", ("65001", "65002"))
def test_nd_state_machine_campus_fabric_00080(bgp_asn: str) -> None:
    """Merged ASN input must not reset an existing custom site ID."""
    existing = _fabric_response()
    existing["management"]["siteId"] = "12345"

    instance = _run(
        "merged",
        [{"fabric_name": "campus1", "management": {"bgp_asn": bgp_asn}}],
        [existing],
    )

    calls = instance.model_orchestrator._calls
    assert [name for name, _model in calls] == ([] if bgp_asn == "65001" else ["update"])
    assert instance.existing.get("campus1").management.site_id == "12345"
    assert instance.existing.get("campus1").management.bgp_asn == bgp_asn
    if calls:
        assert calls[0][1].to_payload()["management"]["siteId"] == "12345"


@pytest.mark.parametrize("state", ("replaced", "overridden"))
def test_nd_state_machine_campus_fabric_00090(state: str) -> None:
    """Exact-state omission still applies the ASN-derived site ID."""
    existing = _fabric_response()
    existing["management"]["siteId"] = "12345"

    instance = _run(state, [_minimal_config()], [existing])

    calls = instance.model_orchestrator._calls
    assert [name for name, _model in calls] == ["update"]
    assert calls[0][1].management.site_id == "65001"
    assert calls[0][1].to_payload()["management"]["siteId"] == "65001"


def test_nd_state_machine_campus_fabric_00100() -> None:
    """An unrelated IPv6 Campus fabric does not block a merged update."""
    target = _fabric_response("campus1")
    target["management"]["siteId"] = "12345"
    unrelated = _fabric_response("campus2")
    unrelated["management"].update(
        {
            "dhcpStartAddress": "2001:db8::10",
            "dhcpEndAddress": "2001:db8::20",
            "managementGateway": "2001:db8::1",
        }
    )

    instance = _run(
        "merged",
        [{"fabric_name": "campus1", "management": {"bgp_asn": "65001", "performance_monitoring": True}}],
        [target, unrelated],
    )

    calls = instance.model_orchestrator._calls
    assert [name for name, _model in calls] == ["update"]
    assert calls[0][1].get_identifier_value() == "campus1"
    assert calls[0][1].management.site_id == "12345"
    assert instance.existing.get("campus2").management.dhcp_start_address == "2001:db8::10"
    assert instance.existing.get("campus2").management.dhcp_end_address == "2001:db8::20"
    assert instance.existing.get("campus2").management.management_gateway == "2001:db8::1"
