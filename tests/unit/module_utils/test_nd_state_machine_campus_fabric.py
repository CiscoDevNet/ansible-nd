# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""State-machine coverage for Campus iBGP VXLAN fabric CRUD and idempotence."""

from __future__ import annotations

from copy import deepcopy

import pytest
from ansible.module_utils.common.arg_spec import ModuleArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import FabricCampusIbgpVxlanModel

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
    rest_send.controller_product_version = "4.3.1"
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


def _memory_run(backend: dict, config: dict, state: str, version: str) -> NDStateMachine:
    """Run the actual state lifecycle while retaining callback wire bodies for repeat checks."""

    class MemoryCampusOrchestrator(ManageCampusIbgpVxlanFabricOrchestrator):
        def query_all(self) -> ResponseType:
            return [deepcopy(backend["response"])] if backend["response"] is not None else []

        def create(self, model_instance, **kwargs) -> ResponseType:
            return self._remember("create", model_instance)

        def update(self, model_instance, **kwargs) -> ResponseType:
            return self._remember("update", model_instance)

        def _remember(self, operation: str, model_instance) -> ResponseType:
            payload = model_instance.to_payload()
            if version == "4.2.1":
                assert "bgpFastConvergence" not in payload["management"]
            backend["writes"].append((operation, deepcopy(payload)))
            backend["response"] = deepcopy(payload)
            if backend.get("omit_inactive_http") and not payload["management"]["nxapi"]:
                backend["response"]["management"].pop("nxapiHttp", None)
            return {}

    rest = _rest_send()
    rest.controller_product_version = version
    machine = NDStateMachine(module=_module(state, [deepcopy(config)]), model_orchestrator=MemoryCampusOrchestrator(rest_send=rest))
    machine.manage_state()
    return machine


@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_native_defaults_create_and_repeat_without_writes(version: str, state: str) -> None:
    """Default materialization and release filtering apply before every create/exact comparison."""
    backend = {"response": None, "writes": []}
    config = _minimal_config()
    created = _memory_run(backend, config, state, version)
    assert created.output.format()["changed"] is True
    assert [operation for operation, _ in backend["writes"]] == ["create"]
    management = backend["response"]["management"]
    assert management["fabricMtu"] == management["l2HostInterfaceMtu"] == 9198
    assert management["nxapi"] is management["nxapiHttp"] is True
    assert backend["response"]["telemetryCollectionType"] == "inBand"
    assert _memory_run(backend, config, state, version).output.format()["changed"] is False
    assert len(backend["writes"]) == 1


@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_scoped_out_management_controls_survive_updates_and_repeated_exact_states(version: str, state: str) -> None:
    """An unrelated managed update preserves opaque NetFlow and hidden IPv6 state on both releases."""
    backend = {"response": None, "writes": []}
    config = _minimal_config()
    _memory_run(backend, config, state, version)
    opaque = {
        "netflowSettings": {"netflow": True, "netflowExporterCollection": [{"exporterName": "existing", "udpPort": 2055}]},
        "perVrfLoopbackAutoProvisionIpv6": True,
        "perVrfLoopbackIpv6Range": "2001:db8:5::/112",
    }
    backend["response"]["management"].update(deepcopy(opaque))
    backend["writes"].clear()
    assert _memory_run(backend, config, state, version).output.format()["changed"] is False
    config["management"]["performance_monitoring"] = not backend["response"]["management"]["performanceMonitoring"]
    updated = _memory_run(backend, config, state, version)
    assert updated.output.format()["changed"] is True
    assert [operation for operation, _ in backend["writes"]] == ["update"]
    for alias, value in opaque.items():
        assert backend["response"]["management"][alias] == value
    assert _memory_run(backend, config, state, version).output.format()["changed"] is False
    assert len(backend["writes"]) == 1

    gathered = FabricCampusIbgpVxlanModel.from_response(backend["response"]).to_gathered_config()
    for name in ("netflow_settings", "per_vrf_loopback_auto_provision_ipv6", "per_vrf_loopback_ipv6_range"):
        assert name not in gathered["management"]
    checked = ModuleArgumentSpecValidator(FabricCampusIbgpVxlanModel.get_argument_spec()).validate({"state": state, "config": [gathered]})
    assert checked.error_messages == []
    assert _memory_run(backend, checked.validated_parameters["config"][0], state, version).output.format()["changed"] is False


@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_native_defaults_preserve_merge_omission_and_reset_exact_state(version: str, state: str) -> None:
    """The default correction keeps existing merged semantics and ordinary exact-state reset behavior."""
    backend = {"response": None, "writes": []}
    config = _minimal_config()
    _memory_run(backend, config, "merged", version)
    backend["response"]["management"].update({"nxapi": False, "nxapiHttp": False, "fabricMtu": 9000, "l2HostInterfaceMtu": 9000})
    backend["writes"].clear()
    changed = _memory_run(backend, config, state, version).output.format()["changed"]
    assert changed is (state != "merged")
    expected = False if state == "merged" else True
    assert backend["response"]["management"]["nxapi"] is expected
    assert backend["response"]["management"]["nxapiHttp"] is expected
    assert backend["response"]["management"]["fabricMtu"] == (9000 if state == "merged" else 9198)
    assert backend["response"]["management"]["l2HostInterfaceMtu"] == (9000 if state == "merged" else 9198)
    assert _memory_run(backend, config, state, version).output.format()["changed"] is False


@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
@pytest.mark.parametrize("bgp_asn", ("70000", "1.1"))
def test_expanded_asn_fails_before_any_callback_on_4_2_and_repeats_cleanly_on_4_3(state: str, bgp_asn: str) -> None:
    """Release-specific ASN constraints reject unsupported writes without gating the whole field."""
    config = _minimal_config()
    config["management"]["bgp_asn"] = bgp_asn
    older = {"response": None, "writes": []}
    with pytest.raises(NDStateMachineError, match=r"management\.bgp_asn.*ND release-specific format"):
        _memory_run(older, config, state, "4.2.1")
    assert older["writes"] == []
    assert older["response"] is None

    newer = {"response": None, "writes": []}
    assert _memory_run(newer, config, state, "4.3.1").output.format()["changed"] is True
    assert newer["response"]["management"]["bgpAsn"] == bgp_asn
    assert _memory_run(newer, config, state, "4.3.1").output.format()["changed"] is False
    assert [operation for operation, _ in newer["writes"]] == ["create"]


@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_disabled_nxapi_http_controller_omission_does_not_repeat_writes(version, state):
    backend = {"response": None, "writes": [], "omit_inactive_http": True}
    config = _minimal_config()
    _memory_run(backend, config, state, version)
    backend["writes"].clear()
    config["management"].update(nxapi=False, nxapi_http=False)
    assert _memory_run(backend, config, state, version).output.format()["changed"] is True
    assert "nxapiHttp" not in backend["response"]["management"]
    assert backend["writes"][0][1]["management"]["nxapiHttp"] is False
    assert _memory_run(backend, config, state, version).output.format()["changed"] is False
    assert len(backend["writes"]) == 1

    # A merged input omitting the parent must use existing disabled state.
    partial = {"fabric_name": "campus1", "management": {"nxapi_http": False}}
    assert _memory_run(backend, partial, "merged", version).output.format()["changed"] is False

    config["management"]["nxapi"] = True
    assert _memory_run(backend, config, state, version).output.format()["changed"] is True
    assert backend["response"]["management"]["nxapiHttp"] is False
    assert _memory_run(backend, config, state, version).output.format()["changed"] is False
    config["management"]["nxapi_http"] = True
    assert _memory_run(backend, config, state, version).output.format()["changed"] is True
    assert backend["response"]["management"]["nxapiHttp"] is True
    assert _memory_run(backend, config, state, version).output.format()["changed"] is False
    assert len(backend["writes"]) == 3
