# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""State-machine coverage for fabric replacement preservation."""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ebgp_vxlan import (
    ManageAiEbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ibgp_vxlan import (
    ManageAiIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ebgp_vxlan import (
    ManageEbgpFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_external import (
    ManageExternalFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ibgp_vxlan import (
    ManageIbgpFabricOrchestrator,
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

FABRIC_CASES = (
    (
        "external",
        ManageExternalFabricOrchestrator,
        "externalConnectivity",
        "aiMonitoring",
        True,
    ),
    ("ibgp", ManageIbgpFabricOrchestrator, "vxlanIbgp", "borderCount", 0),
    ("ebgp", ManageEbgpFabricOrchestrator, "vxlanEbgp", "borderCount", 0),
    (
        "ai_ibgp",
        ManageAiIbgpVxlanFabricOrchestrator,
        "aimlVxlanIbgp",
        "borderCount",
        0,
    ),
    (
        "ai_ebgp",
        ManageAiEbgpVxlanFabricOrchestrator,
        "aimlVxlanEbgp",
        "borderCount",
        0,
    ),
)


def _existing_response(fabric_type: str, opaque_key: str, opaque_value) -> dict:
    management = {
        "type": fabric_type,
        "bgpAsn": "65001",
        opaque_key: opaque_value,
    }
    if fabric_type.endswith("Ebgp"):
        management["bgpAsnRange"] = "3001-4000"
    if fabric_type != "externalConnectivity":
        management["ntpAuthKey"] = "encrypted-controller-secret"
    if fabric_type.endswith("Ibgp"):
        management.update(
            {
                "vrfLiteIpv6SubnetRange": "fd00::a33:0/112",
                "vrfLiteIpv6SubnetTargetMask": 126,
            }
        )
    return {
        "name": "fabric1",
        "category": "fabric",
        "licenseTier": "essentials",
        "location": {"latitude": 37.33939, "longitude": -121.89496},
        "management": management,
    }


def _replacement_spy(orchestrator_class, response):
    """Build a family-specific orchestrator that records updates without HTTP."""

    class ReplacementSpy(orchestrator_class):
        def model_post_init(self, __context) -> None:
            super().model_post_init(__context)
            self._updated: list = []

        def query_all(self) -> ResponseType:
            return [deepcopy(response)]

        def update(self, model_instance, **kwargs) -> ResponseType:
            self._updated.append(model_instance)
            return {}

    return ReplacementSpy


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


def _module(
    state: str,
    license_tier: str | None = None,
    check_mode: bool = False,
) -> MockAnsibleModule:
    module = MockAnsibleModule()
    module.check_mode = check_mode
    module.no_log_values = set()
    config = {"fabric_name": "fabric1", "management": {"bgp_asn": "65001"}}
    if license_tier is not None:
        config["license_tier"] = license_tier
    module.params = {
        "state": state,
        "config": [config],
        "output_level": "normal",
        "ignore_errors": False,
    }
    return module


@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
@pytest.mark.parametrize(
    "case_name,orchestrator_class,fabric_type,opaque_key,opaque_value",
    FABRIC_CASES,
    ids=[case[0] for case in FABRIC_CASES],
)
def test_nd_state_machine_fabric_replacement_00010(
    state,
    case_name,
    orchestrator_class,
    fabric_type,
    opaque_key,
    opaque_value,
) -> None:
    """
    # Summary

    Verify all three write states remain idempotent for every fabric family when
    the controller returns location defaults, dynamic allocation, and hidden
    writable state.

    ## Classes and Methods

    - NDStateMachine._manage_create_update_state()
    - NDBaseModel.prepare_for_replacement()
    """
    del case_name
    response = _existing_response(fabric_type, opaque_key, opaque_value)
    spy = _replacement_spy(orchestrator_class, response)(rest_send=_rest_send())
    instance = NDStateMachine(module=_module(state), model_orchestrator=spy)

    instance.manage_state()

    assert instance.model_orchestrator._updated == []
    assert instance.output.format()["changed"] is False
    if fabric_type != "externalConnectivity":
        assert "encrypted-controller-secret" in instance.module.no_log_values


@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
@pytest.mark.parametrize(
    "case_name,orchestrator_class,fabric_type,opaque_key,opaque_value",
    FABRIC_CASES,
    ids=[case[0] for case in FABRIC_CASES],
)
def test_nd_state_machine_fabric_replacement_00020(
    state,
    case_name,
    orchestrator_class,
    fabric_type,
    opaque_key,
    opaque_value,
) -> None:
    """
    # Summary

    Verify a real update in every write state and fabric family applies explicit
    user intent while hidden existing values survive the outgoing payload and
    stay out of normalized output.

    ## Classes and Methods

    - NDStateMachine._manage_create_update_state()
    - NDBaseModel.prepare_for_replacement()
    - NDBaseModel.to_payload()
    - NDBaseModel.to_config()
    """
    del case_name
    response = _existing_response(fabric_type, opaque_key, opaque_value)
    spy = _replacement_spy(orchestrator_class, response)(rest_send=_rest_send())
    instance = NDStateMachine(
        module=_module(state, license_tier="premier"), model_orchestrator=spy
    )

    instance.manage_state()

    assert len(instance.model_orchestrator._updated) == 1
    updated = instance.model_orchestrator._updated[0]
    assert updated.license_tier == "premier"
    management_payload = updated.to_payload()["management"]
    management_config = updated.to_config()["management"]
    assert management_payload[opaque_key] == opaque_value
    assert opaque_key not in management_config
    if fabric_type.endswith("Ebgp"):
        assert updated.management.bgp_asn_range == "3001-4000"
    if fabric_type != "externalConnectivity":
        assert management_payload["ntpAuthKey"] == "encrypted-controller-secret"
        assert "ntpAuthKey" not in management_config
        assert "encrypted-controller-secret" in instance.module.no_log_values
    assert instance.output.format()["changed"] is True


def test_nd_state_machine_fabric_replacement_00030() -> None:
    """
    # Summary

    Verify check mode reports a replacement change and prepares its dynamic and
    hidden state without calling the update operation.

    ## Classes and Methods

    - NDStateMachine._manage_create_update_state()
    - NDStateMachine._execute_operation()
    """
    response = _existing_response("vxlanEbgp", "borderCount", 0)
    spy = _replacement_spy(ManageEbgpFabricOrchestrator, response)(
        rest_send=_rest_send()
    )
    instance = NDStateMachine(
        module=_module("replaced", license_tier="premier", check_mode=True),
        model_orchestrator=spy,
    )

    instance.manage_state()

    intended = instance.existing.get("fabric1")
    assert instance.model_orchestrator._updated == []
    assert intended.license_tier == "premier"
    assert intended.management.bgp_asn_range == "3001-4000"
    assert intended.to_payload()["management"]["borderCount"] == 0
    assert instance.output.format()["changed"] is True
