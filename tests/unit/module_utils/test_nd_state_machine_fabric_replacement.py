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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_vxlan import (
    FabricGroupVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import (
    FabricExternalConnectivityModel,
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
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_group_vxlan import (
    ManageFabricGroupVxlanOrchestrator,
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
        "hypershieldConnectivityProxyServer",
        "proxy.example.test",
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
    # The controller-response fixtures include ND 4.3.1 authentication fields.
    rest_send.controller_product_version = "4.3.1"
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
@pytest.mark.parametrize("version", ("4.2.1", "4.2(1)", "4.3.1"))
@pytest.mark.parametrize(("orchestrator", "fabric_type"), (
    (ManageIbgpFabricOrchestrator, "vxlanIbgp"),
    (ManageAiIbgpVxlanFabricOrchestrator, "aimlVxlanIbgp"),
))
def test_ibgp_absent_newer_release_defaults_remain_idempotent(state, version, orchestrator, fabric_type) -> None:
    response = {
        "name": "fabric1", "category": "fabric", "licenseTier": "essentials",
        "management": {"type": fabric_type, "bgpAsn": "65001"},
    }
    rest = _rest_send()
    rest.controller_product_version = version
    spy = _replacement_spy(orchestrator, response)(rest_send=rest)
    instance = NDStateMachine(module=_module(state), model_orchestrator=spy)
    instance.manage_state()
    assert spy._updated == []
    assert instance.output.format()["changed"] is False


@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_ibgp_explicit_newer_default_changes_a_nondefault_setting(state) -> None:
    response = {
        "name": "fabric1", "category": "fabric", "licenseTier": "essentials",
        "management": {"type": "vxlanIbgp", "bgpAsn": "65001", "bfdMinRxInterval": 60},
    }
    rest = _rest_send()
    rest.controller_product_version = "4.3.1"
    spy = _replacement_spy(ManageIbgpFabricOrchestrator, response)(rest_send=rest)
    module = _module(state)
    module.params["config"][0]["management"]["bfd_min_rx_interval"] = 50
    instance = NDStateMachine(module=module, model_orchestrator=spy)
    instance.manage_state()
    assert len(spy._updated) == 1
    assert spy._updated[0].to_payload()["management"]["bfdMinRxInterval"] == 50


@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_ibgp_omitted_newer_default_keeps_existing_merge_and_resets_exact_states(state) -> None:
    response = {
        "name": "fabric1", "category": "fabric", "licenseTier": "essentials",
        "management": {"type": "vxlanIbgp", "bgpAsn": "65001", "bfdMinRxInterval": 60},
    }
    rest = _rest_send()
    rest.controller_product_version = "4.3.1"
    spy = _replacement_spy(ManageIbgpFabricOrchestrator, response)(rest_send=rest)
    instance = NDStateMachine(module=_module(state), model_orchestrator=spy)
    instance.manage_state()
    assert len(spy._updated) == (0 if state == "merged" else 1)
    if spy._updated:
        assert spy._updated[0].to_payload()["management"]["bfdMinRxInterval"] == 50


@pytest.mark.parametrize("version", (None, "4.2.1", "4.2(1)", "4.3.1"))
@pytest.mark.parametrize(("orchestrator", "fabric_type"), (
    (ManageIbgpFabricOrchestrator, "vxlanIbgp"),
    (ManageAiIbgpVxlanFabricOrchestrator, "aimlVxlanIbgp"),
))
def test_ibgp_real_merged_update_does_not_replay_unreported_release_defaults(version, orchestrator, fabric_type) -> None:
    response = {
        "name": "fabric1", "category": "fabric", "licenseTier": "essentials",
        "management": {"type": fabric_type, "bgpAsn": "65001"},
    }
    rest = _rest_send()
    rest.controller_product_version = version
    spy = _replacement_spy(orchestrator, response)(rest_send=rest)
    instance = NDStateMachine(module=_module("merged", license_tier="premier"), model_orchestrator=spy)
    instance.manage_state()
    assert len(spy._updated) == 1
    payload = spy._updated[0].to_payload()
    assert payload["licenseTier"] == "premier"
    assert "bfdMinRxInterval" not in payload["management"]
    assert "ospfMaxMetricStartupWait" not in payload["management"]
    assert "ntpAuthEnable" not in payload["management"]
    assert "hypershieldHASourceSubnet" not in payload["management"]


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
    writable state. Public BGP secrets are explicitly retained in the proposal.

    ## Classes and Methods

    - NDStateMachine._manage_create_update_state()
    - NDBaseModel.prepare_for_replacement()
    """
    del case_name
    response = _existing_response(fabric_type, opaque_key, opaque_value)
    spy = _replacement_spy(orchestrator_class, response)(rest_send=_rest_send())
    module = _module(state)
    if fabric_type.endswith(("Ibgp", "Ebgp")):
        module.params["config"][0]["management"]["ntp_auth_key"] = "encrypted-controller-secret"
    instance = NDStateMachine(module=module, model_orchestrator=spy)

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

    Verify updates retain opaque fields and apply public-secret omission
    semantics: merged updates preserve and mask existing secrets, while exact
    replacement resets omitted public secrets.

    ## Classes and Methods

    - NDStateMachine._manage_create_update_state()
    - NDBaseModel.prepare_for_replacement()
    - NDBaseModel.to_payload()
    - NDBaseModel.to_config()
    """
    del case_name
    response = _existing_response(fabric_type, opaque_key, opaque_value)
    spy = _replacement_spy(orchestrator_class, response)(rest_send=_rest_send())
    instance = NDStateMachine(module=_module(state, license_tier="premier"), model_orchestrator=spy)

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
        if state == "merged":
            assert management_payload["ntpAuthKey"] == "encrypted-controller-secret"
            assert management_config["ntp_auth_key"] == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
        else:
            assert "ntpAuthKey" not in management_payload
            assert "ntp_auth_key" not in management_config
        assert "encrypted-controller-secret" in instance.module.no_log_values
    assert instance.output.format()["changed"] is True


@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_external_public_sampler_omission_preserves_merge_and_resets_exact_states(version, state):
    """Public sampler omission follows normal state semantics on both API releases."""
    response = FabricExternalConnectivityModel.from_config(_module(state).params["config"][0]).to_payload()
    response["management"]["netflowSettings"]["netflowSamplerCollection"] = [
        {"samplerName": "sampler-1", "numSamples": 10, "samplingRate": 1000}
    ]
    rest = _rest_send()
    rest.controller_product_version = version
    spy = _replacement_spy(ManageExternalFabricOrchestrator, response)(rest_send=rest)
    instance = NDStateMachine(module=_module(state), model_orchestrator=spy)

    instance.manage_state()

    assert len(spy._updated) == (0 if state == "merged" else 1)
    if spy._updated:
        assert "netflowSamplerCollection" not in spy._updated[0].to_payload()["management"]["netflowSettings"]


@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_external_public_ai_monitoring_omission_preserves_merge_and_resets_exact_states(state):
    """AI monitoring uses ordinary public management semantics on ND 4.3.1."""
    response = FabricExternalConnectivityModel.from_config(_module(state).params["config"][0]).to_payload()
    response["management"]["aiMonitoring"] = True
    spy = _replacement_spy(ManageExternalFabricOrchestrator, response)(rest_send=_rest_send())
    instance = NDStateMachine(module=_module(state), model_orchestrator=spy)

    instance.manage_state()

    assert len(spy._updated) == (0 if state == "merged" else 1)
    if spy._updated:
        expected = type(spy._updated[0].management).model_fields["ai_monitoring"].default
        assert spy._updated[0].to_payload()["management"].get("aiMonitoring") is expected


@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
@pytest.mark.parametrize("state", ("merged", "replaced", "overridden"))
def test_external_unreported_newer_defaults_do_not_create_a_replacement_diff(version, state):
    """Missing newer API fields cannot manufacture writes in either supported release."""
    response = {
        "name": "fabric1",
        "category": "fabric",
        "licenseTier": "essentials",
        "management": {"type": "externalConnectivity", "bgpAsn": "65001"},
    }
    rest = _rest_send()
    rest.controller_product_version = version
    spy = _replacement_spy(ManageExternalFabricOrchestrator, response)(rest_send=rest)
    instance = NDStateMachine(module=_module(state), model_orchestrator=spy)

    instance.manage_state()

    assert spy._updated == []
    assert instance.output.format()["changed"] is False


@pytest.mark.parametrize("version", ("4.2.1", "4.3.1"))
def test_external_real_merge_does_not_replay_unreported_newer_defaults(version):
    """An unrelated update preserves omission for every newer default, including on ND 4.3."""
    response = {
        "name": "fabric1",
        "category": "fabric",
        "licenseTier": "essentials",
        "management": {"type": "externalConnectivity", "bgpAsn": "65001"},
    }
    rest = _rest_send()
    rest.controller_product_version = version
    spy = _replacement_spy(ManageExternalFabricOrchestrator, response)(rest_send=rest)
    instance = NDStateMachine(module=_module("merged", license_tier="premier"), model_orchestrator=spy)

    instance.manage_state()

    assert len(spy._updated) == 1
    payload = spy._updated[0].to_payload()
    assert payload["licenseTier"] == "premier"
    for alias in (
        "aiMonitoring", "allowSmartSwitchHA", "autoSmartSwitchVpcPairHA", "enableRemoteSwitchBackup",
        "hypershieldHAPeerLinkSubnet", "hypershieldHAPeerLinkSubnetGranularity", "hypershieldHASourceIntf",
        "hypershieldHASourceSubnet", "hypershieldHAVlan", "iosXeTorBootstrapVlan",
        "softwareUpdateInMonitoredMode", "strictConfigComplianceMode", "useHypershieldSourceLoopbackForHA",
    ):
        assert alias not in payload["management"]


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
    spy = _replacement_spy(ManageEbgpFabricOrchestrator, response)(rest_send=_rest_send())
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


def test_nd_state_machine_fabric_group_overridden_00040() -> None:
    """
    # Summary

    Verify Fabric Group overridden semantics in a unit test without invoking
    cluster-wide deletion against a live controller.

    ## Test

    - The controller inventory contains a keep group and an unlisted group.
    - The overridden proposal contains only the keep group.
    - The state machine leaves the keep group unchanged and deletes only the
      unlisted group through the in-memory spy.

    ## Classes and Methods

    - NDStateMachine.manage_state()
    - NDStateMachine._manage_override_deletions()
    - ManageFabricGroupVxlanOrchestrator.delete()
    """

    keep = FabricGroupVxlanModel.from_config({"fabric_name": "group_keep"})
    prune = FabricGroupVxlanModel.from_config({"fabric_name": "group_prune"})

    class FabricGroupOverrideSpy(ManageFabricGroupVxlanOrchestrator):
        def model_post_init(self, __context) -> None:
            super().model_post_init(__context)
            self._updated: list = []
            self._deleted: list = []

        def query_all(self, model_instance=None, **kwargs) -> ResponseType:
            del model_instance, kwargs
            return [deepcopy(keep.to_payload()), deepcopy(prune.to_payload())]

        def update(self, model_instance, **kwargs) -> ResponseType:
            del kwargs
            self._updated.append(model_instance)
            return {}

        def delete(self, model_instance, **kwargs) -> ResponseType:
            del kwargs
            self._deleted.append(model_instance)
            return {}

    module = MockAnsibleModule()
    module.check_mode = False
    module.no_log_values = set()
    module.params = {
        "state": "overridden",
        "config": [{"fabric_name": "group_keep"}],
        "output_level": "normal",
        "ignore_errors": False,
    }
    spy = FabricGroupOverrideSpy(rest_send=_rest_send())
    instance = NDStateMachine(module=module, model_orchestrator=spy)

    instance.manage_state()

    assert spy._updated == []
    assert [item.fabric_name for item in spy._deleted] == ["group_prune"]
    assert [item.fabric_name for item in instance.existing] == ["group_keep"]
    assert instance.output.format()["changed"] is True
