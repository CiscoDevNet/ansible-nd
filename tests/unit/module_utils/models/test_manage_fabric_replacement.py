# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Replacement-default and opaque-field tests for fabric models."""

from __future__ import annotations

import re

import pytest
from pydantic import ValidationError

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import (
    FabricAiEbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    FabricAiIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import (
    FabricCampusIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import (
    FabricExternalConnectivityModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import (
    FabricIbgpModel,
)

FABRIC_CASES = (
    (FabricExternalConnectivityModel, "externalConnectivity", "aiMonitoring", True),
    (FabricIbgpModel, "vxlanIbgp", "borderCount", 0),
    (FabricEbgpModel, "vxlanEbgp", "borderCount", 0),
    (FabricAiIbgpVxlanModel, "aimlVxlanIbgp", "borderCount", 0),
    (FabricAiEbgpVxlanModel, "aimlVxlanEbgp", "borderCount", 0),
)

EBGP_CASES = (
    (FabricEbgpModel, "vxlanEbgp"),
    (FabricAiEbgpVxlanModel, "aimlVxlanEbgp"),
)

IBGP_CASES = (
    (FabricIbgpModel, "vxlanIbgp"),
    (FabricAiIbgpVxlanModel, "aimlVxlanIbgp"),
)

TELEMETRY_CASES = (
    (FabricExternalConnectivityModel, "externalConnectivity"),
    (FabricIbgpModel, "vxlanIbgp"),
    (FabricEbgpModel, "vxlanEbgp"),
    (FabricAiIbgpVxlanModel, "aimlVxlanIbgp"),
    (FabricAiEbgpVxlanModel, "aimlVxlanEbgp"),
    (FabricCampusIbgpVxlanModel, "vxlanCampus"),
)


def _fabric_config(fabric_name: str = "fabric1", **management) -> dict:
    return {
        "fabric_name": fabric_name,
        "management": {"bgp_asn": "65001", **management},
    }


def _fabric_response(fabric_type: str, fabric_name: str = "fabric1", **management) -> dict:
    return {
        "name": fabric_name,
        "category": "fabric",
        "location": {"latitude": 37.33939, "longitude": -121.89496},
        "management": {"type": fabric_type, "bgpAsn": "65001", **management},
    }


@pytest.mark.parametrize("model_class,fabric_type,opaque_key,opaque_value", FABRIC_CASES)
def test_manage_fabric_replacement_00010(model_class, fabric_type, opaque_key, opaque_value) -> None:
    """
    # Summary

    Verify every fabric family normalizes the deterministic location echo and
    preserves allowlisted opaque management state during exact replacement.

    ## Test

    - Existing state contains ND's default location and one unsupported writable field.
    - eBGP state additionally contains a controller-allocated ASN range.
    - The prepared replacement is exact-diff idempotent.
    - Opaque values remain in the API payload but not in normalized Ansible output.

    ## Classes and Methods

    - NDBaseModel.prepare_for_replacement()
    - NDBaseModel.get_diff()
    - NDBaseModel.to_payload()
    - NDBaseModel.to_config()
    """
    management = {opaque_key: opaque_value}
    if "Ebgp" in model_class.__name__:
        management["bgpAsnRange"] = "3001-4000"
    if "Ibgp" in model_class.__name__:
        management.update(
            {
                "vrfLiteIpv6SubnetRange": "fd00::a33:0/112",
                "vrfLiteIpv6SubnetTargetMask": 126,
            }
        )

    existing = model_class.from_response(_fabric_response(fabric_type, **management))
    proposed = model_class.from_config(_fabric_config())
    candidate = proposed.prepare_for_replacement(existing)
    management_spec = model_class.get_argument_spec()["config"]["options"]["management"]["options"]

    assert existing.get_diff(candidate, exclude_unset=False) is True
    assert candidate.to_payload()["management"][opaque_key] == opaque_value
    assert opaque_key not in candidate.to_config()["management"]
    assert opaque_key not in existing.to_config()["management"]
    assert re.sub(r"(?<!^)(?=[A-Z])", "_", opaque_key).lower() not in management_spec


def test_manage_fabric_replacement_00020() -> None:
    """
    # Summary

    Verify only the observed default location is normalized; omitting a custom
    location remains a real replacement change that resets the controller value.

    ## Classes and Methods

    - FabricBaseModel.reverse_diff_defaults
    - NDBaseModel.get_diff()
    """
    response = _fabric_response("externalConnectivity")
    response["location"] = {"latitude": 40.7128, "longitude": -74.006}
    existing = FabricExternalConnectivityModel.from_response(response)
    proposed = FabricExternalConnectivityModel.from_config(_fabric_config())

    assert existing.get_diff(proposed.prepare_for_replacement(existing), exclude_unset=False) is False


def test_manage_fabric_replacement_00025() -> None:
    """
    # Summary

    Verify hidden authentication fields are preserved without entering normal
    output, their nested string values are available to Ansible's no-log
    scrubber, and arbitrary response metadata is not replayed.

    ## Classes and Methods

    - NDBaseModel.prepare_for_replacement()
    - NDBaseModel.collect_replacement_secret_values()
    """
    response = _fabric_response(
        "vxlanIbgp",
        ntpAuthKey="encrypted-ntp-secret",
        ospfKeys=[{"id": 1, "key": "encrypted-ospf-secret"}],
        responseStatus="READY",
    )
    existing = FabricIbgpModel.from_response(response)
    candidate = FabricIbgpModel.from_config(_fabric_config()).prepare_for_replacement(existing)

    management_payload = candidate.to_payload()["management"]
    assert management_payload["ntpAuthKey"] == "encrypted-ntp-secret"
    assert management_payload["ospfKeys"] == [{"id": 1, "key": "encrypted-ospf-secret"}]
    assert "responseStatus" not in management_payload
    assert "ntpAuthKey" not in candidate.to_config()["management"]
    assert candidate.collect_replacement_secret_values() == {
        "encrypted-ntp-secret",
        "encrypted-ospf-secret",
    }


@pytest.mark.parametrize("model_class,fabric_type", EBGP_CASES)
def test_manage_fabric_replacement_00030(model_class, fabric_type) -> None:
    """
    # Summary

    Verify a controller-allocated eBGP ASN range is dynamically preserved when
    omitted, while an explicitly configured range remains authoritative.

    ## Classes and Methods

    - NDBaseModel.prepare_for_replacement()
    - VxlanEbgpManagementModel.replacement_preserve_fields
    """
    existing = model_class.from_response(_fabric_response(fabric_type, bgpAsnRange="3001-4000"))

    omitted = model_class.from_config(_fabric_config())
    assert "bgpAsnRange" not in omitted.to_payload()["management"]
    omitted_candidate = omitted.prepare_for_replacement(existing)
    assert omitted_candidate.management.bgp_asn_range == "3001-4000"
    assert omitted_candidate.to_payload()["management"]["bgpAsnRange"] == "3001-4000"
    assert existing.get_diff(omitted_candidate, exclude_unset=False) is True

    explicit = model_class.from_config(_fabric_config(bgp_asn_range="65000-65100"))
    explicit_candidate = explicit.prepare_for_replacement(existing)
    assert explicit_candidate.management.bgp_asn_range == "65000-65100"
    assert existing.get_diff(explicit_candidate, exclude_unset=False) is False


@pytest.mark.parametrize("model_class,fabric_type", IBGP_CASES)
def test_manage_fabric_replacement_00040(model_class, fabric_type) -> None:
    """
    # Summary

    Verify the iBGP VRF Lite IPv6 fields are optional public parameters with
    live-default reverse normalization and bounded validation.

    ## Classes and Methods

    - VxlanIbgpManagementModel
    - FabricBaseModel.get_argument_spec()
    - NDBaseModel.get_diff()
    """
    management_spec = model_class.get_argument_spec()["config"]["options"]["management"]["options"]
    assert management_spec["vrf_lite_ipv6_subnet_range"] == {"type": "str"}
    assert management_spec["vrf_lite_ipv6_subnet_target_mask"] == {"type": "int"}

    proposed = model_class.from_config(_fabric_config())
    payload = proposed.to_payload()["management"]
    assert "vrfLiteIpv6SubnetRange" not in payload
    assert "vrfLiteIpv6SubnetTargetMask" not in payload

    existing_default = model_class.from_response(
        _fabric_response(
            fabric_type,
            vrfLiteIpv6SubnetRange="fd00::a33:0/112",
            vrfLiteIpv6SubnetTargetMask=126,
        )
    )
    assert existing_default.get_diff(proposed.prepare_for_replacement(existing_default), exclude_unset=False) is True

    existing_custom = model_class.from_response(
        _fabric_response(
            fabric_type,
            vrfLiteIpv6SubnetRange="fd00::beef:0/112",
            vrfLiteIpv6SubnetTargetMask=124,
        )
    )
    assert existing_custom.get_diff(proposed.prepare_for_replacement(existing_custom), exclude_unset=False) is False

    explicit = model_class.from_config(
        _fabric_config(
            vrf_lite_ipv6_subnet_range="fd00::beef:0/112",
            vrf_lite_ipv6_subnet_target_mask=124,
        )
    )
    explicit_payload = explicit.to_payload()["management"]
    assert explicit_payload["vrfLiteIpv6SubnetRange"] == "fd00::beef:0/112"
    assert explicit_payload["vrfLiteIpv6SubnetTargetMask"] == 124

    with pytest.raises(ValidationError):
        model_class.from_config(_fabric_config(vrf_lite_ipv6_subnet_range="10.0.0.0/24"))
    with pytest.raises(ValidationError):
        model_class.from_config(_fabric_config(vrf_lite_ipv6_subnet_target_mask=128))


@pytest.mark.parametrize("model_class,fabric_type", TELEMETRY_CASES)
def test_manage_fabric_replacement_00050(model_class, fabric_type) -> None:
    """
    # Summary

    Verify every fabric family preserves hidden writable telemetry roots while
    stripping top-level and nested read-only response data.

    ## Test

    - Omitted telemetry is materialized only so opaque writable roots survive.
    - Read-only capabilities, operating mode, compatibility protocol, UUIDs,
      attribute IDs, and switch IDs never enter the replacement payload.
    - Opaque roots stay out of config, gathered output, and argument specs.
    """
    response = _fabric_response(fabric_type)
    response["telemetrySettings"] = {
        "flowCollection": {
            "trafficAnalytics": "enabled",
            "trafficAnalyticsScope": "intraFabric",
            "udpCategorization": "enabled",
            "operatingMode": "flowTelemetry",
            "trafficAnalyticsCompatibilityProtocol": "netflow",
            "flowCollectionCapabilities": {"trafficAnalyticsMode": "full"},
            "flowCollectionModes": {"netFlow": True, "sFlow": False, "flowTelemetry": False},
            "flowRules": {
                "vrfFlowRules": [
                    {
                        "name": "vrf-rule",
                        "uuid": "controller-vrf-uuid",
                        "attributes": [{"srcIp": "", "attributeId": "controller-attribute-id"}],
                    }
                ],
                "interfaceFlowRules": [
                    {
                        "name": "interface-rule",
                        "uuid": "controller-interface-uuid",
                        "interfaceCollection": [
                            {
                                "switchId": "controller-switch-id",
                                "switchName": "leaf-1",
                                "interfaces": ["eth1/1"],
                            }
                        ],
                    }
                ],
            },
            "trafficAnalyticsRules": {
                "enabled": True,
                "interfaceRules": [
                    {
                        "name": "ta-rule",
                        "uuid": "controller-ta-uuid",
                        "interfaceCollection": [
                            {
                                "switchId": "controller-ta-switch-id",
                                "switchName": "leaf-2",
                                "interfaces": [{"name": "eth1/2", "type": "physical"}],
                            }
                        ],
                    }
                ],
            },
        }
    }

    existing = model_class.from_response(response)
    proposed = model_class.from_config(_fabric_config())
    candidate = proposed.prepare_for_replacement(existing)

    # Response normalization must not mutate the endpoint result retained by callers.
    assert response["telemetrySettings"]["flowCollection"]["flowRules"]["vrfFlowRules"][0]["uuid"] == "controller-vrf-uuid"
    flow_payload = candidate.to_payload()["telemetrySettings"]["flowCollection"]
    assert flow_payload["flowCollectionModes"] == {"netFlow": True, "sFlow": False, "flowTelemetry": False}
    assert flow_payload["flowRules"]["vrfFlowRules"][0] == {
        "name": "vrf-rule",
        "attributes": [{"srcIp": ""}],
    }
    assert flow_payload["flowRules"]["interfaceFlowRules"][0] == {
        "name": "interface-rule",
        "interfaceCollection": [{"switchName": "leaf-1", "interfaces": ["eth1/1"]}],
    }
    assert flow_payload["trafficAnalyticsRules"]["interfaceRules"][0] == {
        "name": "ta-rule",
        "interfaceCollection": [
            {
                "switchName": "leaf-2",
                "interfaces": [{"name": "eth1/2", "type": "physical"}],
            }
        ],
    }
    assert "operatingMode" not in flow_payload
    assert "trafficAnalyticsCompatibilityProtocol" not in flow_payload
    assert "flowCollectionCapabilities" not in flow_payload

    flow_config = candidate.to_config()["telemetry_settings"]["flow_collection"]
    flow_gathered = candidate.to_gathered_config()["telemetry_settings"]["flow_collection"]
    for hidden_key in ("flowCollectionModes", "flowRules", "trafficAnalyticsRules"):
        assert hidden_key not in flow_config
        assert hidden_key not in flow_gathered

    flow_spec = model_class.get_argument_spec()["config"]["options"]["telemetry_settings"]["options"]["flow_collection"]["options"]
    assert "operating_mode" not in flow_spec
    assert existing.get_diff(candidate, exclude_unset=False) is True


def test_manage_fabric_replacement_00060() -> None:
    """Verify telemetry materialization does not preserve public exact-state values."""
    response = _fabric_response("vxlanIbgp")
    response["telemetrySettings"] = {
        "flowCollection": {
            "trafficAnalytics": "disabled",
            "flowCollectionModes": {"netFlow": True},
        }
    }
    existing = FabricIbgpModel.from_response(response)
    candidate = FabricIbgpModel.from_config(_fabric_config()).prepare_for_replacement(existing)
    flow_payload = candidate.to_payload()["telemetrySettings"]["flowCollection"]

    assert flow_payload["trafficAnalytics"] == "enabled"
    assert flow_payload["flowCollectionModes"] == {"netFlow": True}
    assert existing.get_diff(candidate, exclude_unset=False) is False


def test_manage_fabric_replacement_00070() -> None:
    """Verify External-only netflow sampler state is preserved but remains private."""
    existing = FabricExternalConnectivityModel.from_response(
        _fabric_response(
            "externalConnectivity",
            netflowSettings={
                "netflow": False,
                "netflowSamplerCollection": [{"samplerName": "sampler-1", "numSamples": 10, "samplingRate": 1000}],
            },
        )
    )
    candidate = FabricExternalConnectivityModel.from_config(_fabric_config()).prepare_for_replacement(existing)

    sampler = [{"samplerName": "sampler-1", "numSamples": 10, "samplingRate": 1000}]
    assert candidate.to_payload()["management"]["netflowSettings"]["netflowSamplerCollection"] == sampler
    assert "netflowSamplerCollection" not in candidate.to_config()["management"]["netflow_settings"]
    assert "netflowSamplerCollection" not in candidate.to_gathered_config()["management"]["netflow_settings"]
    netflow_spec = FabricExternalConnectivityModel.get_argument_spec()["config"]["options"]["management"]["options"]["netflow_settings"]["options"]
    assert "netflow_sampler_collection" not in netflow_spec
    assert existing.get_diff(candidate, exclude_unset=False) is True


@pytest.mark.parametrize("model_class,fabric_type", IBGP_CASES)
def test_manage_fabric_replacement_00080(model_class, fabric_type) -> None:
    """Verify read-only securityGroupStatus is removed for both iBGP families."""
    existing = model_class.from_response(_fabric_response(fabric_type, securityGroupStatus="enabled"))
    management_spec = model_class.get_argument_spec()["config"]["options"]["management"]["options"]

    assert "securityGroupStatus" not in existing.to_payload()["management"]
    assert "security_group_status" not in existing.to_config()["management"]
    assert "security_group_status" not in existing.to_gathered_config()["management"]
    assert "security_group_status" not in management_spec


@pytest.mark.parametrize("model_class,fabric_type", EBGP_CASES)
def test_manage_fabric_replacement_00090(model_class, fabric_type) -> None:
    """Verify the controller-forced nxapiHttp value is normalized for both eBGP families."""
    existing = model_class.from_response(_fabric_response(fabric_type, nxapiHttp=True))
    proposed = model_class.from_config(_fabric_config())
    candidate = proposed.prepare_for_replacement(existing)

    assert "nxapiHttp" not in existing.to_diff_dict()["management"]
    assert "nxapiHttp" not in candidate.to_diff_dict()["management"]
    assert candidate.to_payload()["management"]["nxapiHttp"] is False
    assert existing.get_diff(candidate, exclude_unset=False) is True
