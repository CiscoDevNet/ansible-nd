# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for VRF orchestrator payload transformation.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import (
    VrfConfigModel,
    VrfParentConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_data_models import (
    VrfDataModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrfs import (
    NDVrfOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_argument_specs import (
    _child_fabric_config_element_spec,
    vrf_base_argument_spec,
    vrf_parent_argument_spec,
)


class _Strategy:
    def __init__(self, fabric_data=None, is_child=False, is_parent=False):
        self.fabric_data = fabric_data or {}
        self.is_child = is_child
        self.is_parent = is_parent


def _transform(
    config,
    fabric_name="AK-VXLAN",
    fabric_data=None,
    is_child=False,
    is_parent=False,
):
    """Call the payload transformer without constructing the full orchestrator."""
    instance = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(
        instance,
        "strategy",
        _Strategy(fabric_data, is_child, is_parent),
    )
    if is_child:
        return instance._transform_child_config_to_payload_model_data(config, fabric_name)
    return instance._transform_config_to_payload_model_data(config, fabric_name)


class _EndpointStrategy:
    fabric_name = "AK-VXLAN"
    fabric_data = {}
    is_parent = False

    def __init__(self, is_child=False):
        self.is_child = is_child

    @staticmethod
    def configure_endpoint(_endpoint):
        return None

    @staticmethod
    def vrfs_get_cls():
        from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
            EpManageFabricsVrfsGet,
        )

        return EpManageFabricsVrfsGet

    @staticmethod
    def vrf_actions_remove_post_cls():
        from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrf_actions import (
            EpManageFabricsVrfActionsRemovePost,
        )

        return EpManageFabricsVrfActionsRemovePost

    @staticmethod
    def vrf_put_cls():
        from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
            EpManageFabricsVrfsVrfNamePut,
        )

        return EpManageFabricsVrfsVrfNamePut


class _RestSend:
    def __init__(self, params):
        self.params = params
        self.response_current = {}


def _orchestrator_for_request_tests(params, is_child=False):
    instance = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(instance, "strategy", _EndpointStrategy(is_child=is_child))
    object.__setattr__(instance, "rest_send", _RestSend(params))
    return instance


def test_vrfs_00010_transform_standalone_config_to_schema_payload():
    """
    # Summary

    Verify playbook-facing VRF config is transformed to the schema-shaped
    payload before VrfDataModel drops unknown config fields.

    ## Test

    - Python config fields are mapped into coreData and fabricData
    - vrfType defaults from resolved fabric details
    - The final VrfDataModel payload contains nested ND API keys

    ## Classes and Methods

    - NDVrfOrchestrator._transform_config_to_payload_model_data()
    - VrfDataModel.to_payload()
    """
    transformed = _transform(
        {
            "vrf_name": "ansible-vrf-int1",
            "vrf_id": 9008011,
            "vlan_id": 600,
            "vrf_int_mtu": 9216,
            "loopback_route_tag": 12345,
            "redist_direct_rmap": "FABRIC-RMAP-REDIST-SUBNET",
            "v6_redist_direct_rmap": "FABRIC-RMAP-REDIST-SUBNET",
            "max_bgp_paths": 1,
            "max_ibgp_paths": 2,
            "ipv6_linklocal_enable": True,
            "disable_rt_auto": False,
            "adv_host_routes": False,
            "adv_default_routes": True,
            "static_default_route": True,
            "netflow_enable": False,
        },
        fabric_data={"vrfType": "vxlanEbgp"},
    )

    payload = VrfDataModel.from_config(transformed).to_payload()

    assert payload["fabricName"] == "AK-VXLAN"
    assert payload["vrfName"] == "ansible-vrf-int1"
    assert payload["vrfId"] == 9008011
    assert payload["vlanId"] == 600
    assert payload["vrfType"] == "vxlanEbgp"

    assert payload["coreData"]["mtu"] == 9216
    assert payload["coreData"]["routingTag"] == 12345
    assert payload["coreData"]["vrfRouteMap"] == "FABRIC-RMAP-REDIST-SUBNET"
    assert payload["coreData"]["v6VrfRouteMap"] == "FABRIC-RMAP-REDIST-SUBNET"
    assert "routeTargetImport" not in payload["coreData"]
    assert "evpnRouteTargetExport" not in payload["coreData"]

    assert payload["fabricData"]["advertiseHostRoute"] is False
    assert payload["fabricData"]["advertiseDefaultRoute"] is True
    assert payload["fabricData"]["configureStaticDefaultRoute"] is True
    assert payload["fabricData"]["netflow"] is False
    assert payload["fabricData"]["trmData"]["ipv4Trm"] is False
    assert "mvpnRouteTargetImport" not in payload["fabricData"]["trmData"]


def test_vrfs_00020_transform_applies_schema_defaults_for_minimal_config():
    """
    # Summary

    Verify a minimal VRF config still receives the defaults expected by the
    ND VRF schema and UI-generated payloads.

    ## Classes and Methods

    - NDVrfOrchestrator._transform_config_to_payload_model_data()
    """
    transformed = _transform({"vrf_name": "ansible-vrf-int1"})
    payload = VrfDataModel.from_config(transformed).to_payload()

    assert payload["vrfType"] == "vxlanIbgp"
    assert payload["coreData"]["mtu"] == 9216
    assert payload["coreData"]["routingTag"] == 12345
    assert payload["coreData"]["maxBgpPaths"] == 1
    assert payload["coreData"]["maxIbgpPaths"] == 2
    assert payload["coreData"]["ipv6LinkLocal"] is True
    assert payload["coreData"]["disableRtAuto"] is False
    assert payload["fabricData"]["l3VniWithoutVlan"] is False
    assert payload["fabricData"]["advertiseDefaultRoute"] is True
    assert payload["fabricData"]["configureStaticDefaultRoute"] is True
    assert payload["fabricData"]["bgpPasswordKeyType"] == 3
    assert payload["fabricData"]["trmData"]["v4RpAbsent"] is False


def test_vrfs_00025_config_model_accepts_supported_attachment_fields():
    """
    # Summary

    Verify attach/deploy are accepted by standalone and parent config models
    with only the supported attachment-level fields.
    """
    config = {
        "vrf_name": "ansible-vrf-attach",
        "deploy": False,
        "deploy_type": "vrf",
        "attach": [
            {
                "ip_address": "192.168.1.224",
                "loopback_id": 10,
                "loopback_ipv4_address": "10.10.10.10",
                "loopback_ipv6_address": "2001:db8::10",
                "import_vpn_rt": ["65000:10"],
                "export_vpn_rt": ["65000:11"],
                "import_evpn_rt": ["65000:12"],
                "export_evpn_rt": ["65000:13"],
            }
        ],
    }

    standalone = VrfConfigModel.from_config(config).to_config()
    parent = VrfParentConfigModel.from_config(dict(config, child_fabric_config=[{"fabric": "AK-VXLAN"}])).to_config()

    for parsed in (standalone, parent):
        assert parsed["deploy"] is False
        assert parsed["deploy_type"] == "vrf"
        attachment = parsed["attach"][0]
        assert attachment["ip_address"] == "192.168.1.224"
        assert attachment["loopback_id"] == 10
        assert attachment["loopback_ipv4_address"] == "10.10.10.10"
        assert attachment["loopback_ipv6_address"] == "2001:db8::10"
        assert attachment["import_vpn_rt"] == ["65000:10"]
        assert attachment["export_vpn_rt"] == ["65000:11"]
        assert attachment["import_evpn_rt"] == ["65000:12"]
        assert attachment["export_evpn_rt"] == ["65000:13"]


def test_vrfs_00026_config_models_match_argument_specs():
    """
    # Summary

    Verify playbook-facing config models accept the same field names exposed
    by their corresponding argument specs.
    """
    assert set(VrfConfigModel.model_fields) == set(vrf_base_argument_spec())
    assert set(VrfParentConfigModel.model_fields) == set(vrf_parent_argument_spec())

    from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import (
        VrfChildConfigModel,
    )

    assert set(VrfChildConfigModel.model_fields) == set(_child_fabric_config_element_spec())


def test_vrfs_00027_config_model_accepts_schema_security_fields():
    """
    # Summary

    Verify schema-supported security group fields are accepted and preserved
    by standalone and parent config models.
    """
    config = {
        "vrf_name": "ansible-vrf-security",
        "default_security_action": "enforcedPermit",
        "default_security_group_tag": 101,
    }

    standalone = VrfConfigModel.from_config(config).to_config()
    parent = VrfParentConfigModel.from_config(config).to_config()

    for parsed in (standalone, parent):
        assert parsed["default_security_action"] == "enforcedPermit"
        assert parsed["default_security_group_tag"] == 101


def test_vrfs_00030_transform_all_standalone_manageable_fields():
    """
    # Summary

    Verify every standalone module config field that can legally coexist is
    either mapped into the VXLAN VRF payload or intentionally excluded because
    the POST schema does not expose it for vxlanIbgp.

    ## Classes and Methods

    - NDVrfOrchestrator._transform_config_to_payload_model_data()
    - VrfDataModel.to_payload()
    """
    transformed = _transform(
        {
            "vrf_name": "ansible-vrf-allprops",
            "vrf_id": 9008012,
            "vlan_id": 651,
            "vrf_vlan_name": "ansible_vrf_allprops_vlan",
            "vrf_intf_desc": "Ansible all properties VRF SVI",
            "vrf_int_mtu": 9216,
            "l3vni_wo_vlan": False,
            "vrf_description": "Ansible all manageable properties test",
            "loopback_route_tag": 12345,
            "redist_direct_rmap": "FABRIC-RMAP-REDIST-SUBNET",
            "v6_redist_direct_rmap": "FABRIC-RMAP-REDIST-SUBNET",
            "max_bgp_paths": 4,
            "max_ibgp_paths": 4,
            "ipv6_linklocal_enable": True,
            "disable_rt_auto": True,
            "import_vpn_rt": ["65000:9008012"],
            "export_vpn_rt": ["65000:9008013"],
            "import_evpn_rt": ["65000:9008014"],
            "export_evpn_rt": ["65000:9008015"],
            "trm_enable": True,
            "no_rp": False,
            "rp_external": False,
            "rp_address": "10.254.254.1",
            "rp_loopback_id": 101,
            "underlay_mcast_ip": "239.1.1.1",
            "overlay_mcast_group": "239.2.2.2",
            "trm_bgw_msite": False,
            "import_mvpn_rt": ["65000:9008016"],
            "export_mvpn_rt": ["65000:9008017"],
            "adv_host_routes": True,
            "adv_default_routes": False,
            "static_default_route": False,
            "bgp_password": "abcdef12",
            "bgp_passwd_encrypt": 3,
            "netflow_enable": True,
            "nf_monitor": "MON1",
        }
    )

    payload = VrfDataModel.from_config(transformed).to_payload()
    core = payload["coreData"]
    fabric = payload["fabricData"]
    trm = fabric["trmData"]

    assert payload["fabricName"] == "AK-VXLAN"
    assert payload["vrfName"] == "ansible-vrf-allprops"
    assert payload["vrfId"] == 9008012
    assert payload["vlanId"] == 651
    assert payload["vrfType"] == "vxlanIbgp"
    assert "vrfTemplateName" not in payload
    assert "vrfExtensionTemplateName" not in payload
    assert "serviceVrfTemplateName" not in payload

    assert core["vrfVlanName"] == "ansible_vrf_allprops_vlan"
    assert core["vrfInterfaceDescription"] == "Ansible all properties VRF SVI"
    assert core["vrfDescription"] == "Ansible all manageable properties test"
    assert core["mtu"] == 9216
    assert core["routingTag"] == 12345
    assert core["vrfRouteMap"] == "FABRIC-RMAP-REDIST-SUBNET"
    assert core["v6VrfRouteMap"] == "FABRIC-RMAP-REDIST-SUBNET"
    assert core["maxBgpPaths"] == 4
    assert core["maxIbgpPaths"] == 4
    assert core["ipv6LinkLocal"] is True
    assert core["disableRtAuto"] is True
    assert core["routeTargetImport"] == ["65000:9008012"]
    assert core["routeTargetExport"] == ["65000:9008013"]
    assert core["evpnRouteTargetImport"] == ["65000:9008014"]
    assert core["evpnRouteTargetExport"] == ["65000:9008015"]

    assert fabric["l3VniWithoutVlan"] is False
    assert fabric["advertiseHostRoute"] is True
    assert fabric["advertiseDefaultRoute"] is False
    assert fabric["configureStaticDefaultRoute"] is False
    assert fabric["bgpPassword"] == "abcdef12"
    assert fabric["bgpPasswordKeyType"] == 3
    assert fabric["netflow"] is True
    assert fabric["netflowMonitor"] == "MON1"

    assert trm["ipv4Trm"] is True
    assert trm["v4RpAbsent"] is False
    assert trm["v4RpExternal"] is False
    assert trm["v4RpAddress"] == "10.254.254.1"
    assert trm["loopbackNumber"] == 101
    assert trm["l3VniMulticastGroup"] == "239.1.1.1"
    assert trm["v4MulticastGroup"] == "239.2.2.2"
    assert trm["trmOnBgw"] is False
    assert trm["mvpnRouteTargetImport"] == ["65000:9008016"]
    assert trm["mvpnRouteTargetExport"] == ["65000:9008017"]


def test_vrfs_00040_transform_user_defined_custom_template_payload():
    """
    Verify custom template fields are emitted only for userDefined VRFs and
    use the schema-supported field names.
    """
    transformed = _transform(
        {
            "vrf_name": "ansible-vrf-custom",
            "vrf_type": "userDefined",
            "vrf_id": 9008020,
            "vlan_id": 652,
            "service_vrf_template_name": "CustomServiceTemplate1",
            "vrf_template_name": "CustomTemplate1",
            "vrf_extension_template_name": "CustomExtTemplate1",
            "vrf_template_config": {
                "param1": "value1",
                "mtu": "9216",
            },
        },
        fabric_data={"vrfType": "vxlanIbgp"},
    )

    payload = VrfDataModel.from_config(transformed).to_payload()

    assert payload == {
        "fabricName": "AK-VXLAN",
        "vrfName": "ansible-vrf-custom",
        "vrfId": 9008020,
        "vlanId": 652,
        "vrfType": "userDefined",
        "serviceVrfTemplateName": "CustomServiceTemplate1",
        "vrfTemplateName": "CustomTemplate1",
        "vrfExtensionTemplateName": "CustomExtTemplate1",
        "vrfTemplateConfig": {
            "param1": "value1",
            "mtu": "9216",
        },
    }


def test_vrfs_00050_custom_template_fields_require_user_defined_type():
    """Custom template fields must not be silently dropped or sent on VXLAN."""
    with pytest.raises(ValidationError):
        VrfConfigModel.from_config(
            {
                "vrf_name": "ansible-vrf-invalid-custom",
                "vrf_template_name": "CustomTemplate1",
            }
        )


def test_vrfs_00060_vrf_template_config_values_must_be_strings():
    """Schema requires vrfTemplateConfig to be an object of string values."""
    with pytest.raises(ValidationError):
        VrfConfigModel.from_config(
            {
                "vrf_name": "ansible-vrf-invalid-template-config",
                "vrf_type": "userDefined",
                "vrf_template_name": "CustomTemplate1",
                "vrf_template_config": {"mtu": 9216},
            }
        )


def test_vrfs_00070_transform_child_config_to_fabric_data_only():
    """MSD child overrides must not emit parent-owned VLAN/SVI/core fields."""
    transformed = _transform(
        {
            "vrf_name": "ansible-msd-vrf",
            "l3vni_wo_vlan": False,
            "adv_host_routes": True,
            "adv_default_routes": False,
            "static_default_route": False,
            "netflow_enable": False,
            "trm_enable": False,
        },
        fabric_name="AK-VXLAN",
        is_child=True,
    )

    payload = VrfDataModel.from_config(transformed).to_payload()

    assert payload["fabricName"] == "AK-VXLAN"
    assert payload["vrfName"] == "ansible-msd-vrf"
    assert "vlanId" not in payload
    assert "vrfId" not in payload
    assert "coreData" not in payload
    fabric = payload["fabricData"]
    assert fabric["l3VniWithoutVlan"] is False
    assert fabric["advertiseHostRoute"] is True
    assert fabric["advertiseDefaultRoute"] is False
    assert fabric["configureStaticDefaultRoute"] is False
    assert fabric["bgpPasswordKeyType"] == 3
    assert fabric["netflow"] is False
    assert fabric["trmData"]["ipv4Trm"] is False
    assert fabric["trmData"]["trmOnBgw"] is False


def test_vrfs_00080_query_all_scopes_targeted_state_reads():
    """
    # Summary

    Verify targeted states only query current VRFs named in config instead of
    reading every VRF in the fabric.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "replaced",
            "config": [
                {"vrf_name": "ansible-vrf-b"},
                {"vrf_name": "ansible-vrf-a"},
                {"vrf_name": "ansible-vrf-a"},
            ],
        }
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {"vrfs": []}

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == []
    assert requested_paths == [
        "/api/v1/manage/fabrics/AK-VXLAN/vrfs?filter=vrfName%3Aansible-vrf-b",
        "/api/v1/manage/fabrics/AK-VXLAN/vrfs?filter=vrfName%3Aansible-vrf-a",
    ]


def test_vrfs_00085_query_all_does_not_scope_overridden_reads():
    """
    # Summary

    Verify overridden keeps a full current-state read because it must compare
    desired config against all existing VRFs.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "overridden",
            "config": [{"vrf_name": "ansible-vrf-a"}],
        }
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {"vrfs": []}

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == []
    assert len(requested_paths) == 1
    assert "filter=" not in requested_paths[0]


def test_vrfs_00090_bulk_delete_retries_only_sync_failed_vrfs():
    """
    # Summary

    Verify bulk delete retries fabric re-sync failures and only sends the VRFs
    that failed with retryable controller sync errors on the next attempt.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "deleted",
            "config": [
                {"vrf_name": "ansible-vrf-a"},
                {"vrf_name": "ansible-vrf-b"},
            ],
        }
    )
    requested_payloads = []

    def request(**kwargs):
        requested_payloads.append(list(kwargs["data"]["vrfNames"]))
        if len(requested_payloads) == 1:
            orchestrator.rest_send.response_current = {
                "DATA": {
                    "results": [
                        {"vrfName": "ansible-vrf-a", "status": "success"},
                        {
                            "vrfName": "ansible-vrf-b",
                            "status": "failed",
                            "message": "Fabric re-sync is in progress. Retry after sync completes.",
                        },
                    ]
                }
            }
            raise Exception("partial delete failure")
        return {"results": [{"vrfName": "ansible-vrf-b", "status": "success"}]}

    object.__setattr__(orchestrator, "delete_retry_delay", 0)
    object.__setattr__(orchestrator, "_request", request)

    result = orchestrator._delete_bulk_with_retry(["ansible-vrf-a", "ansible-vrf-b"])

    assert requested_payloads == [
        ["ansible-vrf-a", "ansible-vrf-b"],
        ["ansible-vrf-b"],
    ]
    assert result["results"] == [
        {"vrfName": "ansible-vrf-b", "status": "success"},
        {"vrfName": "ansible-vrf-a", "status": "success"},
    ]


def test_vrfs_00100_child_create_bulk_uses_update_endpoint():
    """
    # Summary

    Verify parent-driven child fabric work never POST-creates VRFs on member
    fabrics.  ND requires VRF creation at the parent/group level; child fabric
    overrides are applied with PUT.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "merged",
            "config": [{"vrf_name": "ansible-msd-vrf"}],
        },
        is_child=True,
    )
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {"status": "success"}

    object.__setattr__(orchestrator, "_request", request)
    model = VrfDataModel.from_config(
        {
            "fabric_name": "AK-VXLAN",
            "vrf_name": "ansible-msd-vrf",
            "fabric_data": {
                "advertiseDefaultRoute": False,
                "advertiseHostRoute": True,
            },
        }
    )

    result = orchestrator.create_bulk([model])

    assert result == [{"status": "success"}]
    assert len(requests) == 1
    assert requests[0]["verb"].value == "PUT"
    assert requests[0]["path"] == "/api/v1/manage/fabrics/AK-VXLAN/vrfs/ansible-msd-vrf"
    assert requests[0]["data"] == {
        "fabricName": "AK-VXLAN",
        "vrfName": "ansible-msd-vrf",
        "vrfType": "vxlanIbgp",
        "fabricData": {
            "advertiseHostRoute": True,
            "advertiseDefaultRoute": False,
        },
    }
