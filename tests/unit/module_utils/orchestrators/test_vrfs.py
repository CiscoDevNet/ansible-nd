# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for VRF orchestrator payload transformation.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import json

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import (
    HttpVerbEnum,
    OperationType,
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
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_config_utils import (
    vrf_name_filter,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_argument_specs import (
    _child_fabric_config_element_spec,
    vrf_base_argument_spec,
    vrf_parent_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_vrf import (
    MulticlusterParentVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import (
    Results,
)


class _Strategy:
    def __init__(self, fabric_data=None, is_child=False, is_parent=False, is_multicluster=False):
        self.fabric_data = fabric_data or {}
        self.is_child = is_child
        self.is_parent = is_parent
        self.is_multicluster = is_multicluster


def _transform(
    config,
    fabric_name="AK-VXLAN",
    fabric_data=None,
    is_child=False,
    is_parent=False,
    is_multicluster=False,
):
    """Call the payload transformer without constructing the full orchestrator."""
    instance = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(
        instance,
        "strategy",
        _Strategy(fabric_data, is_child, is_parent, is_multicluster),
    )
    if is_child:
        return instance._transform_child_config_to_payload_model_data(config, fabric_name)
    return instance._transform_config_to_payload_model_data(config, fabric_name)


class _EndpointStrategy:
    fabric_name = "AK-VXLAN"
    fabric_data = {}
    is_parent = False

    def __init__(self, is_child=False, is_multicluster=False):
        self.is_child = is_child
        self.is_multicluster = is_multicluster

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
    def vrfs_post_cls():
        from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
            EpManageFabricsVrfsPost,
        )

        return EpManageFabricsVrfsPost

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


class _McfgTopDownStrategy:
    fabric_name = "MCFG_FAB"
    is_parent = True
    is_child = False
    is_multicluster = True

    def __init__(self, fabric_data=None):
        self.fabric_data = fabric_data or {"management": {"type": "vxlan"}}


class _RestSend:
    def __init__(self, params):
        self.params = params
        self.response_current = {}


def _orchestrator_for_request_tests(params, is_child=False, is_multicluster=False):
    instance = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(instance, "strategy", _EndpointStrategy(is_child=is_child, is_multicluster=is_multicluster))
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


def test_vrfs_00021_transform_mcfg_parent_uses_schema_payload_not_template_payload():
    """
    # Summary

    Verify MCFG parent create/update payloads use the OneManage manage schema,
    not the deprecated template-config/top-down payload shape.
    """
    transformed = _transform(
        {
            "vrf_name": "ansible-mcfg-parent",
            "vrf_id": 9008031,
            "vlan_id": 631,
            "adv_host_routes": True,
            "adv_default_routes": False,
            "static_default_route": False,
        },
        fabric_name="MCFG_FAB",
        fabric_data={"managementType": "vxlan"},
        is_parent=True,
        is_multicluster=True,
    )
    payload = VrfDataModel.from_config(transformed).to_payload()

    assert payload["fabricName"] == "MCFG_FAB"
    assert payload["fabricData"]["advertiseHostRoute"] is True
    assert payload["fabricData"]["advertiseDefaultRoute"] is False
    assert payload["fabricData"]["configureStaticDefaultRoute"] is False

    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", _McfgTopDownStrategy())
    mcfg_payload = orchestrator._create_or_update_payload(VrfDataModel.from_config(transformed))

    assert mcfg_payload["fabricName"] == "MCFG_FAB"
    assert mcfg_payload["vrfName"] == "ansible-mcfg-parent"
    assert mcfg_payload["vrfType"] == "vxlan"
    assert mcfg_payload["vrfId"] == 9008031
    assert "vlanId" not in mcfg_payload
    assert "vrfTemplateConfig" not in mcfg_payload
    assert mcfg_payload["fabricData"] == {}
    assert mcfg_payload["coreData"]["vrfVlanName"] == ""
    assert mcfg_payload["coreData"]["vrfInterfaceDescription"] == ""
    assert mcfg_payload["coreData"]["vrfDescription"] == ""
    assert mcfg_payload["coreData"]["routeTargetImport"] == []
    assert mcfg_payload["coreData"]["routeTargetExport"] == []


def test_vrfs_00022_transform_msd_parent_omits_fabric_data():
    """
    # Summary

    Verify non-MCFG parent behavior remains unchanged and does not carry
    parent fabricData into the normal parent payload.
    """
    transformed = _transform(
        {
            "vrf_name": "ansible-msd-parent",
            "adv_host_routes": True,
            "adv_default_routes": False,
            "static_default_route": False,
        },
        is_parent=True,
    )
    payload = VrfDataModel.from_config(transformed).to_payload()

    assert "fabricData" not in payload


def test_vrfs_00023_transform_mcfg_parent_omits_implicit_fabric_defaults():
    """
    # Summary

    Verify MCFG parent configs do not carry implicit fabricData defaults when
    the playbook only intends child_fabric_config to control child options.
    """
    transformed = _transform(
        {
            "vrf_name": "ansible-mcfg-parent-child-options",
            "vrf_id": 9008032,
            "vlan_id": 632,
        },
        fabric_name="MCFG_FAB",
        is_parent=True,
        is_multicluster=True,
    )
    payload = VrfDataModel.from_config(transformed).to_payload()

    assert "fabricData" not in payload


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
                "freeform_config": "interface loopback10\n description test",
                "attachment_options": {
                    "dpu_secure": True,
                    "dpu_affinity": "dynamic",
                    "loopback_id": 10,
                    "loopback_ipv4_address": "10.10.10.10",
                    "loopback_ipv6_address": "2001:db8::10",
                    "import_vpn_rt": ["65000:10"],
                    "export_vpn_rt": ["65000:11"],
                    "import_evpn_rt": ["65000:12"],
                    "export_evpn_rt": ["65000:13"],
                },
            }
        ],
    }

    standalone = VrfConfigModel.from_config(config).to_config()
    parent = VrfParentConfigModel.from_config(dict(config, child_fabric_config=[{"fabric_name": "AK-VXLAN"}])).to_config()

    for parsed in (standalone, parent):
        assert parsed["deploy"] is False
        assert parsed["deploy_type"] == "vrf"
        attachment = parsed["attach"][0]
        assert attachment["ip_address"] == "192.168.1.224"
        assert attachment["freeform_config"] == "interface loopback10\n description test"
        attachment_options = attachment["attachment_options"]
        assert attachment_options["dpu_secure"] is True
        assert attachment_options["dpu_affinity"] == "dynamic"
        assert attachment_options["loopback_id"] == 10
        assert attachment_options["loopback_ipv4_address"] == "10.10.10.10"
        assert attachment_options["loopback_ipv6_address"] == "2001:db8::10"
        assert attachment_options["import_vpn_rt"] == ["65000:10"]
        assert attachment_options["export_vpn_rt"] == ["65000:11"]
        assert attachment_options["import_evpn_rt"] == ["65000:12"]
        assert attachment_options["export_evpn_rt"] == ["65000:13"]


def test_vrfs_00025a_config_model_rejects_attachment_aliases():
    """
    # Summary

    Verify playbook-facing VRF attachment config accepts snake_case only.
    """
    with pytest.raises(ValidationError, match="ipAddress|freeformConfig|attachmentOptions|dpuSecure|Extra inputs"):
        VrfConfigModel.from_config(
            {
                "vrf_name": "ansible-vrf-attach-alias",
                "attach": [
                    {
                        "ipAddress": "192.168.1.224",
                        "freeformConfig": "interface loopback10",
                        "attachmentOptions": {
                            "dpuSecure": True,
                        },
                    }
                ],
            }
        )


def test_vrfs_00026_config_models_match_argument_specs():
    """
    # Summary

    Verify playbook-facing config models accept the same field names exposed
    by their corresponding argument specs.
    """
    assert set(VrfConfigModel.model_fields) == set(vrf_base_argument_spec())
    assert set(VrfParentConfigModel.model_fields) == set(vrf_parent_argument_spec())
    attach_spec = vrf_base_argument_spec()["attach"]["options"]
    attachment_options_spec = attach_spec["attachment_options"]["options"]

    assert set(attach_spec) == {"ip_address", "freeform_config", "attachment_options"}
    assert "loopback_id" not in attach_spec
    assert "dpu_secure" not in attach_spec
    assert "dpu_affinity" not in attach_spec
    assert attachment_options_spec["dpu_affinity"]["choices"] == ["dynamic", "dpu1", "dpu2", "dpu3", "dpu4"]
    assert "dpu_secure" in attachment_options_spec
    assert "loopback_id" in attachment_options_spec
    assert "import_vpn_rt" in attachment_options_spec

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
        return {
            "vrfs": [
                {"vrfName": "ansible-vrf-b"},
                {"vrfName": "ansible-vrf-a"},
                {"vrfName": "ansible-vrf-other"},
            ]
        }

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [
        {"vrfName": "ansible-vrf-b"},
        {"vrfName": "ansible-vrf-a"},
    ]
    assert requested_paths == [
        "/api/v1/manage/fabrics/AK-VXLAN/vrfs?offset=0&max=10000",
    ]


def test_vrfs_00081_query_all_scoped_single_name_uses_fielded_filter():
    """
    # Summary

    Verify single-name scoped reads use the VRF name filter form supported by
    the controller.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "replaced",
            "config": [{"vrf_name": "ansible-vrf-a"}],
        }
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {"vrfs": [{"vrfName": "ansible-vrf-a"}]}

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [{"vrfName": "ansible-vrf-a"}]
    assert requested_paths == [
        "/api/v1/manage/fabrics/AK-VXLAN/vrfs?filter=vrfName%3Aansible-vrf-a",
    ]


def test_vrf_filter_builders_return_raw_expressions_for_endpoint_encoding():
    names = ["VRF/SECOND", "VRF PRIMARY&50%"]
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)

    assert vrf_name_filter(names) == "(vrfName:VRF PRIMARY&50% OR vrfName:VRF/SECOND)"
    assert orchestrator._vrf_name_filter(names) == "(vrfName:VRF PRIMARY&50% OR vrfName:VRF/SECOND)"


def test_vrf_query_all_encodes_reserved_filter_characters_once():
    vrf_name = "VRF PRIMARY&50%"
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "replaced",
            "config": [{"vrf_name": vrf_name}],
        }
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {"vrfs": [{"vrfName": vrf_name}]}

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [{"vrfName": vrf_name}]
    assert requested_paths == [
        "/api/v1/manage/fabrics/AK-VXLAN/vrfs?filter=vrfName%3AVRF%20PRIMARY%2650%25",
    ]


def test_vrfs_00081a_query_all_scoped_multi_name_uses_unfiltered_local_filter():
    """
    # Summary

    Verify multi-name VRF reads avoid unsupported Lucene OR filters and
    exact-filter the paginated read in module code.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "replaced",
            "config": [
                {"vrf_name": "ansible-vrf-b"},
                {"vrf_name": "ansible-vrf-a"},
            ],
        }
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {
            "vrfs": [
                {"vrfName": "ansible-vrf-b"},
                {"vrfName": "ansible-vrf-a"},
                {"vrfName": "ansible-vrf-other"},
            ]
        }

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [
        {"vrfName": "ansible-vrf-b"},
        {"vrfName": "ansible-vrf-a"},
    ]
    assert requested_paths == [
        "/api/v1/manage/fabrics/AK-VXLAN/vrfs?offset=0&max=10000",
    ]


def test_vrfs_00081b_mcfg_parent_scoped_query_uses_unfiltered_read_and_local_filter():
    """
    # Summary

    Verify MCFG parent scoped reads avoid Lucene filters on the OneManage
    parent surface and exact-filter the paginated read in module code.
    """
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(
        orchestrator,
        "strategy",
        MulticlusterParentVrfStrategy(
            fabric_name="MCFG_FAB",
            fabric_data={"management": {"type": "vxlan"}, "members": []},
        ),
    )
    object.__setattr__(
        orchestrator,
        "rest_send",
        _RestSend(
            {
                "state": "replaced",
                "config": [{"vrf_name": "ansible-vrf-a"}],
            }
        ),
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {
            "vrfs": [
                {"vrfName": "ansible-vrf-a", "fabricName": "MCFG_FAB"},
                {"vrfName": "ansible-vrf-other", "fabricName": "MCFG_FAB"},
            ],
            "meta": {"counts": {"remaining": 0, "total": 2}},
        }

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [{"vrfName": "ansible-vrf-a", "fabricName": "MCFG_FAB", "vrfType": "vxlan"}]
    assert requested_paths == ["/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfs?offset=0&max=10000"]


def test_vrfs_00082_query_all_uses_unfiltered_read_at_scoped_threshold():
    """
    # Summary

    Verify large targeted VRF configs avoid a large Lucene filter and use the
    normal fabric GET instead.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "merged",
            "config": [{"vrf_name": f"ansible-vrf-{index}"} for index in range(5)],
        }
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {"vrfs": [{"vrfName": "ansible-vrf-0"}]}

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [{"vrfName": "ansible-vrf-0"}]
    assert requested_paths == ["/api/v1/manage/fabrics/AK-VXLAN/vrfs?offset=0&max=10000"]


def test_vrfs_00083_query_all_unfiltered_walks_paginated_results():
    """
    # Summary

    Verify unfiltered reads follow max/offset pagination instead of relying on
    the controller default page size.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "gathered",
            "config": [],
        }
    )
    original_page_size = NDVrfOrchestrator.unfiltered_query_page_size
    NDVrfOrchestrator.unfiltered_query_page_size = 200
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        if "offset=0" in kwargs["path"]:
            return {
                "vrfs": [{"vrfName": f"ansible-vrf-{index:03d}"} for index in range(200)],
                "metadata": {"counts": {"total": 500, "remaining": 300}},
            }
        if "offset=200" in kwargs["path"]:
            return {
                "vrfs": [{"vrfName": f"ansible-vrf-{index:03d}"} for index in range(200, 400)],
                "metadata": {"counts": {"total": 500, "remaining": 100}},
            }
        return {
            "vrfs": [{"vrfName": f"ansible-vrf-{index:03d}"} for index in range(400, 500)],
            "metadata": {"counts": {"total": 500, "remaining": 0}},
        }

    object.__setattr__(orchestrator, "_request", request)

    try:
        result = orchestrator.query_all()
    finally:
        NDVrfOrchestrator.unfiltered_query_page_size = original_page_size

    assert len(result) == 500
    assert requested_paths == [
        "/api/v1/manage/fabrics/AK-VXLAN/vrfs?offset=0&max=200",
        "/api/v1/manage/fabrics/AK-VXLAN/vrfs?offset=200&max=200",
        "/api/v1/manage/fabrics/AK-VXLAN/vrfs?offset=400&max=200",
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


def test_vrfs_00087_mcfg_parent_normalizes_vrf_template_config():
    """
    # Summary

    Verify MCFG parent template-config data is converted back into the normal VRF
    schema shape used by validation and module output.
    """
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", _McfgTopDownStrategy())

    normalized = orchestrator._normalize_query_vrf_item(
        {
            "fabric": "MCFG_FAB",
            "vrfName": "ansible-nd-vrf-mcfg-a",
            "vrfId": 9008860,
            "vrfStatus": "NA",
            "vrfTemplateConfig": json.dumps(
                {
                    "vrfVlanId": "2860",
                    "vrfDescription": "Ansible ND VRF MCFG sanity merged",
                    "maxBgpPaths": "2",
                    "maxIbgpPaths": "2",
                    "disableRtAuto": "true",
                    "routeTargetImport": "65000:50660",
                    "routeTargetExport": "65000:50661",
                    "routeTargetImportEvpn": "65000:50662",
                    "routeTargetExportEvpn": "65000:50663",
                    "advertiseHostRouteFlag": "true",
                    "advertiseDefaultRouteFlag": "false",
                    "configureStaticDefaultRouteFlag": "false",
                }
            ),
        }
    )

    assert normalized["fabricName"] == "MCFG_FAB"
    assert normalized["vrfType"] == "vxlan"
    assert normalized["vrfStatus"] == "notApplicable"
    assert normalized["vlanId"] == 2860
    assert normalized["coreData"]["vrfDescription"] == "Ansible ND VRF MCFG sanity merged"
    assert normalized["coreData"]["maxBgpPaths"] == 2
    assert normalized["coreData"]["maxIbgpPaths"] == 2
    assert normalized["coreData"]["disableRtAuto"] is True
    assert normalized["coreData"]["routeTargetImport"] == ["65000:50660"]
    assert normalized["coreData"]["routeTargetExport"] == ["65000:50661"]
    assert normalized["coreData"]["evpnRouteTargetImport"] == ["65000:50662"]
    assert normalized["coreData"]["evpnRouteTargetExport"] == ["65000:50663"]
    assert normalized["fabricData"]["l3VniWithoutVlan"] is False
    assert normalized["fabricData"]["advertiseHostRoute"] is True
    assert normalized["fabricData"]["advertiseDefaultRoute"] is False
    assert normalized["fabricData"]["configureStaticDefaultRoute"] is False


def test_vrfs_00088_mcfg_parent_infers_l3vni_without_vlan_from_top_down_empty_vlan():
    """Template-config readback omits the explicit L3VNI flag on some releases but returns an empty VLAN."""
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", _McfgTopDownStrategy())

    normalized = orchestrator._normalize_query_vrf_item(
        {
            "fabric": "MCFG_FAB",
            "vrfName": "ansible-nd-vrf-mcfg-b",
            "vrfStatus": "NA",
            "vrfTemplateConfig": json.dumps(
                {
                    "vrfVlanId": "",
                    "vrfDescription": "Ansible ND VRF MCFG L3VNI without VLAN",
                    "advertiseDefaultRouteFlag": "true",
                    "configureStaticDefaultRouteFlag": "true",
                }
            ),
        }
    )

    assert "vlanId" not in normalized
    assert normalized["coreData"]["vrfDescription"] == "Ansible ND VRF MCFG L3VNI without VLAN"
    assert normalized["fabricData"]["l3VniWithoutVlan"] is True
    assert normalized["fabricData"]["advertiseDefaultRoute"] is True
    assert normalized["fabricData"]["configureStaticDefaultRoute"] is True


def test_vrfs_00089_mcfg_parent_enriches_missing_fabric_fields_from_child_vrfs():
    """
    MCFG parent template-config records may omit fabric-instance booleans; child
    fabric records remain the source of truth for those fields.
    """
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(
        orchestrator,
        "strategy",
        _McfgTopDownStrategy(
            {
                "members": [
                    {
                        "fabricName": "nac-msd-fabric1",
                        "fabricState": "member",
                        "clusterName": "ND42-REL",
                    }
                ]
            }
        ),
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {
            "vrfs": [
                {
                    "vrfName": "ansible-nd-vrf-mcfg-a",
                    "fabricData": {
                        "advertiseHostRoute": True,
                        "advertiseDefaultRoute": False,
                        "configureStaticDefaultRoute": False,
                    },
                }
            ]
        }

    object.__setattr__(orchestrator, "_request", request)

    enriched = orchestrator._enrich_mcfg_parent_vrfs_from_children(
        [
            {
                "fabricName": "MCFG_FAB",
                "vrfName": "ansible-nd-vrf-mcfg-a",
                "fabricData": {
                    "l3VniWithoutVlan": False,
                },
            }
        ]
    )

    assert requested_paths == ["/api/v1/manage/fabrics/nac-msd-fabric1/vrfs?clusterName=ND42-REL"]
    assert enriched[0]["fabricData"] == {
        "l3VniWithoutVlan": False,
        "advertiseHostRoute": True,
        "advertiseDefaultRoute": False,
        "configureStaticDefaultRoute": False,
    }


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


def test_vrfs_00091_mcfg_parent_delete_uses_remove_action_body():
    """
    # Summary

    Verify multicluster parent VRF delete uses the OneManage remove action
    with a body payload, not the deprecated top-down bulk-delete query path.
    """
    strategy = MulticlusterParentVrfStrategy(
        fabric_name="MCFG_FAB",
        fabric_data={
            "managementType": "vxlan",
            "onemanageProxyPath": "/onemanage",
        },
    )
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", strategy)
    object.__setattr__(orchestrator, "rest_send", _RestSend({"state": "deleted", "config": []}))
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {"results": [{"vrfName": name, "status": "success"} for name in kwargs["data"]["vrfNames"]]}

    object.__setattr__(orchestrator, "delete_retry_delay", 0)
    object.__setattr__(orchestrator, "_request", request)

    result = orchestrator._delete_bulk_with_retry(["ansible-vrf-a", "ansible-vrf-b"])

    assert requests == [
        {
            "path": "/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfActions/remove",
            "verb": HttpVerbEnum.POST,
            "data": {"vrfNames": ["ansible-vrf-a", "ansible-vrf-b"]},
            "operation_type": OperationType.DELETE,
        }
    ]
    assert result["results"] == [
        {"vrfName": "ansible-vrf-a", "status": "success"},
        {"vrfName": "ansible-vrf-b", "status": "success"},
    ]


def test_vrfs_00095_bulk_create_uses_single_vrfs_payload():
    """
    # Summary

    Verify standalone/parent VRF creates are batched into one POST request with
    the API's list wrapper.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "merged",
            "config": [
                {"vrf_name": "ansible-vrf-a"},
                {"vrf_name": "ansible-vrf-b"},
            ],
        }
    )
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {
            "results": [
                {"vrfName": "ansible-vrf-a", "status": "success"},
                {"vrfName": "ansible-vrf-b", "status": "success"},
            ]
        }

    object.__setattr__(orchestrator, "_request", request)
    models = [
        VrfDataModel.from_config(
            {
                "fabric_name": "AK-VXLAN",
                "vrf_name": "ansible-vrf-a",
                "vrf_type": "vxlanIbgp",
            }
        ),
        VrfDataModel.from_config(
            {
                "fabric_name": "AK-VXLAN",
                "vrf_name": "ansible-vrf-b",
                "vrf_type": "vxlanIbgp",
            }
        ),
    ]

    result = orchestrator.create_bulk(models)

    assert result["results"][0]["vrfName"] == "ansible-vrf-a"
    assert len(requests) == 1
    assert requests[0]["path"] == "/api/v1/manage/fabrics/AK-VXLAN/vrfs"
    assert requests[0]["verb"].value == "POST"
    assert [item["vrfName"] for item in requests[0]["data"]["vrfs"]] == [
        "ansible-vrf-a",
        "ansible-vrf-b",
    ]


def test_vrfs_00096_mcfg_parent_bulk_create_uses_onemanage_schema_payload():
    """
    # Summary

    Verify MCFG parent VRF create uses the OneManage manage schema payload
    accepted by ND 4.2: ``{"vrfs": [{fabricName, vrfName, vrfType, coreData,
    fabricData, vrfId}]}``.
    """
    strategy = MulticlusterParentVrfStrategy(
        fabric_name="MCFG_C",
        fabric_data={
            "managementType": "vxlan",
            "manageFabricDetails": {"management": {"type": "vxlan"}},
        },
    )
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", strategy)
    object.__setattr__(orchestrator, "rest_send", _RestSend({"state": "merged", "config": []}))
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {"results": [{"vrfName": "MyVRF_50000", "status": "success"}]}

    object.__setattr__(orchestrator, "_request", request)
    model = VrfDataModel.from_config(
        {
            "fabric_name": "MCFG_C",
            "vrf_name": "MyVRF_50000",
            "vrf_type": "vxlan",
            "vrf_id": 50000,
            "vlan_id": 3123,
            "core_data": {
                "mtu": 9216,
                "routingTag": 12345,
                "vrfRouteMap": "FABRIC-RMAP-REDIST-SUBNET",
                "v6VrfRouteMap": "FABRIC-RMAP-REDIST-SUBNET",
                "maxBgpPaths": 1,
                "maxIbgpPaths": 2,
                "ipv6LinkLocal": True,
                "disableRtAuto": False,
            },
            "fabric_data": {
                "advertiseHostRoute": True,
                "advertiseDefaultRoute": False,
            },
        }
    )

    orchestrator.create_bulk([model])

    assert len(requests) == 1
    assert requests[0]["path"] == "/api/v1/oneManage/manage/fabrics/MCFG_C/vrfs"
    assert requests[0]["verb"] == HttpVerbEnum.POST
    assert requests[0]["operation_type"] == OperationType.CREATE
    assert requests[0]["data"] == {
        "vrfs": [
            {
                "fabricName": "MCFG_C",
                "vrfName": "MyVRF_50000",
                "vrfType": "vxlan",
                "coreData": {
                    "vrfVlanName": "",
                    "vrfInterfaceDescription": "",
                    "vrfDescription": "",
                    "mtu": 9216,
                    "routingTag": 12345,
                    "vrfRouteMap": "FABRIC-RMAP-REDIST-SUBNET",
                    "v6VrfRouteMap": "FABRIC-RMAP-REDIST-SUBNET",
                    "maxBgpPaths": 1,
                    "maxIbgpPaths": 2,
                    "ipv6LinkLocal": True,
                    "disableRtAuto": False,
                    "routeTargetImport": [],
                    "routeTargetExport": [],
                    "evpnRouteTargetImport": [],
                    "evpnRouteTargetExport": [],
                },
                "fabricData": {},
                "vrfId": 50000,
            }
        ]
    }


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


def test_vrfs_00105_remote_mcfg_child_update_falls_back_to_list_visibility():
    """
    # Summary

    Verify a remote MCFG child VRF update rejection does not fail the parent
    workflow when the VRF is visible through the child list endpoint.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "merged",
            "config": [{"vrf_name": "ansible-mcfg-vrf"}],
        },
        is_child=True,
        is_multicluster=True,
    )
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        if kwargs["verb"].value == "PUT":
            raise Exception("Request failed (400): Fabric 'AK-VXLAN' does not exist")
        return {"vrfs": [{"fabricName": "AK-VXLAN", "vrfName": "ansible-mcfg-vrf"}]}

    object.__setattr__(orchestrator, "_request", request)
    model = VrfDataModel.from_config(
        {
            "fabric_name": "AK-VXLAN",
            "vrf_name": "ansible-mcfg-vrf",
            "fabric_data": {
                "advertiseDefaultRoute": False,
                "advertiseHostRoute": True,
            },
        }
    )

    result = orchestrator.update(model)

    assert result["status"] == "skipped"
    assert result["fabricName"] == "AK-VXLAN"
    assert result["vrfName"] == "ansible-mcfg-vrf"
    assert [request["verb"].value for request in requests] == ["PUT", "GET"]
    assert requests[1]["path"] == "/api/v1/manage/fabrics/AK-VXLAN/vrfs?filter=vrfName%3Aansible-mcfg-vrf"


def test_vrfs_00106_handled_remote_mcfg_child_update_clears_failed_trace():
    """
    # Summary

    Verify the accepted remote-child PUT rejection remains visible in debug
    traces but no longer marks the task failed after list visibility is proven.
    """
    results = Results()
    results.action = OperationType.UPDATE.value
    results.operation_type = OperationType.UPDATE
    results.path_current = "/api/v1/manage/fabrics/AK-VXLAN/vrfs/ansible-mcfg-vrf"
    results.verb_current = HttpVerbEnum.PUT
    results.payload_current = {"vrfName": "ansible-mcfg-vrf"}
    results.response_current = {
        "RETURN_CODE": 400,
        "DATA": {"message": "Fabric 'AK-VXLAN' does not exist"},
    }
    results.result_current = {"success": False, "changed": False}
    results.diff_current = {}
    results.verbosity_level_current = 2
    results.register_api_call()

    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "merged",
            "config": [{"vrf_name": "ansible-mcfg-vrf"}],
        },
        is_child=True,
        is_multicluster=True,
    )
    object.__setattr__(orchestrator, "results", results)

    orchestrator._mark_child_update_rejection_handled("/api/v1/manage/fabrics/AK-VXLAN/vrfs/ansible-mcfg-vrf")

    results.build_final_result()
    final = results.final_result
    assert final["failed"] is False
    assert final["result"][0]["success"] is True
    assert final["result"][0]["handled"] is True
    assert final["response"][0]["handled"] is True


def test_vrfs_00107_vrf_status_accepts_uppercase_controller_values():
    """
    # Summary

    Verify live controller status casing is normalized by the API data model.
    """
    model = VrfDataModel.from_response(
        {
            "fabricName": "MCFG_C",
            "vrfName": "ansible-nd-vrf-mcfg-merged",
            "vrfStatus": "PENDING",
        }
    )

    assert model.to_config()["vrf_status"] == "pending"
