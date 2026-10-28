"""Actionable VRF/Network fabric-feature preflight tests."""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.fabric_feature_preflight import (
    preflight_feature_changes,
    preflight_workflow_features,
    validate_fabric_features,
    validate_standalone_vrf_trm_requirements,
    validate_standalone_vrf_svi_requirements,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_data_models import (
    NetworkBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_data_models import (
    VrfDataModel,
)


def _details(fabric_type="vxlanIbgp", private_vlan=True, trm=True, netflow=True):
    return {
        "management": {
            "type": fabric_type,
            "privateVlan": private_vlan,
            "tenantRoutedMulticast": trm,
            "netflowSettings": {"netflow": netflow},
        }
    }


@pytest.mark.parametrize(
    "vlan_type",
    [
        "primary",
        "community",
        "isolated",
        "privatePrimary",
        "privateSecondaryCommunity",
        "privateSecondaryIsolated",
    ],
)
@pytest.mark.parametrize("fabric_type", ["vxlanIbgp", "vxlanEbgp"])
def test_pvlan_requires_enabled_dc_fabric(vlan_type, fabric_type):
    config = {"vlan_network_type": vlan_type}
    validate_fabric_features(_details(fabric_type), config, "Network", 0, "FAB")
    with pytest.raises(ValueError, match="requires private VLAN"):
        validate_fabric_features(_details(fabric_type, private_vlan=False), config, "Network", 0, "FAB")
    details = _details(fabric_type)
    del details["management"]["privateVlan"]
    with pytest.raises(ValueError, match="cannot verify private VLAN"):
        validate_fabric_features(details, config, "Network", 0, "FAB")


@pytest.mark.parametrize("fabric_type", ["vxlanCampus", "externalConnectivity", "unknown"])
def test_pvlan_rejects_non_dc_fabrics(fabric_type):
    with pytest.raises(ValueError, match="supported only on Data Center VXLAN"):
        validate_fabric_features(_details(fabric_type), {"vlan_network_type": "primary"}, "Network", 2, "FAB")


@pytest.mark.parametrize("resource", ["Network", "VRF"])
@pytest.mark.parametrize("fabric_type", ["vxlanIbgp", "vxlanEbgp", "vxlanCampus"])
@pytest.mark.parametrize(
    "feature,flag,description",
    [
        ("trm_enable", "tenantRoutedMulticast", "IPv4 Tenant Routed Multicast"),
        ("netflow_enable", "netflow", "NetFlow"),
    ],
)
def test_affirmative_features_require_fabric_settings(resource, fabric_type, feature, flag, description):
    config = {feature: True}
    validate_fabric_features(_details(fabric_type), config, resource, 1, "FAB")
    details = _details(fabric_type)
    target = details["management"]["netflowSettings"] if feature == "netflow_enable" else details["management"]
    target[flag] = False
    with pytest.raises(ValueError, match=description):
        validate_fabric_features(details, config, resource, 1, "FAB")
    del target[flag]
    with pytest.raises(ValueError, match="cannot verify"):
        validate_fabric_features(details, config, resource, 1, "FAB")


def test_disabled_and_unproven_features_are_not_blocked():
    validate_fabric_features(
        _details("vxlanCampus", trm=False, netflow=False),
        {"trm_enable": False, "netflow_enable": False},
        "Network",
        0,
        "FAB",
    )
    validate_fabric_features(
        _details("externalConnectivity", trm=False, netflow=False),
        {"trm_enable": True, "netflow_enable": True},
        "Network",
        0,
        "FAB",
    )
    validate_fabric_features(
        _details(trm=False),
        {"dhcp_servers": ["192.0.2.1"], "ipv6_trm": True},
        "Network",
        0,
        "FAB",
    )


@pytest.mark.parametrize(
    ("config", "missing"),
    [
        ({"trm_enable": True, "no_rp": True}, "underlay_mcast_ip"),
        ({"trm_enable": True, "underlay_mcast_ip": "239.1.1.3"}, "rp_address"),
        (
            {
                "trm_enable": True,
                "rp_address": "192.0.2.1",
                "underlay_mcast_ip": "239.1.1.3",
            },
            "rp_loopback_id",
        ),
        ({"ipv6_trm": True, "underlay_mcast_ip": "239.1.1.3"}, "v6_rp_address"),
    ],
)
def test_standalone_trm_requires_mode_specific_fields(config, missing):
    with pytest.raises(ValueError, match=missing):
        validate_standalone_vrf_trm_requirements(config, 0, "FAB")


def test_standalone_trm_external_and_no_rp_modes_allow_omitted_loopback():
    validate_standalone_vrf_trm_requirements(
        {
            "trm_enable": True,
            "rp_external": True,
            "rp_address": "192.0.2.1",
            "underlay_mcast_ip": "239.1.1.3",
        },
        0,
        "FAB",
    )
    validate_standalone_vrf_trm_requirements({"ipv6_trm": True, "v6_no_rp": True, "underlay_mcast_ip": "239.1.1.3"}, 0, "FAB")


@pytest.mark.parametrize(
    "field,value",
    [
        ("vlan_id", 3001),
        ("vrf_vlan_name", "old"),
        ("vrf_intf_desc", "old"),
        ("vrf_int_mtu", 9216),
        ("ipv6_linklocal_enable", True),
    ],
)
def test_effective_no_vlan_mode_rejects_sparse_svi_requests(field, value):
    with pytest.raises(ValueError, match=field):
        validate_standalone_vrf_svi_requirements({"l3vni_wo_vlan": True}, {field: value}, 0, "FAB")
    validate_standalone_vrf_svi_requirements({"l3vni_wo_vlan": True}, {"vrf_description": "new"}, 0, "FAB")


def test_sparse_svi_edit_is_rejected_against_existing_no_vlan_vrf():
    current = _Model("BLUE", {"l3vni_wo_vlan": True, "vrf_description": "old"})
    proposed = _Model("BLUE", {"vrf_int_mtu": 9216})
    sm = _StateMachine(proposed, {"BLUE": current}, "changed")
    with pytest.raises(ValueError, match="vrf_int_mtu not applicable"):
        preflight_feature_changes(sm, "merged", lambda: _details(), "VRF", "FAB", standalone_vrf=True)
    assert current.config == {"l3vni_wo_vlan": True, "vrf_description": "old"}


@pytest.mark.parametrize("action", ["enforcedPermit", "enforcedDeny"])
def test_enforced_vrf_action_requires_enabled_fabric_security_groups(action):
    config = {"default_security_action": action}
    details = _details()
    with pytest.raises(ValueError, match="cannot verify security group"):
        validate_fabric_features(details, config, "VRF", 0, "FAB", standalone_vrf=True)
    details["management"]["securityGroupTag"] = False
    with pytest.raises(ValueError, match="requires security groups"):
        validate_fabric_features(details, config, "VRF", 0, "FAB", standalone_vrf=True)
    details["management"]["securityGroupTag"] = True
    validate_fabric_features(details, config, "VRF", 0, "FAB", standalone_vrf=True)
    validate_fabric_features(_details(), config, "VRF", 0, "FAB")


def test_sparse_enforced_action_uses_effective_fabric_security_setting():
    current = _Model("BLUE", {"default_security_action": "unenforcedOrNone"})
    proposed = _Model("BLUE", {"default_security_action": "enforcedPermit"})
    sm = _StateMachine(proposed, {"BLUE": current}, "changed")
    details = _details()
    details["management"]["securityGroupTag"] = False
    with pytest.raises(ValueError, match="requires security groups"):
        preflight_feature_changes(sm, "merged", lambda: details, "VRF", "FAB", standalone_vrf=True)
    assert current.config["default_security_action"] == "unenforcedOrNone"


class _Model:
    def __init__(self, name, config):
        self.network_name = name
        self.config = config

    def get_identifier_value(self):
        return self.network_name

    def model_copy(self, deep=False):
        return _Model(self.network_name, deepcopy(self.config) if deep else dict(self.config))

    def merge(self, other):
        self.config.update(other.config)
        return self

    def to_gathered_config(self):
        return self.config


class _Collection:
    def __init__(self, current, status):
        self.current = current
        self.status = status

    def get(self, name):
        return self.current.get(name)

    def get_diff_config(self, _item, exclude_unset=False):
        del exclude_unset
        return self.status


class _StateMachine:
    def __init__(self, proposed, current, status):
        self.proposed = [proposed]
        self.existing = _Collection(current, status)


def test_unchanged_resource_and_read_delete_states_do_not_fetch_fabric_details():
    proposed = _Model("BLUE", {"vlan_network_type": "primary"})
    sm = _StateMachine(proposed, {"BLUE": proposed}, "no_diff")

    def unexpected_details():
        raise AssertionError("No fabric GET expected")

    for state in ("merged", "replaced", "overridden", "staged", "gathered", "deleted"):
        preflight_feature_changes(sm, state, unexpected_details, "Network", "FAB")


def test_sparse_merge_checks_effective_mode_without_mutating_inventory():
    current = _Model("BLUE", {"vlan_network_type": "primary", "display_name": "OLD"})
    proposed = _Model("BLUE", {"display_name": "NEW"})
    sm = _StateMachine(proposed, {"BLUE": current}, "changed")
    with pytest.raises(ValueError, match="requires private VLAN"):
        preflight_feature_changes(sm, "merged", lambda: _details(private_vlan=False), "Network", "FAB")
    assert current.config["display_name"] == "OLD"


@pytest.mark.parametrize(
    "prerequisite,dependent,value",
    [
        ("trm_enable", "igmp_version", 3),
        ("netflow_enable", "vlan_netflow_monitor", "VLAN_MON"),
        ("netflow_enable", "interface_netflow_monitor", "INTF_MON"),
    ],
)
def test_child_dependencies_reuse_the_feature_preflight_merge(monkeypatch, prerequisite, dependent, value):
    """Child dependency checks reuse one effective merge and skip unchanged writes."""
    current = _Model("BLUE", {prerequisite: True})
    proposed = _Model("BLUE", {dependent: value})
    sm = _StateMachine(proposed, {"BLUE": current}, "changed")
    merges = []
    original_merge = _Model.merge

    def record_merge(model, intent):
        merges.append(model)
        return original_merge(model, intent)

    monkeypatch.setattr(_Model, "merge", record_merge)
    preflight_feature_changes(sm, "merged", _details, "Network", "CHILD", child_network=True)
    assert len(merges) == 1
    assert current.config == {prerequisite: True}

    def unexpected_details():
        raise AssertionError("Dependency validation must precede fabric retrieval")

    sm.existing = _Collection({}, "new")
    with pytest.raises(ValueError, match=rf"child_fabric_config\[CHILD\].*{prerequisite}=true"):
        preflight_feature_changes(sm, "merged", unexpected_details, "Network", "CHILD", child_network=True)

    sm.existing = _Collection({"BLUE": current}, "no_diff")
    preflight_feature_changes(sm, "merged", unexpected_details, "Network", "CHILD", child_network=True)
    assert len(merges) == 1


def test_sparse_standalone_vrf_trm_inherits_existing_required_values():
    current = _Model("BLUE", {"ipv6_trm": True, "v6_no_rp": True, "underlay_mcast_ip": "239.1.1.3"})
    proposed = _Model("BLUE", {"ipv6_trm": True, "v6_no_rp": True})
    sm = _StateMachine(proposed, {"BLUE": current}, "changed")
    details = _details()
    details["management"]["tenantRoutedMulticastIpv6"] = True
    preflight_feature_changes(sm, "merged", lambda: details, "VRF", "FAB", standalone_vrf=True)
    assert current.config["underlay_mcast_ip"] == "239.1.1.3"


def test_ipv6_vrf_trm_requires_fabric_setting():
    config = {"ipv6_trm": True}
    with pytest.raises(ValueError, match="cannot verify IPv6 TRM"):
        validate_fabric_features(_details(), config, "VRF", 0, "FAB")
    details = _details()
    details["management"]["tenantRoutedMulticastIpv6"] = False
    with pytest.raises(ValueError, match="IPv6 Tenant Routed Multicast"):
        validate_fabric_features(details, config, "VRF", 0, "FAB")


def test_attachment_only_change_is_preflighted_but_unchanged_attachment_is_not():
    proposed = _Model("BLUE", {"vlan_network_type": "primary"})
    sm = _StateMachine(proposed, {"BLUE": proposed}, "no_diff")
    with pytest.raises(ValueError, match="requires private VLAN"):
        preflight_feature_changes(
            sm,
            "merged",
            lambda: _details(private_vlan=False),
            "Network",
            "FAB",
            attachment_names={"BLUE"},
        )
    preflight_feature_changes(
        sm,
        "merged",
        lambda: _details(private_vlan=False),
        "Network",
        "FAB",
        attachment_names=set(),
    )


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
def test_each_write_state_rejects_changed_feature_before_execution(state):
    proposed = _Model("BLUE", {"trm_enable": True})
    sm = _StateMachine(proposed, {}, "new")
    with pytest.raises(ValueError, match="trm_enable=true"):
        preflight_feature_changes(sm, state, lambda: _details(trm=False), "Network", "FAB")


def test_preflight_reads_public_flags_from_real_payload_models():
    network = NetworkBaseModel.from_config(
        {
            "network_name": "BLUE",
            "network_type": "vxlanIbgp",
            "vlan_network_type": "privatePrimary",
            "l3_data": {"fabric_data": {"ipv4_trm": True, "netflow": True}},
        }
    )
    vrf = VrfDataModel.from_config(
        {
            "fabric_name": "FAB",
            "vrf_name": "BLUE",
            "vrf_type": "vxlanIbgp",
            "fabric_data": {"trm_data": {"ipv4_trm": True}, "netflow": True},
        }
    )
    assert {key: network.to_gathered_config()[key] for key in ("vlan_network_type", "trm_enable", "netflow_enable")} == {
        "vlan_network_type": "primary",
        "trm_enable": True,
        "netflow_enable": True,
    }
    assert {key: vrf.to_gathered_config()[key] for key in ("trm_enable", "netflow_enable")} == {
        "trm_enable": True,
        "netflow_enable": True,
    }


def test_parent_checks_each_child_full_fabric_details():
    proposed = _Model("BLUE", {"trm_enable": True})
    sm = _StateMachine(proposed, {}, "new")

    class Resolver:
        def __init__(self):
            self.calls = []

        def get_fabric_details(self, name, cluster):
            self.calls.append((name, cluster))
            return _details(trm=name == "CHILD1")

    class Strategy:
        is_parent = True
        fabric_data = {
            "members": [
                {"fabricName": "CHILD1"},
                {"fabricName": "CHILD2", "clusterName": "REMOTE"},
            ]
        }

        @staticmethod
        def child_fabric_members():
            return ["CHILD1", "CHILD2"]

    class Attachments:
        @staticmethod
        def planned_attach_payloads(_current, _desired):
            return []

    resolver = Resolver()

    class Coordinator:
        attachments = Attachments()
        _fabric_resolver = resolver

    coordinator = Coordinator()
    with pytest.raises(ValueError, match="CHILD2.*trm_enable"):
        preflight_workflow_features(coordinator, sm, {"state": "merged"}, Strategy(), "Network")
    assert resolver.calls == [("CHILD1", None), ("CHILD2", "REMOTE")]
