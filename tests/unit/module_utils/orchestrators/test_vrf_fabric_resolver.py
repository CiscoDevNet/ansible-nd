# -*- coding: utf-8 -*-

"""Unit tests for VRF fabric resolver endpoint wiring."""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_fabric_resolver import (
    VrfFabricResolver,
)


class _ND:
    version = "3.2.1"

    def __init__(self):
        self.calls = []

    def request(self, path, method="GET", **kwargs):
        self.calls.append({"path": path, "method": method, "kwargs": kwargs})
        if path == "/api/v1/manage/fabrics/fab1":
            return {"management": {"type": "vxlanIbgp"}}
        if path == "/api/v1/manage/fabrics/MCFG_C":
            return {"name": "MCFG_C", "category": "fabricGroup", "management": {"type": "vxlan"}}
        if path == "/api/v1/oneManage/manage/fabrics/MCFG_C/vrfs?max=1":
            return {"vrfs": [], "meta": {"total": 0, "remaining": 0}}
        if path == "/api/v1/manage/fabrics/mfd1?clusterName=cluster1":
            return {"management": {"type": "vxlanEbgp"}}
        if path == "/api/v1/oneManage/manage/fabrics/mfd1/members":
            return {"fabrics": [{"name": "child1", "clusterName": "cluster2", "type": "vxlanIbgp"}]}
        return {}


class _Connection:
    def __init__(self, responses, options=None):
        self.responses = responses
        self.options = options or {}
        self.calls = []

    def send_request(self, method, path):
        self.calls.append({"path": path, "method": method})
        return self.responses.get(path, {"status": 404, "body": {}})

    def get_option(self, name):
        return self.options.get(name)

    def pop_messages(self):
        return []


class _MSDND(_ND):
    def __init__(self):
        super().__init__()
        self.httpapi_logs = []
        self.connection = _Connection(
            {
                "/api/v1/oneManage/manage/fabrics/msd_p/vrfs?max=1": {
                    "status": 500,
                    "body": {"code": 500, "message": "this API is allowed only for remote user"},
                }
            }
        )

    def request(self, path, method="GET", **kwargs):
        self.calls.append({"path": path, "method": method, "kwargs": kwargs})
        if path == "/api/v1/manage/fabrics/msd_p":
            return {"name": "msd_p", "category": "fabricGroup", "management": {"type": "vxlan"}}
        if path == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/msd/fabric-associations":
            return [
                {"fabricName": "msd_p", "fabricType": "MSD", "fabricState": "active"},
                {"fabricName": "nacfab", "fabricType": "VXLAN", "fabricState": "member", "fabricParent": "msd_p"},
            ]
        return {}


class _ChildND(_ND):
    def __init__(self, member_parent, member_name, member_probe_body):
        super().__init__()
        self.member_parent = member_parent
        self.member_name = member_name
        self.httpapi_logs = []
        self.connection = _Connection(
            {
                f"/api/v1/oneManage/manage/fabrics/{member_parent}/members": member_probe_body,
            }
        )

    def request(self, path, method="GET", **kwargs):
        self.calls.append({"path": path, "method": method, "kwargs": kwargs})
        if path == f"/api/v1/manage/fabrics/{self.member_name}":
            return {"name": self.member_name, "category": "fabric", "management": {"type": "vxlanIbgp"}}
        if path == "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/msd/fabric-associations":
            return [
                {"fabricName": self.member_parent, "fabricType": "MSD", "fabricState": "msd", "fabricParent": "None"},
                {"fabricName": self.member_name, "fabricType": "Switch_Fabric", "fabricState": "member", "fabricParent": self.member_parent},
            ]
        return {}


def test_vrf_fabric_resolver_00010_standalone_enrichment_does_not_fetch_members():
    nd = _ND()
    resolver = VrfFabricResolver(nd_module=nd, fabric_name="fab1")

    enriched = resolver._enrich_with_manage_fabric_details({"fabricName": "fab1", "fabricType": "VXLAN"})

    assert enriched["vrfType"] == "vxlanIbgp"
    assert [call["path"] for call in nd.calls] == ["/api/v1/manage/fabrics/fab1"]


def test_vrf_fabric_resolver_00020_mcfg_enrichment_fetches_members_with_cluster_name():
    nd = _ND()
    resolver = VrfFabricResolver(nd_module=nd, fabric_name="mfd1")

    enriched = resolver._enrich_with_manage_fabric_details({"fabricName": "mfd1", "fabricType": "MFD", "clusterName": "cluster1"})

    assert enriched["vrfType"] == "vxlanEbgp"
    assert enriched["manageFabricMembers"] == [
        {"name": "child1", "clusterName": "cluster2", "type": "vxlanIbgp", "fabricName": "child1", "fabricState": "member", "fabricType": "vxlanIbgp"}
    ]
    assert [call["path"] for call in nd.calls] == [
        "/api/v1/manage/fabrics/mfd1?clusterName=cluster1",
        "/api/v1/oneManage/manage/fabrics/mfd1/members",
    ]


def test_vrf_fabric_resolver_00030_mcfg_detection_uses_schema_backed_onemanage_resource_path():
    nd = _ND()
    resolver = VrfFabricResolver(nd_module=nd, fabric_name="MCFG_C")

    fabric_type, fabric_data = resolver._resolve_fabric_type()

    assert fabric_type == "multicluster_parent"
    assert fabric_data == {"fabricName": "MCFG_C", "fabricType": "MFD", "fabricState": "active"}
    assert [call["path"] for call in nd.calls] == [
        "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/msd/fabric-associations",
        "/api/v1/manage/fabrics/MCFG_C",
        "/api/v1/oneManage/manage/fabrics/MCFG_C/vrfs?max=1",
    ]


def test_vrf_fabric_resolver_00031_mcfg_detection_uses_httpapi_connection_probe():
    nd = _ND()
    nd.httpapi_logs = []
    nd.connection = _Connection(
        {
            "/api/v1/oneManage/manage/fabrics/MCFG_C/vrfs?max=1": {
                "status": 200,
                "body": {"vrfs": [], "meta": {"total": 0, "remaining": 0}},
            }
        },
    )
    resolver = VrfFabricResolver(nd_module=nd, fabric_name="MCFG_C")

    fabric_type, fabric_data = resolver._resolve_fabric_type()

    assert fabric_type == "multicluster_parent"
    assert fabric_data == {"fabricName": "MCFG_C", "fabricType": "MFD", "fabricState": "active"}
    assert [call["path"] for call in nd.connection.calls] == ["/api/v1/oneManage/manage/fabrics/MCFG_C/vrfs?max=1"]


def test_vrf_fabric_resolver_00040_standalone_detection_does_not_probe_onemanage():
    nd = _ND()
    resolver = VrfFabricResolver(nd_module=nd, fabric_name="fab1")

    fabric_type, fabric_data = resolver._resolve_fabric_type()

    assert fabric_type == "standalone"
    assert fabric_data == {"fabricName": "fab1", "fabricType": None, "fabricState": "active"}
    assert [call["path"] for call in nd.calls] == [
        "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/msd/fabric-associations",
        "/api/v1/manage/fabrics/fab1",
    ]


def test_vrf_fabric_resolver_00050_msd_detection_falls_back_when_onemanage_unavailable():
    nd = _MSDND()
    resolver = VrfFabricResolver(nd_module=nd, fabric_name="msd_p")

    fabric_type, fabric_data = resolver._resolve_fabric_type()

    assert fabric_type == "multisite_parent"
    assert fabric_data == {
        "fabricName": "msd_p",
        "fabricType": "MSD",
        "fabricState": "active",
        "fabricParent": None,
        "members": [{"fabricName": "nacfab", "fabricType": "VXLAN", "fabricState": "member", "fabricParent": "msd_p"}],
    }
    assert [call["path"] for call in nd.calls] == [
        "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/msd/fabric-associations",
        "/api/v1/manage/fabrics/msd_p",
    ]
    assert [call["path"] for call in nd.connection.calls] == [
        "/api/v1/oneManage/manage/fabrics/msd_p/vrfs?max=1",
    ]


def test_vrf_fabric_resolver_00060_mcfg_child_uses_parent_onemanage_members_cluster():
    nd = _ChildND(
        "MCFG_C",
        "nacfab",
        {
            "status": 200,
            "body": {"fabrics": [{"name": "nacfab", "clusterName": "ND42-REL", "fabricGroupName": "MCFG_C", "type": "vxlanIbgp"}]},
        },
    )
    resolver = VrfFabricResolver(nd_module=nd, fabric_name="nacfab")

    fabric_type, fabric_data = resolver._resolve_fabric_type()

    assert fabric_type == "multicluster_child"
    assert fabric_data["fabricName"] == "nacfab"
    assert fabric_data["fabricParent"] == "MCFG_C"
    assert fabric_data["clusterName"] == "ND42-REL"
    assert [call["path"] for call in nd.connection.calls] == ["/api/v1/oneManage/manage/fabrics/MCFG_C/members"]


def test_vrf_fabric_resolver_00070_msd_child_falls_back_when_parent_onemanage_unavailable():
    nd = _ChildND(
        "msd_p",
        "AK-VXLAN",
        {
            "status": 500,
            "body": {"code": 500, "message": "this API is allowed only for remote user"},
        },
    )
    resolver = VrfFabricResolver(nd_module=nd, fabric_name="AK-VXLAN")

    fabric_type, fabric_data = resolver._resolve_fabric_type()

    assert fabric_type == "multisite_child"
    assert fabric_data == {
        "fabricName": "AK-VXLAN",
        "fabricType": "Switch_Fabric",
        "fabricState": "member",
        "fabricParent": "msd_p",
    }
    assert [call["path"] for call in nd.connection.calls] == ["/api/v1/oneManage/manage/fabrics/msd_p/members"]
