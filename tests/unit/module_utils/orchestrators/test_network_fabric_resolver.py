# -*- coding: utf-8 -*-

"""Unit tests for network fabric resolver endpoint wiring."""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_fabric_resolver import (
    NetworkFabricResolver,
)


class _ND:
    version = "3.2.1"

    def __init__(self):
        self.calls = []

    def request(self, path, method="GET", **kwargs):
        self.calls.append({"path": path, "method": method, "kwargs": kwargs})
        if path == "/api/v1/manage/fabrics/fab1":
            return {"management": {"type": "vxlanIbgp"}}
        if path == "/api/v1/manage/fabrics/mfd1?clusterName=cluster1":
            return {"management": {"type": "vxlanEbgp"}}
        if path == "/api/v1/manage/fabrics/mfd1/members?clusterName=cluster1":
            return [{"fabricName": "child1", "clusterName": "cluster2", "fabricState": "member"}]
        return {}


def test_network_fabric_resolver_00010_standalone_enrichment_does_not_fetch_members():
    nd = _ND()
    resolver = NetworkFabricResolver(nd_module=nd, fabric_name="fab1")

    enriched = resolver._enrich_with_manage_fabric_details({"fabricName": "fab1", "fabricType": "VXLAN"})

    assert enriched["networkType"] == "vxlanIbgp"
    assert [call["path"] for call in nd.calls] == ["/api/v1/manage/fabrics/fab1"]


def test_network_fabric_resolver_00020_mcfg_enrichment_fetches_members_with_cluster_name():
    nd = _ND()
    resolver = NetworkFabricResolver(nd_module=nd, fabric_name="mfd1")

    enriched = resolver._enrich_with_manage_fabric_details({"fabricName": "mfd1", "fabricType": "MFD", "clusterName": "cluster1"})

    assert enriched["networkType"] == "vxlanEbgp"
    assert enriched["manageFabricMembers"] == [{"fabricName": "child1", "clusterName": "cluster2", "fabricState": "member"}]
    assert [call["path"] for call in nd.calls] == [
        "/api/v1/manage/fabrics/mfd1?clusterName=cluster1",
        "/api/v1/manage/fabrics/mfd1/members?clusterName=cluster1",
    ]
