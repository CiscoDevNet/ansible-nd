# -*- coding: utf-8 -*-

"""Unit tests for VRF fabric resolver endpoint wiring."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.fabric_resolver import (
    FabricResolverRequestError,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_fabric_resolver import (
    VrfFabricResolver,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


class _RestSend:
    version = "3.2.1"

    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.path = None
        self.verb = None
        self.return_code = 200
        self.success = True
        self.error_summary = ""
        self.response_current = {}

    def commit(self):
        method = self.verb.value if hasattr(self.verb, "value") else self.verb
        self.calls.append({"path": self.path, "method": method})
        response = self.responses.get(self.path, {})
        if isinstance(response, Exception):
            raise response
        if isinstance(response, dict) and "RETURN_CODE" in response:
            self.return_code = response.get("RETURN_CODE", 200)
            self.success = self.return_code < 400
            self.response_current = response
            self.error_summary = f"({self.return_code})"
            return
        self.return_code = 200
        self.success = True
        self.error_summary = ""
        self.response_current = {"DATA": response}


def _resolver(fabric_name, responses):
    rest_send = _RestSend(responses)
    return VrfFabricResolver(rest_send=rest_send, fabric_name=fabric_name), rest_send


def _controller_response(status: int, message: str, data: dict | None = None) -> dict:
    return {
        "RETURN_CODE": status,
        "MESSAGE": message,
        "DATA": data or {},
        "METHOD": "GET",
        "REQUEST_PATH": "https://controller.example/api/v1/manage/fabrics/fab1",
    }


def _real_rest_send_resolver(fabric_name: str, responses: list[dict], sender_exception: Exception | None = None) -> VrfFabricResolver:
    def generated_responses():
        for response in responses:
            yield response

    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(generated_responses())
    if sender_exception is not None:
        sender.raise_method = "commit"
        sender.raise_exception = sender_exception

    rest_send = RestSend({"check_mode": False, "fabric_name": fabric_name})
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    rest_send.unit_test = True
    rest_send.timeout = 1
    rest_send.send_interval = 1

    return VrfFabricResolver(rest_send=rest_send, fabric_name=fabric_name)


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (401, "Unauthorized"),
        (403, "Forbidden"),
        (500, "Internal Server Error"),
    ],
)
def test_vrf_fabric_resolver_00001_initial_manage_failure_preserves_controller_error(status, message):
    resolver = _real_rest_send_resolver(
        "fab1",
        [
            _controller_response(status, message, {"code": status, "message": "controller unavailable"}),
        ],
    )

    with pytest.raises(FabricResolverRequestError, match="controller unavailable") as exc_info:
        resolver.resolve()

    assert "GET /api/v1/manage/fabrics/fab1 failed" in str(exc_info.value)
    assert "could not be resolved from ND Manage fabric topology" not in str(exc_info.value)


def test_vrf_fabric_resolver_00002_initial_manage_transport_failure_preserves_error():
    resolver = _real_rest_send_resolver("fab1", [], sender_exception=ValueError("socket closed"))

    with pytest.raises(FabricResolverRequestError, match="socket closed") as exc_info:
        resolver.resolve()

    assert "GET /api/v1/manage/fabrics/fab1 failed before controller response" in str(exc_info.value)
    assert "could not be resolved from ND Manage fabric topology" not in str(exc_info.value)


def test_vrf_fabric_resolver_00003_initial_manage_404_uses_topology_resolution_error():
    resolver = _real_rest_send_resolver(
        "fab1",
        [
            _controller_response(404, "Not Found", {"code": 404, "message": "fabric not found"}),
            _controller_response(200, "OK", {"fabrics": []}),
        ],
    )

    with pytest.raises(ValueError, match="Fabric 'fab1' could not be resolved from ND Manage fabric topology"):
        resolver.resolve()


def test_vrf_fabric_resolver_00010_standalone_enrichment_does_not_fetch_members():
    resolver, rest_send = _resolver(
        "fab1",
        {
            "/api/v1/manage/fabrics/fab1": {"management": {"type": "vxlanIbgp"}},
        },
    )

    enriched = resolver._enrich_with_manage_fabric_details({"fabricName": "fab1", "fabricType": "VXLAN"})

    assert enriched["vrfType"] == "vxlanIbgp"
    assert [call["path"] for call in rest_send.calls] == ["/api/v1/manage/fabrics/fab1"]


def test_vrf_fabric_resolver_00020_mcfg_enrichment_fetches_members_with_cluster_name():
    resolver, rest_send = _resolver(
        "mfd1",
        {
            "/api/v1/manage/fabrics/mfd1?clusterName=cluster1": {"management": {"type": "vxlanEbgp"}},
            "/api/v1/oneManage/manage/fabrics/mfd1/members": {"fabrics": [{"name": "child1", "clusterName": "cluster2", "type": "vxlanIbgp"}]},
        },
    )

    enriched = resolver._enrich_with_manage_fabric_details({"fabricName": "mfd1", "fabricType": "MFD", "clusterName": "cluster1"})

    assert enriched["vrfType"] == "vxlanEbgp"
    assert enriched["manageFabricMembers"] == [
        {"name": "child1", "clusterName": "cluster2", "type": "vxlanIbgp", "fabricName": "child1", "fabricState": "member", "fabricType": "vxlanIbgp"}
    ]
    assert [call["path"] for call in rest_send.calls] == [
        "/api/v1/manage/fabrics/mfd1?clusterName=cluster1",
        "/api/v1/oneManage/manage/fabrics/mfd1/members",
    ]


def test_vrf_fabric_resolver_00030_mcfg_detection_uses_schema_backed_onemanage_resource_path():
    resolver, rest_send = _resolver(
        "MCFG_C",
        {
            "/api/v1/manage/fabrics/MCFG_C": {"name": "MCFG_C", "category": "fabricGroup", "management": {"type": "vxlan"}},
            "/api/v1/oneManage/manage/fabrics/MCFG_C/vrfs?max=1": {"vrfs": [], "meta": {"total": 0, "remaining": 0}},
            "/api/v1/oneManage/manage/fabrics/MCFG_C/members": {"fabrics": [{"name": "nacfab", "clusterName": "ND42-REL", "type": "vxlanIbgp"}]},
        },
    )

    fabric_type, fabric_data = resolver._resolve_fabric_type()

    assert fabric_type == "multicluster_parent"
    assert fabric_data == {
        "fabricName": "MCFG_C",
        "fabricType": "MFD",
        "fabricState": "active",
        "members": [
            {
                "name": "nacfab",
                "clusterName": "ND42-REL",
                "type": "vxlanIbgp",
                "fabricName": "nacfab",
                "fabricState": "member",
                "fabricType": "vxlanIbgp",
            }
        ],
    }
    assert [call["path"] for call in rest_send.calls] == [
        "/api/v1/manage/fabrics/MCFG_C",
        "/api/v1/oneManage/manage/fabrics/MCFG_C/vrfs?max=1",
        "/api/v1/oneManage/manage/fabrics/MCFG_C/members",
    ]


def test_vrf_fabric_resolver_00040_standalone_detection_does_not_probe_onemanage():
    resolver, rest_send = _resolver(
        "fab1",
        {
            "/api/v1/manage/fabrics/fab1": {"management": {"type": "vxlanIbgp"}},
            "/api/v1/manage/fabrics?category=fabricGroup&max=10000": {"fabrics": []},
        },
    )

    fabric_type, fabric_data = resolver._resolve_fabric_type()

    assert fabric_type == "standalone"
    assert fabric_data == {"fabricName": "fab1", "fabricType": None, "fabricState": "active"}
    assert [call["path"] for call in rest_send.calls] == [
        "/api/v1/manage/fabrics/fab1",
        "/api/v1/manage/fabrics?category=fabricGroup&max=10000",
    ]


def test_vrf_fabric_resolver_00041_resolve_reuses_manage_fabric_details_for_enrichment():
    resolver, rest_send = _resolver(
        "fab1",
        {
            "/api/v1/manage/fabrics/fab1": {"management": {"type": "vxlanIbgp"}},
            "/api/v1/manage/fabrics?category=fabricGroup&max=10000": {"fabrics": []},
        },
    )

    strategy = resolver.resolve()

    assert strategy.fabric_type == "standalone"
    assert strategy.fabric_data["vrfType"] == "vxlanIbgp"
    assert [call["path"] for call in rest_send.calls].count("/api/v1/manage/fabrics/fab1") == 1
    assert [call["path"] for call in rest_send.calls] == [
        "/api/v1/manage/fabrics/fab1",
        "/api/v1/manage/fabrics?category=fabricGroup&max=10000",
    ]


def test_vrf_fabric_resolver_00050_msd_detection_falls_back_when_onemanage_unavailable():
    resolver, rest_send = _resolver(
        "msd_p",
        {
            "/api/v1/manage/fabrics/msd_p": {"name": "msd_p", "category": "fabricGroup", "management": {"type": "vxlan"}},
            "/api/v1/oneManage/manage/fabrics/msd_p/vrfs?max=1": {
                "RETURN_CODE": 500,
                "DATA": {"code": 500, "message": "this API is allowed only for remote user"},
            },
            "/api/v1/manage/fabrics/msd_p/members": {"fabrics": [{"name": "nacfab", "type": "VXLAN"}]},
        },
    )

    fabric_type, fabric_data = resolver._resolve_fabric_type()

    assert fabric_type == "multisite_parent"
    assert fabric_data == {
        "fabricName": "msd_p",
        "fabricType": "MSD",
        "fabricState": "active",
        "members": [
            {
                "name": "nacfab",
                "type": "VXLAN",
                "fabricName": "nacfab",
                "fabricType": "VXLAN",
                "fabricState": "member",
                "fabricParent": "msd_p",
            }
        ],
    }
    assert [call["path"] for call in rest_send.calls] == [
        "/api/v1/manage/fabrics/msd_p",
        "/api/v1/oneManage/manage/fabrics/msd_p/vrfs?max=1",
        "/api/v1/manage/fabrics/msd_p/members",
    ]


def test_vrf_fabric_resolver_00051_msd_detection_ignores_wrapped_onemanage_error_response():
    resolver, rest_send = _resolver(
        "msd_p",
        {
            "/api/v1/manage/fabrics/msd_p": {"name": "msd_p", "category": "fabricGroup", "management": {"type": "vxlan"}},
            "/api/v1/oneManage/manage/fabrics/msd_p/vrfs?max=1": {"RETURN_CODE": 400, "DATA": {"code": 400, "message": "fabric not found"}},
            "/api/v1/manage/fabrics/msd_p/members": {"fabrics": [{"name": "nacfab", "type": "VXLAN"}]},
        },
    )

    fabric_type, fabric_data = resolver._resolve_fabric_type()

    assert fabric_type == "multisite_parent"
    assert fabric_data["fabricType"] == "MSD"
    assert fabric_data["members"][0]["fabricName"] == "nacfab"
    assert [call["path"] for call in rest_send.calls] == [
        "/api/v1/manage/fabrics/msd_p",
        "/api/v1/oneManage/manage/fabrics/msd_p/vrfs?max=1",
        "/api/v1/manage/fabrics/msd_p/members",
    ]


def test_vrf_fabric_resolver_00060_mcfg_child_uses_parent_onemanage_members_cluster():
    resolver, rest_send = _resolver(
        "nacfab",
        {
            "/api/v1/manage/fabrics/nacfab": {"name": "nacfab", "category": "fabric", "management": {"type": "vxlanIbgp"}},
            "/api/v1/manage/fabrics?category=fabricGroup&max=10000": {
                "fabrics": [{"name": "MCFG_C", "category": "fabricGroup", "management": {"type": "vxlan"}}]
            },
            "/api/v1/manage/fabrics/MCFG_C/members": {"fabrics": [{"name": "nacfab", "type": "Switch_Fabric"}]},
            "/api/v1/oneManage/manage/fabrics/MCFG_C/members": {
                "fabrics": [{"name": "nacfab", "clusterName": "ND42-REL", "fabricGroupName": "MCFG_C", "type": "vxlanIbgp"}]
            },
        },
    )

    fabric_type, fabric_data = resolver._resolve_fabric_type()

    assert fabric_type == "multicluster_child"
    assert fabric_data["fabricName"] == "nacfab"
    assert fabric_data["fabricParent"] == "MCFG_C"
    assert fabric_data["clusterName"] == "ND42-REL"
    assert [call["path"] for call in rest_send.calls] == [
        "/api/v1/manage/fabrics/nacfab",
        "/api/v1/manage/fabrics?category=fabricGroup&max=10000",
        "/api/v1/manage/fabrics/MCFG_C/members",
        "/api/v1/oneManage/manage/fabrics/MCFG_C/members",
    ]


def test_vrf_fabric_resolver_00070_msd_child_falls_back_when_parent_onemanage_unavailable():
    resolver, rest_send = _resolver(
        "AK-VXLAN",
        {
            "/api/v1/manage/fabrics/AK-VXLAN": {"name": "AK-VXLAN", "category": "fabric", "management": {"type": "vxlanIbgp"}},
            "/api/v1/manage/fabrics?category=fabricGroup&max=10000": {
                "fabrics": [{"name": "msd_p", "category": "fabricGroup", "management": {"type": "vxlan"}}]
            },
            "/api/v1/manage/fabrics/msd_p/members": {"fabrics": [{"name": "AK-VXLAN", "type": "Switch_Fabric"}]},
            "/api/v1/oneManage/manage/fabrics/msd_p/members": {
                "RETURN_CODE": 500,
                "DATA": {"code": 500, "message": "this API is allowed only for remote user"},
            },
        },
    )

    fabric_type, fabric_data = resolver._resolve_fabric_type()

    assert fabric_type == "multisite_child"
    assert fabric_data == {
        "name": "AK-VXLAN",
        "type": "Switch_Fabric",
        "fabricName": "AK-VXLAN",
        "fabricType": "Switch_Fabric",
        "fabricState": "member",
        "fabricParent": "msd_p",
    }
    assert [call["path"] for call in rest_send.calls] == [
        "/api/v1/manage/fabrics/AK-VXLAN",
        "/api/v1/manage/fabrics?category=fabricGroup&max=10000",
        "/api/v1/manage/fabrics/msd_p/members",
        "/api/v1/oneManage/manage/fabrics/msd_p/members",
    ]
