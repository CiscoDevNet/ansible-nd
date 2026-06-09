# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for nd_manage_vrf_lite merge/payload/config-actions behavior."""

from __future__ import absolute_import, annotations, division, print_function

import json

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions import (
    build_attach_payload_for_entry,
    build_detach_payload_for_entry,
    _post_attachment_payload,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    get_config_actions,
    get_runtime_warnings,
    request_with_verify_settings,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.deploy import (
    _needs_deployment,
    _target_vrfs_for_deploy,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query import (
    _query_vrf_attachments,
    query_vrf_lite_state,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_payloads import (
    build_vrf_lite_extension_values,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_endpoints import (
    VrfLiteEndpoints,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation import (
    validate_vrf_lite_write_guardrails,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.exceptions import (
    VrfLiteResourceError,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.config_transform import (
    explode_playbook_to_entries,
    group_attachment_entries_to_vrfs,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrf_lite.vrf_lite_attachment_entry import (
    VrfLiteAttachmentEntry,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrf_lite.vrf_lite_model import (
    VrfLiteModel,
    VrfLitePlaybookConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite import (
    ManageVrfLiteOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


class _DummyModule:
    def __init__(self, params):
        self.params = params
        self._debug = False
        self.check_mode = bool(params.get("check_mode", False))


class _DummyWarnModule(_DummyModule):
    def __init__(self, params):
        super().__init__(params)
        self.warnings = []

    def warn(self, msg):
        self.warnings.append(msg)


def _vrf_lite_orchestrator(module):
    sender = Sender()
    sender.ansible_module = module
    rest_send = RestSend(
        {
            "check_mode": module.check_mode,
            "state": module.params.get("state"),
        }
    )
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    return ManageVrfLiteOrchestrator(rest_send=rest_send)


def test_manage_vrf_lite_00050_model_exposes_module_argspec():
    assert VrfLiteModel.get_argument_spec() == VrfLitePlaybookConfigModel.get_argument_spec()


def test_manage_vrf_lite_00075_orchestrator_prepares_runtime_params():
    module = _DummyModule(
        {
            "fabric_name": "F1",
            "state": "merged",
            "config_actions": {"save": True, "deploy": False, "type": "global"},
            "verify": {"enabled": True, "retries": 2, "timeout": 9},
        }
    )
    module_config = VrfLitePlaybookConfigModel.model_validate(
        {
            "fabric_name": "F1",
            "state": "merged",
            "config": [{"vrf_name": "BLUE", "vlan_id": 500}],
        },
        by_alias=True,
        by_name=True,
    )

    ManageVrfLiteOrchestrator.prepare_module_params(module, module_config)

    assert module.params["config"] == [{"vrf_name": "BLUE", "vlan_id": 500}]
    assert module.params["config_actions"] == {"save": True, "deploy": False, "type": "global"}
    assert module.params["verify"] == {"enabled": True, "retries": 2, "timeout": 9}
    assert module.params["_changed_vrfs"] == []
    assert module.params["_gather_filter_config"] == []


def test_manage_vrf_lite_00080_query_reuses_cached_gathered_have(monkeypatch):
    cached_have = [{"vrf_name": "BLUE", "vlan_id": 500, "attach": []}]
    module = _DummyModule({"state": "gathered", "fabric_name": "FABRIC1", "_have": cached_have, "_have_loaded": True})

    def _fail_query(**kwargs):
        del kwargs
        pytest.fail("gathered query should reuse the state machine query result")

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite.query_vrf_lite_state",
        _fail_query,
    )

    assert _vrf_lite_orchestrator(module)._query_current_state() == cached_have


def test_manage_vrf_lite_00100_merge_preserves_unmentioned_switch_and_interface_data():
    have = VrfLiteModel.from_config(
        {
            "vrf_name": "BLUE",
            "vlan_id": 500,
            "attach": [
                {
                    "ip_address": "10.0.0.1",
                    "import_evpn_rt": "100:1",
                    "vrf_lite": [
                        {
                            "interface": "Ethernet1/10",
                            "dot1q": 100,
                            "ipv4_addr": "192.0.2.2/30",
                            "neighbor_ipv4": "192.0.2.1",
                        },
                        {
                            "interface": "Ethernet1/11",
                            "dot1q": 101,
                            "ipv4_addr": "192.0.2.6/30",
                            "neighbor_ipv4": "192.0.2.5",
                        },
                    ],
                },
                {
                    "ip_address": "10.0.0.2",
                    "vrf_lite": [
                        {
                            "interface": "Ethernet1/12",
                            "dot1q": 102,
                            "ipv4_addr": "192.0.2.10/30",
                            "neighbor_ipv4": "192.0.2.9",
                        }
                    ],
                },
            ],
        }
    )

    want = VrfLiteModel.from_config(
        {
            "vrf_name": "BLUE",
            "attach": [
                {
                    "ip_address": "10.0.0.1",
                    "vrf_lite": [
                        {
                            "interface": "Ethernet1/10",
                            "neighbor_ipv4": "192.0.2.9",
                        }
                    ],
                }
            ],
        }
    )

    merged = have.merge(want)

    assert merged.attach is not None
    assert len(merged.attach) == 2

    first_attach = {item.ip_address: item for item in merged.attach}["10.0.0.1"]
    assert first_attach.vrf_lite is not None

    merged_lite_map = {item.interface.lower(): item for item in first_attach.vrf_lite}
    assert set(merged_lite_map.keys()) == {"ethernet1/10", "ethernet1/11"}

    # Updated field from incoming payload
    assert merged_lite_map["ethernet1/10"].neighbor_ipv4 == "192.0.2.9"
    # Preserved field from existing payload
    assert merged_lite_map["ethernet1/10"].dot1q == 100
    # Preserved untouched interface
    assert merged_lite_map["ethernet1/11"].dot1q == 101

    # Preserved second switch attachment (not in incoming payload)
    assert {item.ip_address for item in merged.attach} == {"10.0.0.1", "10.0.0.2"}


def test_manage_vrf_lite_00200_extension_values_preserve_non_vrf_lite_keys():
    existing_outer = {
        "VRF_LITE_CONN": json.dumps({"VRF_LITE_CONN": [{"IF_NAME": "Ethernet1/1"}]}, separators=(",", ":")),
        "MULTISITE_CONN": json.dumps({"MULTISITE_CONN": [{"site": "A"}]}, separators=(",", ":")),
        "CUSTOM_EXTENSION": "keep-me",
    }

    rendered = build_vrf_lite_extension_values(
        vrf_lite_items=[
            {
                "interface": "Ethernet1/20",
                "dot1q": 500,
                "ipv4_addr": "10.10.10.2/30",
                "neighbor_ipv4": "10.10.10.1",
            }
        ],
        existing_extension_values=json.dumps(existing_outer, separators=(",", ":")),
    )

    outer = json.loads(rendered)
    assert outer["MULTISITE_CONN"] == existing_outer["MULTISITE_CONN"]
    assert outer["CUSTOM_EXTENSION"] == "keep-me"

    vrf_lite_inner = json.loads(outer["VRF_LITE_CONN"])
    rows = vrf_lite_inner.get("VRF_LITE_CONN") or []
    assert len(rows) == 1
    assert rows[0]["IF_NAME"] == "Ethernet1/20"
    assert rows[0]["DOT1Q_ID"] == "500"


def test_manage_vrf_lite_00300_extension_values_clear_only_vrf_lite_section():
    existing_outer = {
        "VRF_LITE_CONN": json.dumps({"VRF_LITE_CONN": [{"IF_NAME": "Ethernet1/1"}]}, separators=(",", ":")),
        "MULTISITE_CONN": json.dumps({"MULTISITE_CONN": [{"site": "A"}]}, separators=(",", ":")),
        "OTHER": "preserve",
    }

    rendered = build_vrf_lite_extension_values(
        vrf_lite_items=[],
        existing_extension_values=json.dumps(existing_outer, separators=(",", ":")),
    )

    outer = json.loads(rendered)
    assert outer["MULTISITE_CONN"] == existing_outer["MULTISITE_CONN"]
    assert outer["OTHER"] == "preserve"

    vrf_lite_inner = json.loads(outer["VRF_LITE_CONN"])
    assert vrf_lite_inner == {"VRF_LITE_CONN": []}

    # No pre-existing extension block + empty input should stay empty for detach payloads.
    assert build_vrf_lite_extension_values(vrf_lite_items=[], existing_extension_values=None) == ""


def test_manage_vrf_lite_00325_extension_values_does_not_mutate_existing_dict():
    existing_outer = {
        "VRF_LITE_CONN": json.dumps({"VRF_LITE_CONN": [{"IF_NAME": "Ethernet1/1"}]}, separators=(",", ":")),
        "MULTISITE_CONN": json.dumps({"MULTISITE_CONN": [{"site": "A"}]}, separators=(",", ":")),
    }
    original = dict(existing_outer)

    rendered = build_vrf_lite_extension_values(
        vrf_lite_items=[],
        existing_extension_values=existing_outer,
    )

    assert existing_outer == original
    assert json.loads(json.loads(rendered)["VRF_LITE_CONN"]) == {"VRF_LITE_CONN": []}


def test_manage_vrf_lite_00400_config_actions_ignore_legacy_top_level_deploy():
    module_with_legacy_field_only = _DummyModule({"deploy": False})
    actions = get_config_actions(module_with_legacy_field_only)
    assert actions == {"save": True, "deploy": True, "type": "switch"}
    assert get_config_actions({"deploy": False}) == {"save": True, "deploy": True, "type": "switch"}

    module_with_config_actions = _DummyModule(
        {
            "deploy": False,
            "config_actions": {
                "save": True,
                "deploy": False,
                "type": "global",
            },
        }
    )

    configured_actions = get_config_actions(module_with_config_actions)
    assert configured_actions == {"save": True, "deploy": False, "type": "global"}


def test_manage_vrf_lite_00475_query_ignores_detached_attachment_rows(monkeypatch):
    module = _DummyModule({})

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_fabric_switches",
        lambda _nd_v2, _fabric_name, _timeout: {"SN1": "10.0.0.1"},
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_vrfs",
        lambda _nd_v2, _fabric_name, _timeout: [
            {
                "vrfName": "BLUE",
                "vrfTemplateConfig": '{"vrfVlanId":500}',
            }
        ],
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_vrf_attachments",
        lambda **_kwargs: [
            {
                "vrfName": "BLUE",
                "lanAttachList": [
                    {
                        "serialNumber": "SN1",
                        "isLanAttached": False,
                        "vlanId": 500,
                    }
                ],
            }
        ],
    )

    result = query_vrf_lite_state(module=module, fabric_name="FABRIC1", filter_vrfs={"BLUE"})

    assert result == [{"vrf_name": "BLUE", "vlan_id": 500, "deploy": False, "attach": []}]
    assert module.params["_raw_vrf_attachment_map"] == {}


def test_manage_vrf_lite_00480_query_ignores_base_vrf_attachments_without_vrf_lite(monkeypatch):
    module = _DummyModule({})

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_fabric_switches",
        lambda _nd_v2, _fabric_name, _timeout: {"SN1": "10.0.0.1"},
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_vrfs",
        lambda _nd_v2, _fabric_name, _timeout: [
            {
                "vrfName": "BLUE",
                "vrfTemplateConfig": '{"vrfVlanId":500}',
            }
        ],
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_vrf_attachments",
        lambda **_kwargs: [
            {
                "vrfName": "BLUE",
                "lanAttachList": [
                    {
                        "serialNumber": "SN1",
                        "isLanAttached": True,
                        "lanAttachState": "DEPLOYED",
                        "vlanId": 500,
                        "extensionValues": "",
                        "instanceValues": "",
                    }
                ],
            }
        ],
    )

    result = query_vrf_lite_state(module=module, fabric_name="FABRIC1", filter_vrfs={"BLUE"})

    assert result == [{"vrf_name": "BLUE", "vlan_id": 500, "deploy": False, "attach": []}]
    assert module.params["_raw_vrf_attachment_map"] == {
        "BLUE": {
            "SN1": {
                "extension_values": "",
                "instance_values": "",
                "vlan": 500,
            }
        }
    }


def test_manage_vrf_lite_00481_query_enriches_pending_attachment_from_switch_details(monkeypatch):
    module = _DummyModule({})
    extension_values = json.dumps(
        {
            "VRF_LITE_CONN": json.dumps(
                {
                    "VRF_LITE_CONN": [
                        {
                            "IF_NAME": "Ethernet1/2",
                            "DOT1Q_ID": "2",
                            "IP_MASK": "10.33.0.2/24",
                            "NEIGHBOR_IP": "10.33.0.1",
                            "PEER_VRF_NAME": "GREEN",
                            "VRF_LITE_JYTHON_TEMPLATE": "Ext_VRF_Lite_Jython",
                        }
                    ]
                },
                separators=(",", ":"),
            ),
            "MULTISITE_CONN": json.dumps({"MULTISITE_CONN": []}, separators=(",", ":")),
        },
        separators=(",", ":"),
    )

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_fabric_switches",
        lambda _nd_v2, _fabric_name, _timeout: {"SN1": "10.0.0.1"},
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_vrfs",
        lambda _nd_v2, _fabric_name, _timeout: [
            {
                "vrfName": "BLUE",
                "vrfTemplateConfig": '{"vrfVlanId":500}',
            }
        ],
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_vrf_attachments",
        lambda **_kwargs: [
            {
                "vrfName": "BLUE",
                "lanAttachList": [
                    {
                        "serialNumber": "SN1",
                        "isLanAttached": False,
                        "lanAttachState": "PENDING",
                        "vlanId": 500,
                    }
                ],
            }
        ],
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_vrf_switch_details",
        lambda **_kwargs: {
            "SN1": {
                "serialNumber": "SN1",
                "extensionValues": extension_values,
                "instanceValues": "",
                "islanAttached": False,
                "lanAttachedState": "PENDING",
                "vlan": 2,
            }
        },
    )

    result = query_vrf_lite_state(module=module, fabric_name="FABRIC1", filter_vrfs={"BLUE"})

    assert result == [
        {
            "vrf_name": "BLUE",
            "vlan_id": 500,
            "deploy": False,
            "attach": [
                {
                    "ip_address": "10.0.0.1",
                    "deploy": False,
                    "import_evpn_rt": "",
                    "export_evpn_rt": "",
                    "vrf_lite": [
                        {
                            "interface": "Ethernet1/2",
                            "dot1q": 2,
                            "ipv4_addr": "10.33.0.2/24",
                            "neighbor_ipv4": "10.33.0.1",
                            "peer_vrf": "GREEN",
                        }
                    ],
                }
            ],
        }
    ]
    assert module.params["_raw_vrf_attachment_map"]["BLUE"]["SN1"]["extension_values"] == extension_values
    assert module.params["_raw_vrf_attachment_map"]["BLUE"]["SN1"]["vlan"] == 2


def test_manage_vrf_lite_00490_deploy_needed_when_state_machine_changed_without_changed_vrf_marker():
    module = _DummyModule({})

    assert _needs_deployment({"changed": True}, module) is True


def test_manage_vrf_lite_00491_deploy_targets_honor_vrf_and_attachment_intent():
    module = _DummyModule(
        {
            "config": [
                {
                    "vrf_name": "BLUE",
                    "attach": [{"ip_address": "10.0.0.1", "deploy": False}],
                },
                {
                    "vrf_name": "GREEN",
                    "attach": [
                        {"ip_address": "10.0.0.2", "deploy": False},
                        {"ip_address": "10.0.0.3"},
                    ],
                },
                {
                    "vrf_name": "RED",
                    "deploy": False,
                    "attach": [{"ip_address": "10.0.0.4", "deploy": True}],
                },
                {
                    "vrf_name": "YELLOW",
                    "deploy": True,
                    "attach": [{"ip_address": "10.0.0.5", "deploy": False}],
                },
            ]
        }
    )

    assert _target_vrfs_for_deploy(module) == ["GREEN", "YELLOW"]


def test_manage_vrf_lite_00492_deploy_filters_changed_vrfs_by_deploy_intent():
    module = _DummyModule(
        {
            "check_mode": True,
            "fabric_name": "FABRIC1",
            "_changed_vrfs": ["BLUE", "GREEN", "RED"],
            "config_actions": {"save": True, "deploy": True, "type": "switch"},
            "config": [
                {"vrf_name": "BLUE", "attach": [{"ip_address": "10.0.0.1", "deploy": False}]},
                {"vrf_name": "GREEN", "attach": [{"ip_address": "10.0.0.2"}]},
                {"vrf_name": "RED", "deploy": False, "attach": [{"ip_address": "10.0.0.3"}]},
            ],
        }
    )

    result = _vrf_lite_orchestrator(module)._execute_config_actions(result={"changed": True})

    assert result["target_vrfs"] == ["GREEN"]
    assert result["planned_actions"] == [
        "POST {0}".format(VrfLiteEndpoints.config_save("FABRIC1")),
        "POST {0} vrfNames=GREEN".format(VrfLiteEndpoints.vrf_deployments("FABRIC1")),
    ]


def test_manage_vrf_lite_00493_attachment_deploy_false_does_not_suppress_attachment_payload():
    class _FakeNDModule:
        def request(self, path, verb, payload):
            del path, verb, payload
            pytest.fail("dot1q reservation should not be called when dot1q is provided")

    existing_instance_values = (
        '{"loopbackIpV6Address":"","loopbackId":"","switchRouteTargetImportEvpn":"",'
        '"loopbackIpAddress":"","deviceSupportL3VniNoVlan":"false","switchRouteTargetExportEvpn":""}'
    )
    module = _DummyModule(
        {
            "fabric_name": "FABRIC1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_raw_vrf_attachment_map": {
                "BLUE": {
                    "SN1": {
                        "instance_values": existing_instance_values,
                    }
                }
            },
        }
    )
    entry = VrfLiteAttachmentEntry.from_config(
        {
            "vrf_name": "BLUE",
            "switch_ip": "10.0.0.1",
            "vlan_id": 500,
            "deploy": False,
            "extensions": [{"interface": "Ethernet1/10", "dot1q": 123}],
        }
    )

    payload = build_attach_payload_for_entry(
        module=module,
        nd_v2=_FakeNDModule(),
        entry=entry,
    )

    assert payload["serialNumber"] == "SN1"
    assert payload["vlan"] == 500
    assert payload["deployment"] is True
    assert json.loads(payload["instanceValues"])["deviceSupportL3VniNoVlan"] == "false"


def test_manage_vrf_lite_00494_delete_builds_single_attachment_clear_payload():
    extension_values = build_vrf_lite_extension_values(
        [{"interface": "Ethernet1/11", "dot1q": 222, "ipv4_addr": "10.33.0.2/24"}],
    )
    instance_values = (
        '{"loopbackIpV6Address":"","loopbackId":"","switchRouteTargetImportEvpn":"",'
        '"loopbackIpAddress":"","deviceSupportL3VniNoVlan":"false","switchRouteTargetExportEvpn":""}'
    )
    module = _DummyModule(
        {
            "fabric_name": "FABRIC1",
            "state": "deleted",
            "config": [{"vrf_name": "BLUE", "attach": [{"ip_address": "10.0.0.2"}]}],
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1", "10.0.0.2": "SN2"},
            "_raw_vrf_attachment_map": {
                "BLUE": {
                    "SN1": {"vlan": 111},
                    "SN2": {
                        "vlan": 222,
                        "extension_values": extension_values,
                        "instance_values": instance_values,
                    },
                }
            },
        }
    )
    entry = VrfLiteAttachmentEntry.from_config(
        {
            "vrf_name": "BLUE",
            "switch_ip": "10.0.0.2",
            "vlan_id": 500,
        }
    )

    payload = build_detach_payload_for_entry(module, entry)

    assert payload["serialNumber"] == "SN2"
    assert payload["vlan"] == 500
    assert payload["deployment"] is True
    assert payload["isAttached"] is True
    assert payload["instanceValues"] == instance_values
    clear_outer = json.loads(payload["extensionValues"])
    assert json.loads(clear_outer["VRF_LITE_CONN"]) == {"VRF_LITE_CONN": []}


def test_manage_vrf_lite_00495_delete_query_filters_vrfs_without_managed_attachments(monkeypatch):
    module = _DummyModule({"state": "deleted", "fabric_name": "FABRIC1", "config": []})

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite.query_vrf_lite_state",
        lambda module, fabric_name, filter_vrfs=None, flat=True: [
            {"vrf_name": "BLUE", "switch_ip": "SN1", "vlan_id": 500},
        ],
    )

    have = _vrf_lite_orchestrator(module)._query_current_state()

    assert have == [{"vrf_name": "BLUE", "switch_ip": "SN1", "vlan_id": 500}]
    assert module.params["_have"] == have


def test_manage_vrf_lite_00495a_deleted_vrf_without_attach_expands_to_current_entries():
    module = _DummyModule(
        {
            "state": "deleted",
            "fabric_name": "FABRIC1",
            "_warnings": [],
        }
    )
    current = [
        {"vrf_name": "BLUE", "switch_ip": "SN1", "vlan_id": 500},
        {"vrf_name": "GREEN", "switch_ip": "SN2", "vlan_id": 501},
    ]

    result = explode_playbook_to_entries([{"vrf_name": "BLUE"}], module=module, state="deleted", current_entries=current)

    assert result == [{"vrf_name": "BLUE", "switch_ip": "SN1", "vlan_id": 500}]


def test_manage_vrf_lite_00495aa_public_grouping_preserves_scoped_empty_vrf():
    module = _DummyModule({"_vrf_lite_vrf_vlan_map": {"BLUE": 500}})

    result = group_attachment_entries_to_vrfs([], module=module, include_vrfs=["BLUE"])

    assert result == [{"vrf_name": "BLUE", "attach": [], "vlan_id": 500}]


def test_manage_vrf_lite_00495aaa_public_grouping_drops_unknown_scoped_vrf():
    module = _DummyModule({"_known_vrfs": ["BLUE"], "_vrf_lite_vrf_vlan_map": {"BLUE": 500}})

    result = group_attachment_entries_to_vrfs([], module=module, include_vrfs=["MISSING"])

    assert result == []


def test_manage_vrf_lite_00495ab_deleted_public_output_preserves_empty_after_scope():
    module = _DummyModule(
        {
            "state": "deleted",
            "_vrf_lite_nested_config": [{"vrf_name": "BLUE"}],
            "_vrf_lite_vrf_vlan_map": {"BLUE": 500},
        }
    )
    orchestrator = _vrf_lite_orchestrator(module)

    result = orchestrator.format_public_output({"before": [], "after": [], "current": [], "diff": []})

    assert result["after"] == [{"vrf_name": "BLUE", "attach": [], "vlan_id": 500}]
    assert result["current"] == [{"vrf_name": "BLUE", "attach": [], "vlan_id": 500}]


def test_manage_vrf_lite_00495b_refresh_is_skipped_when_verify_disabled(monkeypatch):
    refreshed = [{"vrf_name": "BLUE", "attach": [{"ip_address": "10.0.0.1"}]}]
    module = _DummyModule(
        {
            "state": "deleted",
            "fabric_name": "FABRIC1",
            "verify": {"enabled": False},
        }
    )
    orchestrator = _vrf_lite_orchestrator(module)

    monkeypatch.setattr(orchestrator, "_query_current_state", lambda: refreshed)

    result = orchestrator.refresh_verified_state({"changed": True, "after": [], "current": []})

    assert result["after"] == []
    assert result["current"] == []


def test_manage_vrf_lite_00495c_delete_unknown_attachment_warns_during_explode():
    module = _DummyModule(
        {
            "fabric_name": "FABRIC1",
            "state": "deleted",
            "config": [{"vrf_name": "BLUE", "attach": [{"ip_address": "10.0.0.99"}]}],
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1", "10.0.0.99": "SN99"},
            "_warnings": [],
        }
    )
    current = [{"vrf_name": "BLUE", "switch_ip": "SN1", "vlan_id": 500}]

    result = explode_playbook_to_entries(module.params["config"], module=module, state="deleted", current_entries=current)

    assert result == [{"vrf_name": "BLUE", "switch_ip": "SN99"}]
    assert any("No matching VRF Lite attachment" in warning for warning in module.params["_warnings"])


def test_manage_vrf_lite_00495d_query_all_prepares_state_machine_config(monkeypatch):
    module = _DummyModule(
        {
            "fabric_name": "FABRIC1",
            "state": "deleted",
            "_vrf_lite_requested_state": "deleted",
            "_vrf_lite_nested_config": [{"vrf_name": "BLUE"}],
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_warnings": [],
        }
    )
    current = [{"vrf_name": "BLUE", "switch_ip": "SN1", "vlan_id": 500}]
    orchestrator = _vrf_lite_orchestrator(module)

    monkeypatch.setattr(orchestrator, "_query_current_state", lambda flat=True: current)

    assert orchestrator.query_all() == current
    assert module.params["config"] == current


def test_manage_vrf_lite_00496_verify_retry_policy_is_applied_to_reads():
    class _FakeRestSend:
        def __init__(self):
            self.timeout = None
            self.saved = 0
            self.restored = 0
            self.timeouts = []

        def save_settings(self):
            self.saved += 1

        def restore_settings(self):
            self.restored += 1
            self.timeouts.append(self.timeout)

    class _FakeNDModule:
        def __init__(self):
            self.calls = 0
            self.rest_send = _FakeRestSend()

        def _get_rest_send(self):
            return self.rest_send

        def request(self, path, verb):
            assert path == "/read"
            assert verb == HttpVerbEnum.GET
            self.calls += 1
            if self.calls < 3:
                raise RuntimeError("controller not ready")
            return {"ok": True}

    module = _DummyModule({"verify": {"retries": 3, "timeout": 7}})
    nd_v2 = _FakeNDModule()

    result = request_with_verify_settings(module, nd_v2, "/read", HttpVerbEnum.GET)

    assert result == {"ok": True}
    assert nd_v2.calls == 3
    assert nd_v2.rest_send.saved == 3
    assert nd_v2.rest_send.restored == 3
    assert nd_v2.rest_send.timeouts == [7, 7, 7]


def test_manage_vrf_lite_00500_guardrails_warn_non_border_role_without_support_flag(monkeypatch):
    module = _DummyWarnModule(
        {
            "fabric_name": "F1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_fabric_switch_inventory": {},
        }
    )
    model = VrfLiteModel.from_config(
        {
            "vrf_name": "BLUE",
            "attach": [
                {
                    "ip_address": "10.0.0.1",
                    "vrf_lite": [
                        {
                            "interface": "Ethernet1/10",
                            "neighbor_ipv4": "192.0.2.9",
                        }
                    ],
                }
            ],
        }
    )

    def _inventory(_module, _fabric_name):
        return {"SN1": {"role": "leaf", "ip_address": "10.0.0.1", "raw": {}}}

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._load_switch_inventory",
        _inventory,
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._query_vrf_lite_support",
        lambda _module, _fabric_name, _vrf_name, _serial_number: None,
    )

    validate_vrf_lite_write_guardrails(module=module, model_instance=model)

    warnings = get_runtime_warnings(module.params)
    assert any("Proceeding with controller-side validation" in warning for warning in warnings)


def test_manage_vrf_lite_00550_guardrails_allow_external_connectivity_leaf(monkeypatch):
    module = _DummyWarnModule(
        {
            "fabric_name": "F1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_fabric_switch_inventory": {},
        }
    )
    model = VrfLiteModel.from_config(
        {
            "vrf_name": "BLUE",
            "attach": [
                {
                    "ip_address": "10.0.0.1",
                    "vrf_lite": [
                        {
                            "interface": "Ethernet1/10",
                            "neighbor_ipv4": "192.0.2.9",
                        }
                    ],
                }
            ],
        }
    )

    def _inventory(_module, _fabric_name):
        return {
            "SN1": {
                "role": "leaf",
                "fabric_type": "externalConnectivity",
                "ip_address": "10.0.0.1",
                "raw": {},
            }
        }

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._load_switch_inventory",
        _inventory,
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._query_vrf_lite_support",
        lambda _module, _fabric_name, _vrf_name, _serial_number: True,
    )

    validate_vrf_lite_write_guardrails(module=module, model_instance=model)


def test_manage_vrf_lite_00600_guardrails_reject_unsupported_switch(monkeypatch):
    module = _DummyWarnModule(
        {
            "fabric_name": "F1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_fabric_switch_inventory": {},
        }
    )
    model = VrfLiteModel.from_config(
        {
            "vrf_name": "BLUE",
            "attach": [
                {
                    "ip_address": "10.0.0.1",
                    "vrf_lite": [
                        {
                            "interface": "Ethernet1/10",
                            "neighbor_ipv4": "192.0.2.9",
                        }
                    ],
                }
            ],
        }
    )

    def _inventory(_module, _fabric_name):
        return {"SN1": {"role": "border", "ip_address": "10.0.0.1", "raw": {}}}

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._load_switch_inventory",
        _inventory,
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._query_vrf_lite_support",
        lambda _module, _fabric_name, _vrf_name, _serial_number: False,
    )

    with pytest.raises(VrfLiteResourceError, match="does not report VRF Lite support"):
        validate_vrf_lite_write_guardrails(module=module, model_instance=model)


def test_manage_vrf_lite_00700_guardrails_collect_warnings_without_module_warn(monkeypatch):
    module = _DummyWarnModule(
        {
            "fabric_name": "F1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_fabric_switch_inventory": {},
            "_warnings": [],
        }
    )
    model = VrfLiteModel.from_config(
        {
            "vrf_name": "BLUE",
            "attach": [
                {
                    "ip_address": "10.0.0.1",
                    "vrf_lite": [
                        {
                            "interface": "Ethernet1/10",
                            "neighbor_ipv4": "192.0.2.9",
                        }
                    ],
                }
            ],
        }
    )

    def _inventory(_module, _fabric_name):
        return {"SN1": {"role": "", "ip_address": "10.0.0.1", "raw": {}}}

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._load_switch_inventory",
        _inventory,
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._query_vrf_lite_support",
        lambda _module, _fabric_name, _vrf_name, _serial_number: (_x for _x in ()).throw(Exception("boom")),
    )

    validate_vrf_lite_write_guardrails(module=module, model_instance=model)

    warnings = get_runtime_warnings(module.params)
    assert any("Unable to determine switch role" in warning for warning in warnings)
    assert any("Unable to query VRF Lite support" in warning for warning in warnings)
    # Ensure validator no longer depends on direct Ansible warning side-effects.
    assert module.warnings == []


def test_manage_vrf_lite_00800_attachment_post_uses_manage_attachment_payload():
    class _FakeNDModule:
        def __init__(self):
            self.calls = []

        def request(self, path, verb, payload):
            self.calls.append((path, verb, payload))
            return {"ok": True}

    nd_v2 = _FakeNDModule()
    lan_attach_list = [{"serialNumber": "SN1", "isAttached": True}]

    result = _post_attachment_payload(
        nd_v2=nd_v2,
        fabric_name="FABRIC1",
        vrf_name="BLUE",
        lan_attach_list=lan_attach_list,
    )

    assert result == {"ok": True}
    assert nd_v2.calls == [
        (
            "/api/v1/manage/fabrics/FABRIC1/vrfAttachments",
            HttpVerbEnum.POST,
            {"attachments": lan_attach_list},
        )
    ]


def test_manage_vrf_lite_00850_attachment_post_rejects_controller_failed_body():
    class _FakeNDModule:
        def request(self, path, verb, payload):
            del path, verb, payload
            return {
                "BLUE-[SN1/leaf1]": "Attach Response : Failed : VPC details not found for Peer Serial no: SN2",
            }

    with pytest.raises(VrfLiteResourceError, match="attachment API reported failure"):
        _post_attachment_payload(
            nd_v2=_FakeNDModule(),
            fabric_name="FABRIC1",
            vrf_name="BLUE",
            lan_attach_list=[{"serialNumber": "SN1"}],
        )
