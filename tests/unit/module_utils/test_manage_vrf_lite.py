# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for nd_manage_vrf_lite merge/payload/config-actions behavior."""

from __future__ import annotations

import json

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions import (
    _ensure_vrf_exists,
    _request_vrf_lite_payload,
    build_attach_payload_for_entry,
    build_detach_payload_for_entry,
    _post_attachment_payload,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    _VrfLiteListPayloadRestSend,
    get_config_actions,
    request_with_rest_send,
    request_with_verify_settings,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.deploy import (
    _needs_deployment,
    _target_vrfs_for_deploy,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query import (
    _coerce_vlan,
    _query_vrf_attachments,
    _query_vrf_switch_details,
    _resolve_vrf_vlan,
    query_vrf_lite_state,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_payloads import (
    build_vrf_lite_extension_values,
    parse_vrf_lite_extension_values,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_endpoints import (
    VrfLiteEndpoints,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation import (
    _extract_vrf_lite_prototypes,
    _vrf_lite_cache_key,
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
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
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


class _StubEntry:
    """Minimal attachment-entry stand-in for preflight validation tests."""

    def __init__(self, vrf_name, switch_ip):
        self.vrf_name = vrf_name
        self.switch_ip = switch_ip


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


def _vrf_lite_prototype(interface="Ethernet1/10", extension_values=None):
    values = {
        "PEER_VRF_NAME": "",
        "NEIGHBOR_IP": "192.0.2.1",
        "VRF_LITE_JYTHON_TEMPLATE": "Ext_VRF_Lite_Jython",
        "enableBorderExtension": "VRF_LITE",
        "AUTO_VRF_LITE_FLAG": "false",
        "IP_MASK": "192.0.2.2/31",
        "MTU": "9216",
        "NEIGHBOR_ASN": "65001",
        "IF_NAME": interface,
        "IPV6_NEIGHBOR": "",
        "IPV6_MASK": "",
        "DOT1Q_ID": "2",
        "asn": "65000",
    }
    if extension_values is not None:
        values = extension_values
    return {
        "interfaceName": interface,
        "extensionType": "VRF_LITE",
        "extensionValues": json.dumps(values) if isinstance(values, dict) else values,
    }


def _vrf_lite_switch_detail(serial_number="SN1", prototypes=None, **extra):
    detail = {
        "serialNumber": serial_number,
        "role": "border gateway",
        "extensionPrototypeValues": [_vrf_lite_prototype()] if prototypes is None else prototypes,
        "islanAttached": False,
    }
    detail.update(extra)
    return detail


def _vrf_lite_guardrail_model(interface="Ethernet1/10"):
    return VrfLiteModel.from_config(
        {
            "vrf_name": "BLUE",
            "attach": [
                {
                    "ip_address": "10.0.0.1",
                    "vrf_lite": [
                        {
                            "interface": interface,
                            "neighbor_ipv4": "192.0.2.9",
                        }
                    ],
                }
            ],
        }
    )


def _mock_guardrail_inventory(monkeypatch, role="border", fabric_type=None):
    switch_data = {
        "role": role,
        "ip_address": "10.0.0.1",
        "raw": {},
    }
    if fabric_type is not None:
        switch_data["fabric_type"] = fabric_type
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._load_switch_inventory",
        lambda _module, _fabric_name, _rest_send: {"SN1": switch_data},
    )


def test_manage_vrf_lite_00050_model_exposes_module_argspec():
    assert VrfLiteModel.get_argument_spec() == VrfLitePlaybookConfigModel.get_argument_spec()


def test_manage_vrf_lite_00060_existing_empty_vrf_passes_existence_check(monkeypatch):
    """An existing VRF with no attachment rows must not be reported missing."""
    module = _DummyModule({"fabric_name": "FABRIC1", "_known_vrfs": []})

    def _query(**kwargs):
        del kwargs
        module.params["_known_vrfs"] = ["BLUE"]
        return []

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions.query_vrf_lite_state",
        _query,
    )

    _ensure_vrf_exists(module, rest_send=object(), vrf_name="BLUE")


def test_manage_vrf_lite_00065_missing_vrf_fails_existence_check(monkeypatch):
    """A VRF absent from the refreshed authoritative inventory is rejected."""
    module = _DummyModule({"fabric_name": "FABRIC1", "_known_vrfs": []})

    def _query(**kwargs):
        del kwargs
        module.params["_known_vrfs"] = ["GREEN"]
        return []

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions.query_vrf_lite_state",
        _query,
    )

    with pytest.raises(VrfLiteResourceError, match="does not exist"):
        _ensure_vrf_exists(module, rest_send=object(), vrf_name="BLUE")


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
    assert module.params["config_actions"] == {
        "save": True,
        "deploy": False,
        "type": "global",
    }
    assert module.params["verify"] == {"enabled": True, "retries": 2, "timeout": 9}
    assert module.params["_changed_vrfs"] == []
    assert module.params["_gather_filter_config"] == []


def test_manage_vrf_lite_00080_query_reuses_cached_gathered_have(monkeypatch):
    cached_have = [{"vrf_name": "BLUE", "vlan_id": 500, "attach": []}]
    module = _DummyModule(
        {
            "state": "gathered",
            "fabric_name": "FABRIC1",
            "_have": cached_have,
            "_have_loaded": True,
        }
    )

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
    assert get_config_actions({"deploy": False}) == {
        "save": True,
        "deploy": True,
        "type": "switch",
    }

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
        lambda _module, _rest_send, _fabric_name: {"SN1": "10.0.0.1"},
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_vrfs",
        lambda _module, _rest_send, _fabric_name: [
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

    result = query_vrf_lite_state(module=module, rest_send=object(), fabric_name="FABRIC1", filter_vrfs={"BLUE"})

    assert result == [{"vrf_name": "BLUE", "vlan_id": 500, "deploy": False, "attach": []}]
    assert module.params["_raw_vrf_attachment_map"] == {}


def test_manage_vrf_lite_00480_query_ignores_base_vrf_attachments_without_vrf_lite(
    monkeypatch,
):
    module = _DummyModule({})

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_fabric_switches",
        lambda _module, _rest_send, _fabric_name: {"SN1": "10.0.0.1"},
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_vrfs",
        lambda _module, _rest_send, _fabric_name: [
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
                        "freeformConfig": "router ospf 100",
                    }
                ],
            }
        ],
    )

    result = query_vrf_lite_state(module=module, rest_send=object(), fabric_name="FABRIC1", filter_vrfs={"BLUE"})

    assert result == [{"vrf_name": "BLUE", "vlan_id": 500, "deploy": False, "attach": []}]
    assert module.params["_raw_vrf_attachment_map"] == {
        "BLUE": {
            "SN1": {
                "extension_values": "",
                "instance_values": "",
                "freeform_config": "router ospf 100",
                "vlan": 500,
            }
        }
    }


def test_manage_vrf_lite_00481_query_enriches_pending_attachment_from_switch_details(
    monkeypatch,
):
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
        lambda _module, _rest_send, _fabric_name: {"SN1": "10.0.0.1"},
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query._query_vrfs",
        lambda _module, _rest_send, _fabric_name: [
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
                "freeformConfig": "router ospf 100",
                "islanAttached": False,
                "lanAttachedState": "PENDING",
                "vlan": 2,
            }
        },
    )

    result = query_vrf_lite_state(module=module, rest_send=object(), fabric_name="FABRIC1", filter_vrfs={"BLUE"})

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
    assert module.params["_raw_vrf_attachment_map"]["BLUE"]["SN1"]["freeform_config"] == "router ospf 100"
    assert module.params["_raw_vrf_attachment_map"]["BLUE"]["SN1"]["vlan"] == 2


def test_manage_vrf_lite_00481a_attachment_query_uses_lossless_top_down_get():
    class _FakeRestSend:
        timeout = 30
        check_mode = False
        response_handler = None

        def __init__(self):
            self.path = None
            self.verb = None
            self.response_current = {}
            self.result_current = {}
            self.payload = None

        def save_settings(self):
            pass

        def restore_settings(self):
            pass

        def commit(self):
            assert self.path == VrfLiteEndpoints.vrf_attachments_query("FABRIC1", "BLUE,GREEN")
            assert self.verb == HttpVerbEnum.GET
            assert self.payload is None
            self.response_current = {
                "DATA": [
                    {
                        "vrfName": "BLUE",
                        "lanAttachList": [
                            {
                                "serialNumber": "SN1",
                                "extensionValues": '{"UNMANAGED_EXTENSION":"preserve-me"}',
                            }
                        ],
                    }
                ]
            }
            self.result_current = {"success": True}

    result = _query_vrf_attachments(
        module=_DummyModule({}),
        rest_send=_FakeRestSend(),
        fabric_name="FABRIC1",
        vrf_names=["BLUE", "GREEN"],
    )

    assert result[0]["lanAttachList"][0]["extensionValues"] == '{"UNMANAGED_EXTENSION":"preserve-me"}'


def test_manage_vrf_lite_00482_vlan_prefers_top_level_vlanid():
    """The current OpenAPI VRF object exposes the VLAN at top-level ``vlanId``."""
    vrf_object = {"vlanId": 500, "vrfTemplateConfig": '{"vrfVlanId":999}'}
    # Top-level wins even when the legacy serialized value disagrees.
    assert _resolve_vrf_vlan(vrf_object) == 500


def test_manage_vrf_lite_00483_vlan_falls_back_to_legacy_template_config():
    """Older controller shapes omit ``vlanId`` and carry the VLAN inside the
    serialized ``vrfTemplateConfig.vrfVlanId``."""
    assert _resolve_vrf_vlan({"vrfTemplateConfig": '{"vrfVlanId":777}'}) == 777
    assert _resolve_vrf_vlan({"vrfTemplateConfig": {"vrfVlanId": 888}}) == 888


def test_manage_vrf_lite_00484_vlan_top_level_unassigned_falls_back():
    """A top-level ``vlanId`` of 0 means unassigned, so fall back to the legacy value."""
    assert _resolve_vrf_vlan({"vlanId": 0, "vrfTemplateConfig": '{"vrfVlanId":123}'}) == 123


def test_manage_vrf_lite_00485_vlan_absent_resolves_to_none():
    assert _resolve_vrf_vlan({}) is None
    assert _resolve_vrf_vlan({"vrfTemplateConfig": "{}"}) is None
    assert _resolve_vrf_vlan({"vlanId": "", "vrfTemplateConfig": ""}) is None


def test_manage_vrf_lite_00486_coerce_vlan_normalizes_values():
    assert _coerce_vlan(None) is None
    assert _coerce_vlan("") is None
    assert _coerce_vlan(0) is None
    assert _coerce_vlan("500") == 500
    assert _coerce_vlan(500) == 500


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
                {
                    "vrf_name": "BLUE",
                    "attach": [{"ip_address": "10.0.0.1", "deploy": False}],
                },
                {"vrf_name": "GREEN", "attach": [{"ip_address": "10.0.0.2"}]},
                {
                    "vrf_name": "RED",
                    "deploy": False,
                    "attach": [{"ip_address": "10.0.0.3"}],
                },
            ],
        }
    )

    result = _vrf_lite_orchestrator(module)._execute_config_actions(result={"changed": True})

    assert result["target_vrfs"] == ["GREEN"]
    assert result["planned_actions"] == [
        "POST {0}".format(VrfLiteEndpoints.config_save("FABRIC1")),
        "POST {0} vrfNames=GREEN".format(VrfLiteEndpoints.vrf_deployments("FABRIC1")),
    ]


def _capture_config_action_requests(monkeypatch):
    """Patch the orchestrator transport and return a list capturing each request."""
    captured: list[dict] = []

    def _fake_request(module, rest_send, path, verb, data=None, timeout=None, force_check_mode=False):
        del module, rest_send, verb, timeout, force_check_mode
        captured.append({"path": path, "payload": data})
        return {}

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite.request_with_rest_send",
        _fake_request,
    )
    return captured


def test_manage_vrf_lite_00492a_config_save_omits_type_and_switch_scope_targets_switch_ids(
    monkeypatch,
):
    captured = _capture_config_action_requests(monkeypatch)
    module = _DummyModule(
        {
            "fabric_name": "FABRIC1",
            "_changed_vrfs": ["GREEN"],
            "_ip_to_sn_mapping": {"10.0.0.2": "SN2"},
            "config_actions": {"save": True, "deploy": True, "type": "switch"},
            "config": [{"vrf_name": "GREEN", "switch_ip": "10.0.0.2"}],
        }
    )

    _vrf_lite_orchestrator(module)._execute_config_actions(result={"changed": True})

    save_call = next(call for call in captured if call["path"] == VrfLiteEndpoints.config_save("FABRIC1"))
    deploy_call = next(call for call in captured if call["path"] == VrfLiteEndpoints.vrf_deployments("FABRIC1"))

    # Config save is a body-less fabric trigger and must not carry deploy-scope 'type'.
    assert save_call["payload"] == {}
    # Switch-scoped deploy targets only the affected switches.
    assert deploy_call["payload"] == {"vrfNames": ["GREEN"], "switchIds": ["SN2"]}


def test_manage_vrf_lite_00492b_global_scope_deploy_omits_switch_ids(monkeypatch):
    captured = _capture_config_action_requests(monkeypatch)
    module = _DummyModule(
        {
            "fabric_name": "FABRIC1",
            "_changed_vrfs": ["GREEN"],
            "_ip_to_sn_mapping": {"10.0.0.2": "SN2"},
            "config_actions": {"save": True, "deploy": True, "type": "global"},
            "config": [{"vrf_name": "GREEN", "switch_ip": "10.0.0.2"}],
        }
    )

    _vrf_lite_orchestrator(module)._execute_config_actions(result={"changed": True})

    deploy_call = next(call for call in captured if call["path"] == VrfLiteEndpoints.vrf_deployments("FABRIC1"))

    # Global-scoped deploy omits switchIds so the controller deploys fabric-wide.
    assert deploy_call["payload"] == {"vrfNames": ["GREEN"]}
    assert "switchIds" not in deploy_call["payload"]


def test_manage_vrf_lite_00492c_replaced_partial_removal_deploys_removed_switch(
    monkeypatch,
):
    """A replaced/overridden run that drops one switch must still deploy the detach on it.

    The removed attachment is gone from the retained config, so the deploy scope is
    recovered from the operation journal (_deploy_targets, which includes detaches).
    """
    captured = _capture_config_action_requests(monkeypatch)
    module = _DummyModule(
        {
            "state": "replaced",
            "fabric_name": "FABRIC1",
            "_changed_vrfs": ["GREEN"],
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1", "10.0.0.2": "SN2"},
            "config_actions": {"save": True, "deploy": True, "type": "switch"},
            # SN1 stays attached; SN2 was removed this run and is absent from config.
            "config": [{"vrf_name": "GREEN", "switch_ip": "10.0.0.1"}],
            "_deploy_targets": [{"vrf_name": "GREEN", "switch_ip": "10.0.0.2"}],
        }
    )

    _vrf_lite_orchestrator(module)._execute_config_actions(result={"changed": True})

    deploy_call = next(call for call in captured if call["path"] == VrfLiteEndpoints.vrf_deployments("FABRIC1"))
    # The removed switch (SN2) is deployed alongside the retained one so the detach lands.
    assert deploy_call["payload"] == {
        "vrfNames": ["GREEN"],
        "switchIds": ["SN1", "SN2"],
    }


def test_manage_vrf_lite_00492d_overridden_remove_all_deploys_every_removed_switch(
    monkeypatch,
):
    """Removing every attachment (empty config for the VRF) must still deploy the
    detach on all previously-attached switches under switch scope."""
    captured = _capture_config_action_requests(monkeypatch)
    module = _DummyModule(
        {
            "state": "overridden",
            "fabric_name": "FABRIC1",
            "_changed_vrfs": ["TENANT"],
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1", "10.0.0.2": "SN2"},
            "config_actions": {"save": True, "deploy": True, "type": "switch"},
            # Every TENANT attachment was removed: nothing remains in the retained config.
            "config": [],
            "_deploy_targets": [
                {"vrf_name": "TENANT", "switch_ip": "10.0.0.1"},
                {"vrf_name": "TENANT", "switch_ip": "10.0.0.2"},
            ],
        }
    )

    _vrf_lite_orchestrator(module)._execute_config_actions(result={"changed": True})

    deploy_call = next(call for call in captured if call["path"] == VrfLiteEndpoints.vrf_deployments("FABRIC1"))
    assert deploy_call["payload"] == {
        "vrfNames": ["TENANT"],
        "switchIds": ["SN1", "SN2"],
    }


def test_manage_vrf_lite_00492e_remove_all_global_scope_still_deploys_vrf(monkeypatch):
    """Remove-all under global deploy scope still deploys the VRF fabric-wide (no
    switchIds) even though the retained config is empty."""
    captured = _capture_config_action_requests(monkeypatch)
    module = _DummyModule(
        {
            "state": "replaced",
            "fabric_name": "FABRIC1",
            "_changed_vrfs": ["TENANT"],
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1", "10.0.0.2": "SN2"},
            "config_actions": {"save": True, "deploy": True, "type": "global"},
            "config": [],
            "_deploy_targets": [
                {"vrf_name": "TENANT", "switch_ip": "10.0.0.1"},
                {"vrf_name": "TENANT", "switch_ip": "10.0.0.2"},
            ],
        }
    )

    _vrf_lite_orchestrator(module)._execute_config_actions(result={"changed": True})

    deploy_call = next(call for call in captured if call["path"] == VrfLiteEndpoints.vrf_deployments("FABRIC1"))
    assert deploy_call["payload"] == {"vrfNames": ["TENANT"]}
    assert "switchIds" not in deploy_call["payload"]


def test_manage_vrf_lite_00493_attachment_deploy_false_does_not_suppress_attachment_payload():
    class _FakeNDModule:
        def request(self, path, verb, payload):
            del path, verb, payload
            pytest.fail("dot1q reservation should not be called when dot1q is provided")

    existing_instance_values = json.dumps(
        {
            "loopbackIpV6Address": "",
            "loopbackId": "",
            "switchRouteTargetImportEvpn": "65000:1",
            "evpnRouteTargetImport": "65000:2",
            "loopbackIpAddress": "",
            "deviceSupportL3VniNoVlan": "false",
            "switchRouteTargetExportEvpn": "65000:3",
            "evpnRouteTargetExport": "65000:4",
        }
    )
    module = _DummyModule(
        {
            "fabric_name": "FABRIC1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_raw_vrf_attachment_map": {
                "BLUE": {
                    "SN1": {
                        "instance_values": existing_instance_values,
                        "freeform_config": "router ospf 100",
                    }
                }
            },
            "_vrf_lite_prototype_cache": {
                _vrf_lite_cache_key("FABRIC1", "BLUE", "SN1"): {
                    "Ethernet1/10": json.loads(_vrf_lite_prototype()["extensionValues"]),
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
            "extensions": [
                {
                    "interface": "ethernet1/10",
                    "dot1q": 123,
                    "ipv4_addr": "10.33.0.2/24",
                    "neighbor_ipv4": "10.33.0.1",
                }
            ],
        }
    )

    payload = build_attach_payload_for_entry(
        module=module,
        rest_send=_FakeNDModule(),
        entry=entry,
    )

    assert payload["fabric"] == "FABRIC1"
    assert payload["serialNumber"] == "SN1"
    assert payload["vlan"] == 500
    assert payload["deployment"] is True
    assert payload["isAttached"] is True
    rendered_instance_values = json.loads(payload["instanceValues"])
    assert rendered_instance_values["deviceSupportL3VniNoVlan"] == "false"
    assert rendered_instance_values["switchRouteTargetImportEvpn"] == ""
    assert rendered_instance_values["switchRouteTargetExportEvpn"] == ""
    assert rendered_instance_values["evpnRouteTargetImport"] == ""
    assert rendered_instance_values["evpnRouteTargetExport"] == ""
    assert payload["freeformConfig"] == "router ospf 100"
    assert parse_vrf_lite_extension_values(payload["extensionValues"]) == [
        {
            "interface": "Ethernet1/10",
            "dot1q": 123,
            "ipv4_addr": "10.33.0.2/24",
            "neighbor_ipv4": "10.33.0.1",
        }
    ]
    extension_outer = json.loads(payload["extensionValues"])
    extension_row = json.loads(extension_outer["VRF_LITE_CONN"])["VRF_LITE_CONN"][0]
    assert extension_row["IF_NAME"] == "Ethernet1/10"
    assert extension_row["NEIGHBOR_ASN"] == "65001"
    assert extension_row["AUTO_VRF_LITE_FLAG"] == "false"
    assert extension_row["IP_MASK"] == "10.33.0.2/24"
    assert extension_row["NEIGHBOR_IP"] == "10.33.0.1"
    assert extension_row["DOT1Q_ID"] == "123"
    assert extension_row["VRF_LITE_JYTHON_TEMPLATE"] == "Ext_VRF_Lite_Jython"
    assert "MTU" not in extension_row
    assert "enableBorderExtension" not in extension_row
    assert "asn" not in extension_row


def test_manage_vrf_lite_00493a_payload_preserves_existing_unmanaged_extension_data():
    existing_outer = {
        "VRF_LITE_CONN": json.dumps(
            {
                "VRF_LITE_CONN": [
                    {
                        "IF_NAME": "Ethernet1/10",
                        "DOT1Q_ID": "2",
                        "NEIGHBOR_ASN": "65099",
                        "AUTO_VRF_LITE_FLAG": "true",
                        "ROUTE_MAP_IN": "PRESERVE-ME",
                    }
                ]
            },
            separators=(",", ":"),
        ),
        "MULTISITE_CONN": json.dumps({"MULTISITE_CONN": [{"site": "preserve-me"}]}, separators=(",", ":")),
        "UNMANAGED_EXTENSION": "preserve-me",
    }
    prototype = json.loads(_vrf_lite_prototype()["extensionValues"])

    rendered = build_vrf_lite_extension_values(
        [{"interface": "Ethernet1/10", "dot1q": 2, "neighbor_ipv4": "203.0.113.1"}],
        existing_extension_values=json.dumps(existing_outer),
        prototype_values_by_interface={"Ethernet1/10": prototype},
    )

    outer = json.loads(rendered)
    row = json.loads(outer["VRF_LITE_CONN"])["VRF_LITE_CONN"][0]
    assert outer["MULTISITE_CONN"] == existing_outer["MULTISITE_CONN"]
    assert outer["UNMANAGED_EXTENSION"] == "preserve-me"
    assert row["ROUTE_MAP_IN"] == "PRESERVE-ME"
    assert row["NEIGHBOR_ASN"] == "65099"
    assert row["AUTO_VRF_LITE_FLAG"] == "true"
    assert row["NEIGHBOR_IP"] == "203.0.113.1"


def test_manage_vrf_lite_00494_delete_builds_single_attachment_clear_payload():
    extension_values = build_vrf_lite_extension_values(
        [{"interface": "Ethernet1/11", "dot1q": 222, "ipv4_addr": "10.33.0.2/24"}],
    )
    instance_values = json.dumps(
        {
            "loopbackIpV6Address": "2001:db8::1",
            "loopbackId": "7",
            "switchRouteTargetImportEvpn": "65000:1",
            "evpnRouteTargetImport": "65000:2",
            "loopbackIpAddress": "192.0.2.10",
            "deviceSupportL3VniNoVlan": "false",
            "switchRouteTargetExportEvpn": "65000:3",
            "evpnRouteTargetExport": "65000:4",
        }
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
                        "freeform_config": "router bgp 65000",
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

    assert payload["fabric"] == "FABRIC1"
    assert payload["serialNumber"] == "SN2"
    assert payload["vlan"] == 500
    assert payload["deployment"] is True
    assert payload["isAttached"] is True
    rendered_instance_values = json.loads(payload["instanceValues"])
    assert rendered_instance_values["deviceSupportL3VniNoVlan"] == "false"
    assert rendered_instance_values["loopbackId"] == "7"
    assert rendered_instance_values["loopbackIpAddress"] == "192.0.2.10"
    assert rendered_instance_values["loopbackIpV6Address"] == "2001:db8::1"
    assert rendered_instance_values["switchRouteTargetImportEvpn"] == ""
    assert rendered_instance_values["switchRouteTargetExportEvpn"] == ""
    assert rendered_instance_values["evpnRouteTargetImport"] == ""
    assert rendered_instance_values["evpnRouteTargetExport"] == ""
    assert payload["freeformConfig"] == "router bgp 65000"
    assert parse_vrf_lite_extension_values(payload["extensionValues"]) == []


def test_manage_vrf_lite_00495_delete_query_filters_vrfs_without_managed_attachments(
    monkeypatch,
):
    module = _DummyModule({"state": "deleted", "fabric_name": "FABRIC1", "config": []})

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite.query_vrf_lite_state",
        lambda module, rest_send, fabric_name, filter_vrfs=None, flat=True: [
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


def test_manage_vrf_lite_00495ba_refresh_invalidates_prewrite_switch_detail_cache(monkeypatch):
    module = _DummyModule(
        {
            "state": "merged",
            "fabric_name": "FABRIC1",
            "verify": {"enabled": True},
            "_vrf_lite_switch_detail_cache": {"stale": {"extensionValues": "before-write"}},
            "_vrf_lite_nested_config": [{"vrf_name": "BLUE"}],
        }
    )
    orchestrator = _vrf_lite_orchestrator(module)
    queried = []

    def _query_current_state(flat=True):
        assert flat is True
        queried.append(True)
        assert module.params["_vrf_lite_switch_detail_cache"] == {}
        return []

    monkeypatch.setattr(orchestrator, "_query_current_state", _query_current_state)

    result = orchestrator.refresh_verified_state({"changed": True, "after": ["stale"], "current": ["stale"]})

    assert queried == [True]
    assert result["after"] == [{"vrf_name": "BLUE", "attach": []}]
    assert result["current"] == [{"vrf_name": "BLUE", "attach": []}]


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
            self.timeout = 30
            self.check_mode = True
            self.path = None
            self.verb = None
            self.response_current = {}
            self.result_current = {}
            self.response_handler = None
            self.calls = 0
            self.saved = 0
            self.restored = 0
            self.timeouts = []

        def save_settings(self):
            self.saved += 1

        def restore_settings(self):
            self.restored += 1
            self.timeouts.append(self.timeout)

        def commit(self):
            assert self.path == "/read"
            assert self.verb == HttpVerbEnum.GET
            self.calls += 1
            if self.calls < 3:
                raise RuntimeError("controller not ready")
            self.response_current = {"DATA": {"ok": True}}
            self.result_current = {"success": True}

    module = _DummyModule({"verify": {"retries": 3, "timeout": 7}})
    rest_send = _FakeRestSend()

    result = request_with_verify_settings(module, rest_send, "/read", HttpVerbEnum.GET)

    assert result == {"ok": True}
    assert rest_send.calls == 3
    assert rest_send.saved == 3
    assert rest_send.restored == 3
    assert rest_send.timeouts == [7, 7, 7]


def test_manage_vrf_lite_00500_guardrails_reject_missing_prototype_metadata(monkeypatch):
    module = _DummyWarnModule(
        {
            "fabric_name": "F1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_fabric_switch_inventory": {},
        }
    )
    model = _vrf_lite_guardrail_model()
    _mock_guardrail_inventory(monkeypatch)
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._query_vrf_lite_support",
        lambda _module, _rest_send, _fabric_name, _vrf_name, _serial_number: None,
    )

    with pytest.raises(VrfLiteResourceError, match="did not return VRF Lite interface prototype metadata"):
        validate_vrf_lite_write_guardrails(module=module, model_instance=model, rest_send=object())


def test_manage_vrf_lite_00550_guardrails_accept_usable_prototype_case_insensitively(monkeypatch):
    module = _DummyWarnModule(
        {
            "fabric_name": "F1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_fabric_switch_inventory": {},
        }
    )
    model = _vrf_lite_guardrail_model(interface="ethernet1/10")
    _mock_guardrail_inventory(monkeypatch, role="leaf", fabric_type="externalConnectivity")
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._query_vrf_lite_support",
        lambda _module, _rest_send, _fabric_name, _vrf_name, _serial_number: True,
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation.get_cached_vrf_lite_prototypes",
        lambda *_args: {
            "Ethernet1/10": json.loads(_vrf_lite_prototype()["extensionValues"]),
        },
    )

    validate_vrf_lite_write_guardrails(module=module, model_instance=model, rest_send=object())


def test_manage_vrf_lite_00575_guardrails_cache_real_switch_prototype_response():
    class _FakeRestSend:
        def __init__(self):
            self.timeout = 30
            self.check_mode = False
            self.path = None
            self.verb = None
            self.response_handler = None
            self.response_current = {}
            self.result_current = {}
            self.calls = 0

        def save_settings(self):
            pass

        def restore_settings(self):
            pass

        def commit(self):
            assert self.path == VrfLiteEndpoints.vrf_switch("F1", "BLUE", "SN1")
            assert self.verb == HttpVerbEnum.GET
            self.calls += 1
            self.response_current = {
                "DATA": [
                    {
                        "vrfName": "BLUE",
                        "switchDetailsList": [
                            _vrf_lite_switch_detail(),
                        ],
                    }
                ]
            }
            self.result_current = {"success": True}

    module = _DummyWarnModule(
        {
            "fabric_name": "F1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_fabric_switch_inventory": {
                "SN1": {
                    "switchId": "SN1",
                    "fabricManagementIp": "10.0.0.1",
                    "switchRole": "border",
                }
            },
            "_vrf_lite_support_cache": {},
            "_vrf_lite_prototype_cache": {},
            "_vrf_lite_switch_detail_cache": {},
        }
    )
    model = _vrf_lite_guardrail_model()
    rest_send = _FakeRestSend()

    validate_vrf_lite_write_guardrails(module=module, model_instance=model, rest_send=rest_send)
    validate_vrf_lite_write_guardrails(module=module, model_instance=model, rest_send=rest_send)

    assert rest_send.calls == 1
    prototypes = module.params["_vrf_lite_prototype_cache"][_vrf_lite_cache_key("F1", "BLUE", "SN1")]
    assert prototypes["Ethernet1/10"]["NEIGHBOR_ASN"] == "65001"
    assert prototypes["Ethernet1/10"]["AUTO_VRF_LITE_FLAG"] == "false"


def test_manage_vrf_lite_00577_switch_detail_cache_isolated_by_vrf():
    class _FakeRestSend:
        timeout = 30
        check_mode = False
        response_handler = None

        def __init__(self):
            self.path = None
            self.verb = None
            self.response_current = {}
            self.result_current = {}
            self.calls = []

        def save_settings(self):
            pass

        def restore_settings(self):
            pass

        def commit(self):
            self.calls.append(self.path)
            vrf_name = "BLUE" if "vrf-names=BLUE" in self.path else "GREEN"
            self.response_current = {
                "DATA": [
                    {
                        "vrfName": vrf_name,
                        "switchDetailsList": [
                            _vrf_lite_switch_detail(extra_vrf=vrf_name),
                        ],
                    }
                ]
            }
            self.result_current = {"success": True}

    module = _DummyModule({"_vrf_lite_switch_detail_cache": {}})
    rest_send = _FakeRestSend()

    blue = _query_vrf_switch_details(module, rest_send, "F1", "BLUE", ["SN1"])
    green = _query_vrf_switch_details(module, rest_send, "F1", "GREEN", ["SN1"])
    blue_cached = _query_vrf_switch_details(module, rest_send, "F1", "BLUE", ["SN1"])

    assert blue["SN1"]["extra_vrf"] == "BLUE"
    assert green["SN1"]["extra_vrf"] == "GREEN"
    assert blue_cached == blue
    assert len(rest_send.calls) == 2


def test_manage_vrf_lite_00580_guardrails_report_requested_and_available_interfaces(monkeypatch):
    module = _DummyWarnModule(
        {
            "fabric_name": "F1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_fabric_switch_inventory": {},
        }
    )
    _mock_guardrail_inventory(monkeypatch)
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._query_vrf_lite_support",
        lambda *_args: True,
    )
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation.get_cached_vrf_lite_prototypes",
        lambda *_args: {
            "Ethernet1/1": json.loads(_vrf_lite_prototype("Ethernet1/1")["extensionValues"]),
        },
    )

    with pytest.raises(VrfLiteResourceError, match=r"Requested interface\(s\): Ethernet1/10.*Available interface\(s\): Ethernet1/1"):
        validate_vrf_lite_write_guardrails(module=module, model_instance=_vrf_lite_guardrail_model(), rest_send=object())


def test_manage_vrf_lite_00582_prototype_parser_distinguishes_absent_empty_and_malformed():
    assert _extract_vrf_lite_prototypes({"serialNumber": "SN1"}, "SN1") is None
    assert (
        _extract_vrf_lite_prototypes(
            {
                "serialNumber": "SN1",
                "extensionPrototypeValues": [],
            },
            "SN1",
        )
        == {}
    )
    assert _extract_vrf_lite_prototypes(
        {
            "serialNumber": "SN1",
            "extensionPrototypeValues": [
                _vrf_lite_prototype(extension_values="{not-json"),
            ],
        },
        "SN1",
    ) == {"Ethernet1/10": {"IF_NAME": "Ethernet1/10"}}


def test_manage_vrf_lite_00585_guardrails_reject_empty_and_malformed_prototypes(monkeypatch):
    module = _DummyWarnModule(
        {
            "fabric_name": "F1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_fabric_switch_inventory": {},
        }
    )
    _mock_guardrail_inventory(monkeypatch)
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._query_vrf_lite_support",
        lambda *_args: True,
    )

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation.get_cached_vrf_lite_prototypes",
        lambda *_args: {},
    )
    with pytest.raises(VrfLiteResourceError, match="No VRF Lite-capable interfaces"):
        validate_vrf_lite_write_guardrails(module=module, model_instance=_vrf_lite_guardrail_model(), rest_send=object())

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation.get_cached_vrf_lite_prototypes",
        lambda *_args: {"Ethernet1/10": {"IF_NAME": "Ethernet1/10"}},
    )
    with pytest.raises(VrfLiteResourceError, match="unusable VRF Lite prototype metadata"):
        validate_vrf_lite_write_guardrails(module=module, model_instance=_vrf_lite_guardrail_model(), rest_send=object())


def test_manage_vrf_lite_00600_guardrails_reject_unsupported_switch(monkeypatch):
    module = _DummyWarnModule(
        {
            "fabric_name": "F1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_fabric_switch_inventory": {},
        }
    )
    model = _vrf_lite_guardrail_model()
    _mock_guardrail_inventory(monkeypatch)
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._query_vrf_lite_support",
        lambda _module, _rest_send, _fabric_name, _vrf_name, _serial_number: False,
    )

    with pytest.raises(VrfLiteResourceError, match="does not report VRF Lite support"):
        validate_vrf_lite_write_guardrails(module=module, model_instance=model, rest_send=object())


def test_manage_vrf_lite_00700_guardrails_fail_closed_when_prototype_query_fails(monkeypatch):
    module = _DummyWarnModule(
        {
            "fabric_name": "F1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_fabric_switch_inventory": {},
            "_warnings": [],
        }
    )
    model = _vrf_lite_guardrail_model()
    _mock_guardrail_inventory(monkeypatch, role="")
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation._query_vrf_lite_support",
        lambda _module, _rest_send, _fabric_name, _vrf_name, _serial_number: (_x for _x in ()).throw(Exception("boom")),
    )

    with pytest.raises(Exception, match="boom"):
        validate_vrf_lite_write_guardrails(module=module, model_instance=model, rest_send=object())


def test_manage_vrf_lite_00800_attachment_post_uses_legacy_vrf_lite_payload(
    monkeypatch,
):
    calls = []

    def _request(module, rest_send, path, verb, payload):
        calls.append((module, rest_send, path, verb, payload))
        return {"ok": True}

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions._request_vrf_lite_payload",
        _request,
    )
    module = _DummyModule({})
    rest_send = object()
    lan_attach_list = [{"serialNumber": "SN1", "isAttached": True}]

    result = _post_attachment_payload(
        module=module,
        rest_send=rest_send,
        fabric_name="FABRIC1",
        vrf_name="BLUE",
        lan_attach_list=lan_attach_list,
    )

    assert result == {"ok": True}
    assert calls == [
        (
            module,
            rest_send,
            "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/FABRIC1/vrfs/attachments",
            HttpVerbEnum.POST,
            [{"vrfName": "BLUE", "lanAttachList": lan_attach_list}],
        )
    ]


def test_manage_vrf_lite_00850_attachment_post_reports_structured_controller_failure(
    monkeypatch,
):
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions._request_vrf_lite_payload",
        lambda *args, **kwargs: {
            "results": [
                {
                    "message": "Provided interface doesn't have extensions[Ethernet1/2]",
                    "status": "failed",
                    "switchId": "SN1",
                    "switchName": "leaf1",
                    "vrfName": "BLUE",
                }
            ]
        },
    )

    with pytest.raises(VrfLiteResourceError, match="attachment API reported failure") as error:
        _post_attachment_payload(
            module=_DummyModule({}),
            rest_send=object(),
            fabric_name="FABRIC1",
            vrf_name="BLUE",
            lan_attach_list=[{"serialNumber": "SN1"}],
        )

    assert "BLUE/SN1: Provided interface doesn't have extensions[Ethernet1/2]" in str(error.value)


def test_manage_vrf_lite_00860_attachment_post_reports_legacy_controller_failure(
    monkeypatch,
):
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions._request_vrf_lite_payload",
        lambda *args, **kwargs: {
            "BLUE-[SN1/leaf1]": "Attach Response : Failed : VPC details not found for Peer Serial no: SN2",
        },
    )

    with pytest.raises(VrfLiteResourceError, match="attachment API reported failure") as error:
        _post_attachment_payload(
            module=_DummyModule({}),
            rest_send=object(),
            fabric_name="FABRIC1",
            vrf_name="BLUE",
            lan_attach_list=[{"serialNumber": "SN1"}],
        )

    assert "VPC details not found for Peer Serial no: SN2" in str(error.value)


def test_manage_vrf_lite_00870_list_payload_uses_list_capable_rest_transport(monkeypatch):
    seen = {}

    def _commit(active_rest_send):
        seen["path"] = active_rest_send.path
        seen["verb"] = active_rest_send.verb
        seen["payload"] = active_rest_send.payload
        active_rest_send.response_current = {"RETURN_CODE": 200, "DATA": {"ok": True}}
        active_rest_send.result_current = {"success": True}

    monkeypatch.setattr(_VrfLiteListPayloadRestSend, "commit", _commit)
    module = _DummyModule({"state": "merged"})
    sender = Sender()
    sender.ansible_module = module
    base_rest_send = RestSend({"check_mode": False, "state": "merged"})
    base_rest_send.sender = sender
    base_rest_send.response_handler = ResponseHandler()
    payload = [{"vrfName": "BLUE", "lanAttachList": [{"serialNumber": "SN1"}]}]

    response = request_with_rest_send(
        module,
        base_rest_send,
        "/legacy/vrfs/attachments",
        HttpVerbEnum.POST,
        payload,
    )

    assert response == {"ok": True}
    assert seen == {
        "path": "/legacy/vrfs/attachments",
        "verb": HttpVerbEnum.POST,
        "payload": payload,
    }


def test_manage_vrf_lite_00880_request_error_preserves_status_and_controller_body(monkeypatch):
    def _raise_nd_error(**_kwargs):
        raise NDModuleError(
            msg="Internal Server Error",
            status=500,
            response_payload={"error": "controller detail"},
        )

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions.request_with_rest_send",
        _raise_nd_error,
    )

    with pytest.raises(VrfLiteResourceError) as error:
        _request_vrf_lite_payload(
            module=_DummyModule({}),
            rest_send=object(),
            path="/legacy/vrfs/attachments",
            verb=HttpVerbEnum.POST,
            payload=[{"vrfName": "BLUE"}],
        )

    assert "status=500" in error.value.msg
    assert "controller detail" in error.value.msg
    assert error.value.details["status"] == 500
    assert error.value.details["response_payload"] == {"error": "controller detail"}


def test_manage_vrf_lite_00890_attachment_post_does_not_double_wrap_resource_error(monkeypatch):
    original = VrfLiteResourceError(
        "controller rejected attachment",
        status=500,
        response_payload={"error": "specific detail"},
    )

    def _raise_resource_error(*_args, **_kwargs):
        raise original

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions._request_vrf_lite_payload",
        _raise_resource_error,
    )

    with pytest.raises(VrfLiteResourceError) as error:
        _post_attachment_payload(
            module=_DummyModule({}),
            rest_send=object(),
            fabric_name="FABRIC1",
            vrf_name="BLUE",
            lan_attach_list=[{"serialNumber": "SN1"}],
        )

    assert error.value is original
    assert error.value.details["response_payload"] == {"error": "specific detail"}


def test_manage_vrf_lite_00900_check_mode_preflight_validates_vrf_existence(
    monkeypatch,
):
    """Check mode must reject a nonexistent VRF the same way the real run would.

    The generic state machine skips every write in check mode, so the attach
    guardrails are reached only through preflight_validate_check_mode.
    """
    seen = []

    def _boom(module, rest_send, vrf_name):
        del module, rest_send
        seen.append(vrf_name)
        raise VrfLiteResourceError("VRF {0} does not exist".format(vrf_name))

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite._ensure_vrf_exists",
        _boom,
    )
    module = _DummyModule({"check_mode": True, "state": "merged", "fabric_name": "F1"})
    orchestrator = _vrf_lite_orchestrator(module)

    with pytest.raises(VrfLiteResourceError, match="does not exist"):
        orchestrator.preflight_validate_check_mode([_StubEntry("MISSING", "10.0.0.1")])
    assert seen == ["MISSING"]


def test_manage_vrf_lite_00910_preflight_is_noop_outside_check_mode(monkeypatch):
    """Outside check mode the write path performs validation, so the preflight must
    not run (and must not double-validate)."""

    def _fail(*args, **kwargs):
        raise AssertionError("preflight must not validate outside check mode")

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite._ensure_vrf_exists",
        _fail,
    )
    module = _DummyModule({"check_mode": False, "state": "merged", "fabric_name": "F1"})
    orchestrator = _vrf_lite_orchestrator(module)

    orchestrator.preflight_validate_check_mode([_StubEntry("BLUE", "10.0.0.1")])


def test_manage_vrf_lite_00920_preflight_skips_non_write_states(monkeypatch):
    """deleted/gathered runs perform no attaches, so the attach preflight is skipped."""

    def _fail(*args, **kwargs):
        raise AssertionError("preflight must not validate for non-write states")

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite._ensure_vrf_exists",
        _fail,
    )
    module = _DummyModule({"check_mode": True, "state": "deleted", "fabric_name": "F1"})
    orchestrator = _vrf_lite_orchestrator(module)

    orchestrator.preflight_validate_check_mode([_StubEntry("BLUE", "10.0.0.1")])
