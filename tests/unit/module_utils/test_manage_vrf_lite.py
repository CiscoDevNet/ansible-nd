# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for nd_manage_vrf_lite merge/payload/config-actions behavior."""

from __future__ import absolute_import, annotations, division, print_function

import json

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.actions import (
    _build_want_attachment_maps,
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
    custom_vrf_lite_deploy,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query import (
    custom_vrf_lite_query_all,
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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrf_lite.vrf_lite_model import (
    VrfLiteModel,
    VrfLitePlaybookConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_vrf_lite import (
    ManageVrfLiteOrchestrator,
)


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


class _DummyQueryContext:
    def __init__(self, module):
        self.module = module


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


def test_manage_vrf_lite_00490_deploy_needed_when_reconciler_changed_without_changed_vrf_marker():
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


def test_manage_vrf_lite_00492_custom_deploy_filters_changed_vrfs_by_deploy_intent():
    module = _DummyModule(
        {
            "check_mode": True,
            "_changed_vrfs": ["BLUE", "GREEN", "RED"],
            "config_actions": {"save": True, "deploy": True, "type": "switch"},
            "config": [
                {"vrf_name": "BLUE", "attach": [{"ip_address": "10.0.0.1", "deploy": False}]},
                {"vrf_name": "GREEN", "attach": [{"ip_address": "10.0.0.2"}]},
                {"vrf_name": "RED", "deploy": False, "attach": [{"ip_address": "10.0.0.3"}]},
            ],
        }
    )

    result = custom_vrf_lite_deploy(module=module, fabric_name="FABRIC1", result={"changed": True})

    assert result["target_vrfs"] == ["GREEN"]
    assert result["planned_actions"] == [
        "POST {0}".format(VrfLiteEndpoints.config_save("FABRIC1")),
        "POST {0} vrfNames=GREEN".format(VrfLiteEndpoints.vrf_deployments("FABRIC1")),
    ]


def test_manage_vrf_lite_00493_attachment_deploy_false_flows_into_attachment_payload():
    class _FakeNDModule:
        def request(self, path, verb, payload):
            del path, verb, payload
            pytest.fail("dot1q reservation should not be called when dot1q is provided")

    module = _DummyModule(
        {
            "fabric_name": "FABRIC1",
            "_ip_to_sn_mapping": {"10.0.0.1": "SN1"},
            "_raw_vrf_attachment_map": {},
        }
    )
    model = VrfLiteModel.from_config(
        {
            "vrf_name": "BLUE",
            "vlan_id": 500,
            "attach": [
                {
                    "ip_address": "10.0.0.1",
                    "deploy": False,
                    "vrf_lite": [{"interface": "Ethernet1/10", "dot1q": 500}],
                }
            ],
        }
    )

    _want_map, payloads = _build_want_attachment_maps(
        module=module,
        nd_v2=_FakeNDModule(),
        model_instance=model,
        current_vrf={"vrf_name": "BLUE", "vlan_id": 500, "attach": []},
    )

    assert payloads["SN1"]["deployment"] is False


def test_manage_vrf_lite_00495_delete_query_filters_vrfs_without_managed_attachments(monkeypatch):
    module = _DummyModule({"state": "deleted", "fabric_name": "FABRIC1", "config": []})

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query.query_vrf_lite_state",
        lambda module, fabric_name, filter_vrfs=None: [
            {"vrf_name": "EMPTY", "attach": []},
            {"vrf_name": "BLUE", "attach": [{"ip_address": "10.0.0.1"}]},
        ],
    )

    have = custom_vrf_lite_query_all(_DummyQueryContext(module))

    assert have == [{"vrf_name": "BLUE", "attach": [{"ip_address": "10.0.0.1"}]}]
    assert module.params["_have"] == have


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
    # Ensure validator no longer depends on module.warn side-effects.
    assert module.warnings == []


def test_manage_vrf_lite_00800_attachment_post_uses_ndfc_top_level_list_payload():
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
            "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/FABRIC1/vrfs/attachments",
            HttpVerbEnum.POST,
            [{"vrfName": "BLUE", "lanAttachList": lan_attach_list}],
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
