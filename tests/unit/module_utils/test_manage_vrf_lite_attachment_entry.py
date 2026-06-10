# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for VrfLiteAttachmentEntry and the flat-mode query output.

These cover PR 1 (Foundations) of the attachment-granularity refactor:
the new flat per-(vrf_name, switch_ip) attachment model and the
``flat=True`` output mode of ``query_vrf_lite_state``.
"""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrf_lite.vrf_lite_attachment_entry import (
    VrfLiteAttachmentEntry,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query import (
    _flatten_to_entries,
)

# --- Identifier & basic serialization ------------------------------------


def test_identifier_is_composite_tuple():
    entry = VrfLiteAttachmentEntry(vrf_name="TENANT_A", switch_ip="10.10.10.11")
    assert entry.identifier_strategy == "composite"
    assert entry.get_identifier_value() == ("TENANT_A", "10.10.10.11")


def test_missing_identifier_field_raises():
    with pytest.raises(ValidationError):
        VrfLiteAttachmentEntry(vrf_name="TENANT_A")  # type: ignore[call-arg]


def test_round_trip_from_config_preserves_fields():
    data = {
        "vrf_name": "TENANT_B",
        "switch_ip": "10.10.10.12",
        "vlan_id": 500,
        "import_evpn_rt": "65000:100",
        "export_evpn_rt": "65000:100",
        "extensions": [{"interface": "Ethernet1/20", "dot1q": 500, "ipv4_addr": "10.33.0.2/24"}],
    }
    entry = VrfLiteAttachmentEntry.from_config(data)
    cfg = entry.to_config()
    assert cfg["vrf_name"] == "TENANT_B"
    assert cfg["switch_ip"] == "10.10.10.12"
    assert cfg["vlan_id"] == 500
    assert cfg["extensions"][0]["interface"] == "Ethernet1/20"


def test_deploy_excluded_from_diff_dict():
    base = VrfLiteAttachmentEntry(vrf_name="A", switch_ip="1.1.1.1")
    with_deploy = VrfLiteAttachmentEntry(vrf_name="A", switch_ip="1.1.1.1", deploy=True)
    assert base.to_diff_dict() == with_deploy.to_diff_dict()


def test_deploy_only_diff_is_no_diff():
    """Existing entry with deploy=True vs proposed without deploy must be no_diff.

    Regression test for TC9: query returns deploy=True on an already-deployed
    entry; if the user did not set deploy in their playbook the state machine
    must not classify it as 'changed' for either merge or replace/override.
    """
    existing = VrfLiteAttachmentEntry(vrf_name="A", switch_ip="1.1.1.1", vlan_id=10, deploy=True)
    proposed = VrfLiteAttachmentEntry(vrf_name="A", switch_ip="1.1.1.1", vlan_id=10)
    coll = NDConfigCollection(model_class=VrfLiteAttachmentEntry, items=[existing])
    # merge state (exclude_unset=True)
    assert coll.get_diff_config(proposed, exclude_unset=True) == "no_diff"
    # replace/override state (exclude_unset=False)
    assert coll.get_diff_config(proposed, exclude_unset=False) == "no_diff"


def test_empty_string_evpn_rt_coerced_to_none():
    """Empty-string EVPN RT is normalised to None by the model validator.

    The query layer may produce '' for absent EVPN RT fields. The model
    must coerce that to None so it is excluded by exclude_none=True in
    to_diff_dict, preventing false 'changed' classifications.
    """
    entry = VrfLiteAttachmentEntry(vrf_name="A", switch_ip="1.1.1.1", import_evpn_rt="", export_evpn_rt="")
    assert entry.import_evpn_rt is None
    assert entry.export_evpn_rt is None
    assert "import_evpn_rt" not in entry.to_diff_dict()
    assert "export_evpn_rt" not in entry.to_diff_dict()


# --- Merge behaviour ------------------------------------------------------


def test_merge_preserves_unmentioned_interfaces():
    base = VrfLiteAttachmentEntry.from_config(
        {
            "vrf_name": "X",
            "switch_ip": "1.1.1.1",
            "extensions": [
                {"interface": "Eth1", "dot1q": 100},
                {"interface": "Eth2", "dot1q": 200},
            ],
        }
    )
    incoming = VrfLiteAttachmentEntry.from_config(
        {
            "vrf_name": "X",
            "switch_ip": "1.1.1.1",
            "extensions": [{"interface": "Eth1", "dot1q": 150}],
        }
    )
    merged = base.merge(incoming)
    by_iface = {e.interface: e.dot1q for e in merged.extensions}
    assert by_iface == {"Eth1": 150, "Eth2": 200}


def test_merge_scalar_fields_only_when_set():
    base = VrfLiteAttachmentEntry(vrf_name="X", switch_ip="1.1.1.1", vlan_id=100)
    incoming = VrfLiteAttachmentEntry(vrf_name="X", switch_ip="1.1.1.1")  # vlan_id unset
    merged = base.merge(incoming)
    assert merged.vlan_id == 100


def test_merge_empty_extensions_list_preserves_existing():
    """An incoming entry with extensions=[] must not wipe existing extensions.

    An empty list is treated the same as an absent list: the existing
    extensions are preserved so that a playbook mentioning a VRF attachment
    without specifying extensions does not accidentally remove them.
    """
    base = VrfLiteAttachmentEntry.from_config(
        {
            "vrf_name": "X",
            "switch_ip": "1.1.1.1",
            "extensions": [{"interface": "Eth1", "dot1q": 100}],
        }
    )
    incoming = VrfLiteAttachmentEntry.from_config(
        {
            "vrf_name": "X",
            "switch_ip": "1.1.1.1",
            "extensions": [],
        }
    )
    merged = base.merge(incoming)
    assert merged.extensions is not None and len(merged.extensions) == 1
    assert merged.extensions[0].interface == "Eth1"


# --- NDConfigCollection integration --------------------------------------


def test_collection_classifies_new_no_diff_changed():
    e1 = VrfLiteAttachmentEntry(vrf_name="A", switch_ip="1.1.1.1", vlan_id=10)
    e2 = VrfLiteAttachmentEntry(vrf_name="B", switch_ip="2.2.2.2", vlan_id=20)
    coll = NDConfigCollection(model_class=VrfLiteAttachmentEntry, items=[e1, e2])

    assert coll.get_diff_config(VrfLiteAttachmentEntry(vrf_name="C", switch_ip="3.3.3.3")) == "new"
    assert coll.get_diff_config(VrfLiteAttachmentEntry(vrf_name="A", switch_ip="1.1.1.1", vlan_id=10)) == "no_diff"
    assert coll.get_diff_config(VrfLiteAttachmentEntry(vrf_name="A", switch_ip="1.1.1.1", vlan_id=99)) == "changed"


def test_collection_keys_use_tuples():
    coll = NDConfigCollection(
        model_class=VrfLiteAttachmentEntry,
        items=[VrfLiteAttachmentEntry(vrf_name="A", switch_ip="1.1.1.1")],
    )
    assert ("A", "1.1.1.1") in coll.keys()


# --- Flat query flattener -------------------------------------------------


def test_flatten_emits_one_entry_per_switch():
    nested = [
        {
            "vrf_name": "TENANT_A",
            "vlan_id": 500,
            "attach": [
                {"ip_address": "10.10.10.11", "deploy": True, "vrf_lite": [{"interface": "Eth1"}]},
                {"ip_address": "10.10.10.12", "deploy": True},
            ],
        }
    ]
    flat = _flatten_to_entries(nested)
    assert [e["switch_ip"] for e in flat] == ["10.10.10.11", "10.10.10.12"]
    assert all(e["vrf_name"] == "TENANT_A" for e in flat)
    assert flat[0]["vlan_id"] == 500
    assert flat[0]["extensions"] == [{"interface": "Eth1"}]


def test_flatten_skips_vrfs_with_no_attach():
    nested = [{"vrf_name": "EMPTY", "vlan_id": 10, "attach": []}]
    assert _flatten_to_entries(nested) == []


def test_flatten_sorts_by_vrf_then_switch():
    nested = [
        {"vrf_name": "B", "attach": [{"ip_address": "2.2.2.2"}, {"ip_address": "1.1.1.1"}]},
        {"vrf_name": "A", "attach": [{"ip_address": "3.3.3.3"}]},
    ]
    flat = _flatten_to_entries(nested)
    assert [(e["vrf_name"], e["switch_ip"]) for e in flat] == [
        ("A", "3.3.3.3"),
        ("B", "1.1.1.1"),
        ("B", "2.2.2.2"),
    ]


def test_flatten_drops_none_fields():
    nested = [{"vrf_name": "A", "attach": [{"ip_address": "1.1.1.1", "deploy": None, "import_evpn_rt": None}]}]
    entry = _flatten_to_entries(nested)[0]
    assert "deploy" not in entry
    assert "import_evpn_rt" not in entry
