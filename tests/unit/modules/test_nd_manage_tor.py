# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``nd_manage_tor`` switch resolution.

Each ``*_switch`` suboption accepts a serial number OR a management IP; the
module resolves an IP to its serial and remaps the user-facing key onto the
``*_switch_id`` model field before the state machine builds the proposed
collection.
"""

from __future__ import annotations

import types

import pytest
import yaml
from ansible_collections.cisco.nd.plugins.modules import nd_manage_tor
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_tor.manage_tor import ManageTorModel


class _FakeInventory:
    """Minimal FabricSwitchInventory stand-in exposing by_ip()."""

    def __init__(self, ip_to_serial):
        self._ip_to_serial = ip_to_serial

    def by_ip(self):
        return {ip: types.SimpleNamespace(switch_id=serial) for ip, serial in self._ip_to_serial.items()}


def _boom():
    raise AssertionError("inventory should not be fetched when every value is a serial")


def test_looks_like_ip_distinguishes_ip_from_serial():
    assert nd_manage_tor._looks_like_ip("192.0.2.10") is True
    assert nd_manage_tor._looks_like_ip("2001:db8::1") is True
    assert nd_manage_tor._looks_like_ip("9WU9XPHL9SW") is False
    assert nd_manage_tor._looks_like_ip("FDO123TOR01") is False


def test_all_serials_remap_without_inventory_fetch():
    """Serials are passed through and remapped; the inventory is never queried."""
    config = [{"access_or_tor_switch": "9TOR", "aggregation_or_leaf_switch": "9LEAF"}]
    nd_manage_tor._resolve_switch_config(config, "fab1", _boom)
    assert config[0]["access_or_tor_switch_id"] == "9TOR"
    assert config[0]["aggregation_or_leaf_switch_id"] == "9LEAF"
    assert "access_or_tor_switch" not in config[0]
    assert "aggregation_or_leaf_switch" not in config[0]


def test_ip_is_resolved_to_serial_and_remapped():
    """A management IP is resolved to its serial via the inventory and remapped."""
    config = [
        {
            "access_or_tor_switch": "192.0.2.10",
            "aggregation_or_leaf_switch": "9LEAF",
            "access_or_tor_peer_switch": None,
            "aggregation_or_leaf_peer_switch": None,
        }
    ]
    inventory = _FakeInventory({"192.0.2.10": "9TOR"})
    nd_manage_tor._resolve_switch_config(config, "fab1", lambda: inventory)
    assert config[0]["access_or_tor_switch_id"] == "9TOR"
    assert config[0]["aggregation_or_leaf_switch_id"] == "9LEAF"
    # User-facing keys are consumed; only the *_switch_id serial fields remain.
    assert "access_or_tor_switch" not in config[0]
    assert "aggregation_or_leaf_switch" not in config[0]


def test_absent_peer_fields_are_dropped_not_set():
    """A None peer value is popped and never written as a *_switch_id field."""
    config = [
        {
            "access_or_tor_switch": "9TOR",
            "aggregation_or_leaf_switch": "9LEAF",
            "access_or_tor_peer_switch": None,
            "aggregation_or_leaf_peer_switch": None,
        }
    ]
    nd_manage_tor._resolve_switch_config(config, "fab1", _boom)
    assert "access_or_tor_peer_switch_id" not in config[0]
    assert "aggregation_or_leaf_peer_switch_id" not in config[0]
    assert "access_or_tor_peer_switch" not in config[0]
    assert "aggregation_or_leaf_peer_switch" not in config[0]


def test_mixed_serial_and_ip_across_sides():
    """Serial and IP inputs resolve independently within one entry."""
    config = [
        {
            "access_or_tor_switch": "192.0.2.10",
            "aggregation_or_leaf_switch": "9LEAF",
            "access_or_tor_peer_switch": "192.0.2.11",
            "aggregation_or_leaf_peer_switch": "9LEAF2",
        }
    ]
    inventory = _FakeInventory({"192.0.2.10": "9TOR", "192.0.2.11": "9TORPEER"})
    nd_manage_tor._resolve_switch_config(config, "fab1", lambda: inventory)
    assert config[0]["access_or_tor_switch_id"] == "9TOR"
    assert config[0]["access_or_tor_peer_switch_id"] == "9TORPEER"
    assert config[0]["aggregation_or_leaf_switch_id"] == "9LEAF"
    assert config[0]["aggregation_or_leaf_peer_switch_id"] == "9LEAF2"


def test_unknown_ip_raises():
    """An IP with no matching switch surfaces a clear resolution error."""
    config = [{"access_or_tor_switch": "10.0.0.99", "aggregation_or_leaf_switch": "9LEAF"}]
    inventory = _FakeInventory({})
    with pytest.raises(Exception, match="Could not resolve"):
        nd_manage_tor._resolve_switch_config(config, "fab1", lambda: inventory)


def test_documentation_suboptions_match_argument_spec():
    """validate-modules parity: DOCUMENTATION suboptions == argument spec options."""
    doc = yaml.safe_load(nd_manage_tor.DOCUMENTATION)
    doc_subs = set(doc["options"]["config"]["suboptions"].keys())
    spec_subs = set(ManageTorModel.get_argument_spec()["config"]["options"].keys())
    assert doc_subs == spec_subs, {"doc_only": sorted(doc_subs - spec_subs), "spec_only": sorted(spec_subs - doc_subs)}
