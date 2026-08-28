# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `MaintenanceModeModel` and `MaintenanceModeSwitchModel`.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.maintenance_mode.maintenance_mode import (
    MaintenanceModeModel,
    MaintenanceModeSwitchModel,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

# =============================================================================
# Test: initialization / identifier behavior
# =============================================================================


def test_maintenance_mode_model_00010() -> None:
    """
    # Summary

    Verify identifier strategy is singleton.

    ## Test

    - `identifier_strategy` is `"singleton"`
    - `identifiers` is the empty list
    - `get_identifier_value()` returns None

    ## Classes and Methods

    - MaintenanceModeModel.identifier_strategy
    - MaintenanceModeModel.get_identifier_value
    """
    assert MaintenanceModeModel.identifier_strategy == "singleton"
    assert MaintenanceModeModel.identifiers == []

    # mode left unset so the `mode set + switches=[]` validator does not fire here.
    instance = MaintenanceModeModel()
    assert instance.get_identifier_value() is None


def test_maintenance_mode_model_00020() -> None:
    """
    # Summary

    Verify defaults for optional fields.

    ## Classes and Methods

    - MaintenanceModeModel.__init__
    """
    instance = MaintenanceModeModel()
    assert instance.mode is None
    assert instance.deploy is False
    assert instance.blocking is False
    assert instance.ticket_id is None
    assert instance.switches == []
    assert instance.switch_modes is None


# =============================================================================
# Test: from_config / from_response factories
# =============================================================================


def test_maintenance_mode_model_00030() -> None:
    """
    # Summary

    Verify `from_config` accepts Ansible-style keys and populates nested switch models.

    ## Classes and Methods

    - NDBaseModel.from_config
    """
    instance = MaintenanceModeModel.from_config(
        {
            "mode": "maintenance",
            "deploy": True,
            "blocking": True,
            "ticket_id": "CHG-1",
            "switches": [{"switch_ip": "192.168.12.131"}, {"switch_ip": "192.168.12.151"}],
        }
    )
    assert instance.mode == "maintenance"
    assert instance.deploy is True
    assert instance.blocking is True
    assert instance.ticket_id == "CHG-1"
    assert len(instance.switches) == 2
    assert all(isinstance(s, MaintenanceModeSwitchModel) for s in instance.switches)
    assert [s.switch_ip for s in instance.switches] == ["192.168.12.131", "192.168.12.151"]
    assert instance.switch_modes is None


def test_maintenance_mode_model_00040() -> None:
    """
    # Summary

    Verify `from_response` accepts a snapshot dict with switch_modes.

    ## Classes and Methods

    - NDBaseModel.from_response
    """
    snapshot = MaintenanceModeModel.from_response(
        {
            "switches": [{"switch_ip": "192.168.12.131"}],
            "switch_modes": {"192.168.12.131": "normal"},
        }
    )
    assert snapshot.mode is None
    assert snapshot.switch_modes == {"192.168.12.131": "normal"}


# =============================================================================
# Test: to_payload (wire shape)
# =============================================================================


def test_maintenance_mode_model_00050() -> None:
    """
    # Summary

    Verify `to_payload` returns only `mode` — everything else is either a query param or client-side
    metadata (orchestrator injects `switchIds` separately).

    ## Classes and Methods

    - MaintenanceModeModel.to_payload
    """
    instance = MaintenanceModeModel.from_config(
        {
            "mode": "maintenance",
            "deploy": True,
            "blocking": True,
            "ticket_id": "CHG-1",
            "switches": [{"switch_ip": "192.168.12.131"}],
        }
    )
    payload = instance.to_payload()
    assert payload == {"mode": "maintenance"}


# =============================================================================
# Test: get_diff (per-switch mode comparison)
# =============================================================================


@pytest.mark.parametrize(
    "snapshot_modes,desired_mode,switches,expected",
    [
        ({"192.168.12.131": "normal"}, "normal", ["192.168.12.131"], True),
        ({"192.168.12.131": "normal"}, "maintenance", ["192.168.12.131"], False),
        (
            {"192.168.12.131": "maintenance", "192.168.12.151": "maintenance"},
            "maintenance",
            ["192.168.12.131", "192.168.12.151"],
            True,
        ),
        (
            {"192.168.12.131": "maintenance", "192.168.12.151": "normal"},
            "maintenance",
            ["192.168.12.131", "192.168.12.151"],
            False,
        ),
        ({"192.168.12.131": "inconsistent"}, "maintenance", ["192.168.12.131"], False),
        ({}, "maintenance", ["192.168.12.131"], False),
    ],
    ids=[
        "match-normal-single",
        "diff-want-maint-have-normal",
        "match-maint-two-switches",
        "mixed-state",
        "snapshot-inconsistent",
        "snapshot-empty",
    ],
)
def test_maintenance_mode_model_00060(snapshot_modes: dict, desired_mode: str, switches: list, expected: bool) -> None:
    """
    # Summary

    Verify `get_diff` returns True (no_diff) iff every requested switch already has the desired mode.

    ## Classes and Methods

    - MaintenanceModeModel.get_diff
    """
    snapshot = MaintenanceModeModel.from_response(
        {
            "switches": [{"switch_ip": ip} for ip in switches],
            "switch_modes": snapshot_modes,
        }
    )
    proposed = MaintenanceModeModel.from_config(
        {
            "mode": desired_mode,
            "switches": [{"switch_ip": ip} for ip in switches],
        }
    )
    assert snapshot.get_diff(proposed) is expected


def test_maintenance_mode_model_00070() -> None:
    """
    # Summary

    Verify `get_diff` returns True when proposed has no mode set (defensive — should never happen via
    argspec, but the diff should not POST in that pathological case).

    ## Classes and Methods

    - MaintenanceModeModel.get_diff
    """
    snapshot = MaintenanceModeModel.from_response(
        {
            "switches": [{"switch_ip": "192.168.12.131"}],
            "switch_modes": {"192.168.12.131": "normal"},
        }
    )
    proposed = MaintenanceModeModel()  # mode=None, switches=[]
    assert snapshot.get_diff(proposed) is True


def test_maintenance_mode_model_00075() -> None:
    """
    # Summary

    Verify the custom `get_diff` accepts NDConfigCollection's shared diff
    keyword arguments.

    ## Classes and Methods

    - MaintenanceModeModel.get_diff
    """
    snapshot = MaintenanceModeModel.from_response(
        {
            "switches": [{"switch_ip": "192.168.12.131"}],
            "switch_modes": {"192.168.12.131": "maintenance"},
        }
    )
    proposed = MaintenanceModeModel.from_config(
        {
            "mode": "maintenance",
            "switches": [{"switch_ip": "192.168.12.131"}],
        }
    )
    assert snapshot.get_diff(proposed, exclude_unset=True, allow_superset=True) is True


def test_maintenance_mode_model_00080() -> None:
    """
    # Summary

    Verify `get_diff` returns False when compared against a different type.

    ## Classes and Methods

    - MaintenanceModeModel.get_diff
    """
    snapshot = MaintenanceModeModel.from_response({"switches": [], "switch_modes": {}})
    assert snapshot.get_diff("not a model") is False  # type: ignore[arg-type]


# =============================================================================
# Test: argument spec
# =============================================================================


def test_maintenance_mode_model_00090() -> None:
    """
    # Summary

    Verify argspec shape matches the documented module surface.

    ## Classes and Methods

    - MaintenanceModeModel.get_argument_spec
    """
    spec = MaintenanceModeModel.get_argument_spec()
    assert spec["fabric_name"] == {"type": "str", "required": True}
    assert spec["state"] == {"type": "str", "default": "merged", "choices": ["merged"]}

    config = spec["config"]
    assert config["type"] == "dict"
    assert config["required"] is True

    opts = config["options"]
    assert opts["mode"] == {"type": "str", "required": True, "choices": ["maintenance", "normal"]}
    assert opts["deploy"] == {"type": "bool", "default": False}
    assert opts["blocking"] == {"type": "bool", "default": False}
    assert opts["ticket_id"] == {"type": "str"}

    switches = opts["switches"]
    assert switches["type"] == "list"
    assert switches["elements"] == "dict"
    assert switches["required"] is True
    assert switches["options"]["switch_ip"] == {"type": "str", "required": True}


# =============================================================================
# Test: empty-switches rejection
# =============================================================================


def test_maintenance_mode_model_00100() -> None:
    """
    # Summary

    Verify the model rejects an empty `switches` list when `mode` is set. The Ansible argspec only
    enforces key presence; without this validator a `switches: []` config would silently no-op
    against an action endpoint that requires a non-empty `switchIds` array.

    ## Classes and Methods

    - MaintenanceModeModel._require_switches_when_mode_set
    """
    with pytest.raises(ValueError, match=r"config\.switches must contain at least one switch when 'mode' is set"):
        MaintenanceModeModel.from_config({"mode": "maintenance", "switches": []})


def test_maintenance_mode_model_00110() -> None:
    """
    # Summary

    Verify the empty-switches validator is gated on `mode` so query_all snapshots (which leave `mode`
    unset and may legitimately carry an empty switches list, e.g. when config is missing) still build.

    ## Classes and Methods

    - MaintenanceModeModel._require_switches_when_mode_set
    """
    with does_not_raise():
        snapshot = MaintenanceModeModel.from_response({"switches": [], "switch_modes": {}})
    assert snapshot.mode is None
    assert snapshot.switches == []


def test_maintenance_mode_switch_model_00010() -> None:
    """
    # Summary

    Verify `MaintenanceModeSwitchModel` parses both the Ansible field name and the API alias.

    ## Classes and Methods

    - MaintenanceModeSwitchModel.__init__
    """
    with does_not_raise():
        from_field = MaintenanceModeSwitchModel(switch_ip="192.168.12.131")
        from_alias = MaintenanceModeSwitchModel.model_validate({"switchIp": "192.168.12.131"})
    assert from_field.switch_ip == "192.168.12.131"
    assert from_alias.switch_ip == "192.168.12.131"
