# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for fabric_inventory.py."""

# pylint: disable=missing-function-docstring,too-few-public-methods

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.fabric_inventory import FabricSwitchInventory
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_data_models import SwitchDataModel


class FailJsonError(RuntimeError):
    """Raised by fake module.fail_json."""


class FakeModule:
    """Small AnsibleModule stand-in for unit tests."""

    def fail_json(self, **kwargs):
        raise FailJsonError(kwargs.get("msg", "fail_json called"))


class FakeND:
    """Small NDModule stand-in for inventory query tests."""

    def __init__(self, response=None, exc=None, response_current=None):
        self.module = FakeModule()
        self._response = response
        self._exc = exc
        self.rest_send = SimpleNamespace(response_current=response_current or {"DATA": {}, "RETURN_CODE": 200})
        self.calls = []

    def request(self, *, path, verb):
        self.calls.append((path, verb))
        if self._exc:
            raise self._exc
        return self._response


def _switch(switch_id, ip=None, role="leaf"):
    return SwitchDataModel.from_response(
        {
            "switchId": switch_id,
            "serialNumber": switch_id,
            "fabricManagementIp": ip,
            "switchRole": role,
        }
    )


def test_inventory_indexes_by_ip_and_id_skip_missing_values():
    """FabricSwitchInventory builds useful lookup maps and skips empty identifiers."""
    sw1 = _switch("SERIAL1", "192.0.2.10")
    sw2 = _switch("SERIAL2", None)
    inventory = FabricSwitchInventory([sw1, sw2])

    assert inventory.by_ip() == {"192.0.2.10": sw1}
    assert inventory.by_id() == {"SERIAL1": sw1, "SERIAL2": sw2}


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ([{"switchId": "SERIAL1"}], [{"switchId": "SERIAL1"}]),
        ({"switches": [{"switchId": "SERIAL2"}]}, [{"switchId": "SERIAL2"}]),
        ({"unexpected": []}, []),
        ("unexpected", []),
    ],
)
def test_query_fabric_switches_response_shapes(response, expected):
    """query_fabric_switches accepts both list and {switches: [...]} response shapes."""
    nd = FakeND(response=response)
    log = SimpleNamespace(debug=lambda *args, **kwargs: None, error=lambda *args, **kwargs: None)

    result = FabricSwitchInventory.query_fabric_switches(nd, "FAB1", log)

    assert result == expected
    assert nd.calls[0][0] == "/api/v1/manage/fabrics/FAB1/switches"


def test_query_fabric_switches_request_error_calls_fail_json():
    """Transport/request errors are surfaced through module.fail_json."""
    nd = FakeND(exc=ValueError("boom"))
    log = SimpleNamespace(debug=lambda *args, **kwargs: None, error=lambda *args, **kwargs: None)

    with pytest.raises(FailJsonError, match="Failed to retrieve switch inventory"):
        FabricSwitchInventory.query_fabric_switches(nd, "FAB1", log)


def test_query_fabric_switches_controller_error_calls_fail_json():
    """Controller error payloads are detected via ApiDataChecker."""
    nd = FakeND(
        response={"switches": []},
        response_current={
            "code": 200,
            "message": "Fabric not found",
            "RETURN_CODE": 200,
        },
    )
    log = SimpleNamespace(debug=lambda *args, **kwargs: None, error=lambda *args, **kwargs: None)

    with pytest.raises(FailJsonError, match="Fabric not found"):
        FabricSwitchInventory.query_fabric_switches(nd, "MISSING", log)


def test_from_fabric_builds_collection(monkeypatch):
    """from_fabric fetches raw data and returns an indexed model collection."""
    raw = [
        {"switchId": "SERIAL1", "serialNumber": "SERIAL1", "fabricManagementIp": "192.0.2.10", "switchRole": "leaf"},
        {"switchId": "SERIAL2", "serialNumber": "SERIAL2", "fabricManagementIp": "192.0.2.11", "switchRole": "spine"},
    ]
    monkeypatch.setattr(FabricSwitchInventory, "query_fabric_switches", staticmethod(lambda _nd, _fabric, _log: raw))

    inventory = FabricSwitchInventory.from_fabric(FakeND(), "FAB1", SimpleNamespace(), SwitchDataModel)

    assert inventory.collection is not None
    assert set(inventory.by_ip()) == {"192.0.2.10", "192.0.2.11"}
    assert inventory.by_id()["SERIAL2"].switch_role == "spine"
