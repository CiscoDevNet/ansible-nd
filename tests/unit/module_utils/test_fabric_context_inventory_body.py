# Copyright: (c) 2026, Cisco Systems, Inc. and its affiliates
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Tests for the switch inventory response body used by FabricContext."""

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import PlatformType
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext


class InventoryRestSend:
    """A read-only response source that records the number of requests."""

    def __init__(self, data):
        self.response_current = {"DATA": data}
        self.return_code = 200
        self.success = True
        self.path = None
        self.verb = None
        self.calls = 0

    def commit(self):
        """Record one GET."""
        self.calls += 1


@pytest.mark.parametrize("wrapped", [False, True])
def test_fabric_context_switch_inventory_accepts_bare_and_wrapped_lists(wrapped):
    """Both formats populate raw rows and shared indexes with one cached request."""
    rows = [
        {
            "fabricManagementIp": "192.0.2.10",
            "switchId": "SERIAL1",
            "additionalData": {"platformType": "nx-os", "configSyncStatus": "outOfSync"},
        }
    ]
    rest = InventoryRestSend({"switches": rows} if wrapped else rows)
    context = FabricContext(rest_send=rest, fabric_name="fabric_1")

    assert context.switches == rows
    assert context.get_switch_id("192.0.2.10") == "SERIAL1"
    assert context.get_switch_ip("SERIAL1") == "192.0.2.10"
    assert context.get_platform_type("192.0.2.10") == PlatformType.NX_OS
    assert context.switch_config_in_sync("SERIAL1") is False
    assert rest.calls == 1


def test_fabric_context_accepts_empty_bare_inventory():
    """An empty list is cached as an empty inventory."""
    rest = InventoryRestSend([])
    context = FabricContext(rest_send=rest, fabric_name="fabric_1")
    assert context.switches == []
    assert context.switch_map == {}
    assert rest.calls == 1


@pytest.mark.parametrize("data", ["unexpected", "", 42, 0, {"switches": "unexpected"}, {"switches": ["unexpected"]}, ["unexpected"]])
def test_fabric_context_rejects_invalid_inventory_body(data):
    """An invalid body raises a controller failure that callers can handle."""
    context = FabricContext(rest_send=InventoryRestSend(data), fabric_name="fabric_1")
    with pytest.raises(RuntimeError, match="invalid switch inventory response"):
        context.switches  # pylint: disable=pointless-statement
