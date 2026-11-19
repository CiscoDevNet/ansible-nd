# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Regression tests for cache invalidation after switch fabric actions."""

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.manage_switches.nd_switch_resources import SwitchFabricOps
from .test_nd_switch_resources import RecordingFinalizeFabricUtils, _ctx, _resource, _sw


class SwitchInventoryTransport:
    """Provide successive inventory snapshots to the real fabric context."""

    def __init__(self, switches):
        self.switches = switches
        self.calls = []
        self.return_code = 200
        self.success = True
        self.response_current = {}
        self.path = None
        self.verb = None

    def commit(self):
        self.calls.append(self.path)
        self.response_current = {"DATA": {"switches": self.switches}}


def test_dirty_exit_invalidates_real_fabric_context_and_reports_fresh_inventory():
    """The after snapshot comes from a second GET, not the pre-mutation cache."""
    before = _sw("192.0.2.10", "SERIAL1")
    after = _sw("192.0.2.11", "SERIAL2")
    transport = SwitchInventoryTransport([before.model_dump(by_alias=True)])
    resource = _resource(existing=[before], output_level="info")
    resource.fabric_context = FabricContext(transport, "FAB1")

    assert [switch.switch_id for switch in resource._load_fabric_switch_inventory().collection] == ["SERIAL1"]
    transport.switches = [after.model_dump(by_alias=True)]
    assert [switch.switch_id for switch in resource._load_fabric_switch_inventory().collection] == ["SERIAL1"]
    assert len(transport.calls) == 1

    resource.ctx.mark_inventory_refresh_needed()
    resource.exit_json()

    assert len(transport.calls) == 2
    assert resource.module.exit_kwargs["before"][0]["seed_ip"] == "192.0.2.10"
    assert resource.module.exit_kwargs["after"][0]["seed_ip"] == "192.0.2.11"


@pytest.mark.parametrize(
    "save,deploy,deploy_type,serials,expected",
    [
        (True, False, "switch", ["SERIAL1"], "config_save"),
        (False, True, "switch", ["SERIAL1"], "deploy_switches"),
        (False, True, "global", [], "deploy_config"),
    ],
)
def test_fabric_save_and_deploy_mark_inventory_for_refresh(save, deploy, deploy_type, serials, expected):
    """Each real finalize action registers its result and invalidates the final inventory snapshot."""
    ctx = _ctx()
    ctx.save_config = save
    ctx.deploy_config = deploy
    ctx.deploy_type = deploy_type
    calls = []
    ops = SwitchFabricOps(ctx, RecordingFinalizeFabricUtils(calls))

    ops.finalize(serial_numbers=serials)

    assert ctx.inventory_refresh_needed is True
    assert ctx.results.metadata[0]["action"] == expected
    assert len(calls) == 1


@pytest.mark.parametrize("check_mode", [False, True])
def test_finalize_without_executed_actions_does_not_mark_inventory(check_mode):
    """No-op and check-mode finalize leave the cached inventory reusable."""
    ctx = _ctx()
    ctx.nd.module.check_mode = check_mode
    ctx.save_config = check_mode
    ctx.deploy_config = check_mode
    calls = []

    SwitchFabricOps(ctx, RecordingFinalizeFabricUtils(calls)).finalize(serial_numbers=["SERIAL1"])

    assert ctx.inventory_refresh_needed is False
    assert calls == []
