# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Regression coverage for incomplete switch discovery responses."""

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.manage_switches.nd_switch_resources import SwitchDiscoveryService
from .test_nd_switch_resources import FailJsonError, _cfg, _ctx, _resource, _sw, FakeND


def _service_for_rows(rows):
    data = {"switches": rows}
    return SwitchDiscoveryService(_ctx(nd=FakeND(data=data, response_current={"DATA": data, "RETURN_CODE": 200})))


@pytest.mark.parametrize(
    "rows,missing",
    [
        ([], ["192.0.2.10", "192.0.2.11"]),
        ([{"ip": "192.0.2.10", "serialNumber": "SERIAL1", "status": "ok"}], ["192.0.2.11"]),
        ([{"ip": "192.0.2.10", "serialNumber": "SERIAL1", "status": "unexpected", "statusReason": "bad"}], ["192.0.2.10", "192.0.2.11"]),
    ],
)
def test_discovery_rejects_missing_or_unusable_requested_switches(rows, missing):
    """An incomplete response identifies every omitted switch rather than returning a partial result."""
    service = _service_for_rows(rows)
    with pytest.raises(FailJsonError, match="Switch discovery did not return usable data") as exc:
        service.discover([_cfg("192.0.2.10"), _cfg("192.0.2.11")])
    assert all(ip in str(exc.value) for ip in missing)


def test_discovery_accepts_complete_requested_switches():
    """Complete discovery results still return the original controller rows."""
    rows = [
        {"ip": "192.0.2.10", "serialNumber": "SERIAL1", "status": "ok"},
        {"ip": "192.0.2.11", "serialNumber": "SERIAL2", "status": "alreadyManaged"},
    ]
    assert _service_for_rows(rows).discover([_cfg("192.0.2.10"), _cfg("192.0.2.11")]) == {row["ip"]: row for row in rows}


@pytest.mark.parametrize("state", ["replaced", "overridden"])
def test_missing_normal_readd_discovery_stops_before_delete_and_sync_deploy(state):
    """A missing reachable POAP re-add cannot delete the old switch or deploy an unrelated one."""
    existing = [
        _sw("192.0.2.10", "OLD", discovery_status="ok"),
        _sw("192.0.2.11", "SYNC", additionalData={"configSyncStatus": "outOfSync", "discoveryStatus": "ok", "systemMode": "normal", "platformType": "nx-os"}),
    ]
    config = [
        {"seed_ip": "192.0.2.10", "username": "admin", "password": "password", "role": "leaf", "poap": {"serial_number": "NEW", "hostname": "new"}},
        {"seed_ip": "192.0.2.11", "username": "admin", "password": "password", "role": "leaf"},
    ]
    resource = _resource(state=state, config=config, existing=existing)
    resource.ctx.deploy_config = True
    data = {"switches": []}
    resource.nd = FakeND(data=data, response_current={"DATA": data, "RETURN_CODE": 200})
    resource.ctx.nd = resource.nd
    resource.discovery = SwitchDiscoveryService(resource.ctx)
    with pytest.raises(FailJsonError, match="192.0.2.10"):
        resource.manage_state()
    assert resource.fabric_ops.deleted == []
    assert resource.fabric_ops.bulk_adds == []
    assert resource.fabric_ops.finalized == []


@pytest.mark.parametrize("state", ["replaced", "overridden"])
def test_missing_post_delete_rediscovery_fails_before_add_or_sync_deploy(state):
    """An update may already be deleted, but failed rediscovery cannot be reported as a successful deployment."""
    existing = [
        _sw("192.0.2.10", "UPDATE", role="leaf"),
        _sw("192.0.2.11", "SYNC", additionalData={"configSyncStatus": "outOfSync", "discoveryStatus": "ok", "systemMode": "normal", "platformType": "nx-os"}),
    ]
    config = [
        {"seed_ip": "192.0.2.10", "username": "admin", "password": "password", "role": "spine"},
        {"seed_ip": "192.0.2.11", "username": "admin", "password": "password", "role": "leaf"},
    ]
    resource = _resource(state=state, config=config, existing=existing)
    resource.ctx.deploy_config = True
    data = {"switches": []}
    resource.nd = FakeND(data=data, response_current={"DATA": data, "RETURN_CODE": 200})
    resource.ctx.nd = resource.nd
    resource.discovery = SwitchDiscoveryService(resource.ctx)
    with pytest.raises(FailJsonError, match="192.0.2.10"):
        resource.manage_state()
    assert [[switch.switch_id for switch in batch] for batch in resource.fabric_ops.deleted] == [["UPDATE"]]
    assert resource.fabric_ops.bulk_adds == []
    assert resource.fabric_ops.finalized == []
