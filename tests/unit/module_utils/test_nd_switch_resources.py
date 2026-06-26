# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for manage_switches/nd_switch_resources.py."""

# pylint: disable=missing-function-docstring,protected-access,too-few-public-methods,too-many-lines,too-many-arguments
# pylint: disable=use-implicit-booleaness-not-comparison,unnecessary-lambda,cell-var-from-loop

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.manage_switches.utils import (
    PayloadUtils,
    SwitchWaitUtils,
    SwitchOperationError,
    build_bootstrap_index,
    build_poap_data_block,
    determine_operation_type,
    get_switch_field,
    group_switches_by_credentials,
    mask_password,
    query_bootstrap_switches,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_switches.nd_switch_resources import (
    AddPhaseSpec,
    ApiCallSpec,
    BootstrapCache,
    BulkAddSpec,
    DiscoveryBatchSpec,
    NDSwitchResourceModule,
    POAPHandler,
    PostAddProcessingSpec,
    RMAHandler,
    SwitchDiffEngine,
    SwitchDiscoveryService,
    SwitchFabricOps,
    SwitchPlan,
    SwitchServiceContext,
    _request_with_retry_policy,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.config_models import SwitchConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_data_models import SwitchDataModel
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results


class FailJsonError(RuntimeError):
    """Raised by fake module.fail_json."""


class FakeModule:
    """Small AnsibleModule stand-in for resource tests."""

    check_mode = False

    def __init__(self):
        self.params = {}
        self.exit_kwargs = None

    def fail_json(self, **kwargs):
        raise FailJsonError(kwargs.get("msg", "fail_json called"))

    def exit_json(self, **kwargs):
        self.exit_kwargs = kwargs


class FakeRestSend:
    """RestSend stand-in with mutable retry settings and current result state."""

    def __init__(self):
        self.timeout = 300
        self.send_interval = 5
        self.response_current = {}
        self.result_current = {}


class FakeND:
    """NDModule stand-in that records calls and publishes rest_send state."""

    def __init__(self, data=None, response_current=None, result_current=None, exc=None):
        self.module = FakeModule()
        self.rest_send = FakeRestSend()
        self._data = data if data is not None else {}
        self._response_current = response_current or {"DATA": self._data, "MESSAGE": "OK", "RETURN_CODE": 200}
        self._result_current = result_current or {"success": True, "changed": True}
        self._exc = exc
        self.calls = []

    def _get_rest_send(self):
        return self.rest_send

    def request(self, path=None, *, verb, data=None):
        self.calls.append(
            {
                "path": path,
                "verb": verb,
                "data": data,
                "timeout": self.rest_send.timeout,
                "send_interval": self.rest_send.send_interval,
            }
        )
        if self._exc:
            raise self._exc
        self.rest_send.response_current = self._response_current
        self.rest_send.result_current = self._result_current
        return self._data


class ListLogger:
    """Logger stand-in that records messages without requiring logging setup."""

    def __init__(self):
        self.messages = []

    def debug(self, *args, **kwargs):  # pylint: disable=unused-argument
        self.messages.append(("debug", args))

    def info(self, *args, **kwargs):  # pylint: disable=unused-argument
        self.messages.append(("info", args))

    def warning(self, *args, **kwargs):  # pylint: disable=unused-argument
        self.messages.append(("warning", args))

    def error(self, *args, **kwargs):  # pylint: disable=unused-argument
        self.messages.append(("error", args))


def _cfg(seed_ip="192.0.2.10", role="leaf", state="merged", **overrides):
    data = {"seed_ip": seed_ip, "username": "admin", "password": "password", "role": role}
    data.update(overrides)
    return SwitchConfigModel.model_validate(data, context={"state": state})


def _sw(seed_ip, switch_id, role="leaf", discovery_status="ok", system_mode="normal", **overrides):
    data = {
        "switchId": switch_id,
        "serialNumber": switch_id,
        "fabricManagementIp": seed_ip,
        "hostname": f"{switch_id.lower()}-host",
        "model": "N9K-C93180YC-EX",
        "softwareVersion": "10.3(1)",
        "switchRole": role,
        "additionalData": {
            "discoveryStatus": discovery_status,
            "systemMode": system_mode,
            "platformType": "nx-os",
        },
    }
    data.update(overrides)
    return SwitchDataModel.from_response(data)


def _ctx(nd=None, results=None, log=None):
    return SwitchServiceContext(
        nd=nd or FakeND(),
        results=results or Results(),
        fabric="FAB1",
        log=log or ListLogger(),
        save_config=False,
        deploy_config=False,
    )


def _empty_plan(**overrides):
    data = {
        "to_add": [],
        "to_update": [],
        "to_delete": [],
        "migration_mode": [],
        "idempotent": [],
        "to_bootstrap": [],
        "normal_readd": [],
        "to_preprovision": [],
        "to_swap": [],
        "to_rma": [],
        "poap_ips": set(),
        "to_delete_existing": [],
    }
    data.update(overrides)
    return SwitchPlan(**data)


class RecordingWait:
    """Wait utility stand-in that records waits and can fail."""

    def __init__(self, manageable=True, rma_ready=True):
        self.manageable = manageable
        self.rma_ready = rma_ready
        self.manageable_calls = []
        self.rma_calls = []

    def wait_for_switch_manageable(self, serial_numbers, **kwargs):
        self.manageable_calls.append((list(serial_numbers), kwargs))
        return self.manageable

    def wait_for_rma_switch_ready(self, serial_numbers):
        self.rma_calls.append(list(serial_numbers))
        return self.rma_ready


class RecordingFabricOps:
    """Fabric operation stand-in that records handler orchestration."""

    def __init__(self, fail_finalize=False):
        self.fail_finalize = fail_finalize
        self.post_add_calls = []
        self.saved_credentials = []
        self.role_updates = []
        self.finalized = []
        self.deleted = []
        self.bulk_adds = []

    def post_add_processing(self, spec):
        self.post_add_calls.append(spec)

    def bulk_save_credentials(self, switch_actions):
        self.saved_credentials.append(list(switch_actions))

    def bulk_update_roles(self, switch_actions):
        self.role_updates.append(list(switch_actions))

    def finalize(self, serial_numbers=None):
        if self.fail_finalize:
            raise SwitchOperationError("finalize failed")
        self.finalized.append(list(serial_numbers or []))

    def bulk_delete(self, switches):
        self.deleted.append(list(switches))
        return [sw.switch_id for sw in switches if getattr(sw, "switch_id", None)]

    def bulk_add(self, spec):
        self.bulk_adds.append(spec)


class StaticBootstrapCache:
    """Bootstrap cache stand-in with optional refresh data."""

    def __init__(self, data, refreshed_data=None):
        self.data = data
        self.refreshed_data = refreshed_data if refreshed_data is not None else data
        self.refreshes = 0

    def get_index(self, *, refresh=False):
        if refresh:
            self.refreshes += 1
            return self.refreshed_data
        return self.data


def raise_assertion(message):
    """Raise AssertionError from lambdas assigned to fakes."""
    raise AssertionError(message)


def raise_switch_operation_error(message):
    """Raise SwitchOperationError from lambdas assigned to fakes."""
    raise SwitchOperationError(message)


def _bootstrap_entry(serial="POAP1", hostname="api-host"):
    return {
        "serialNumber": serial,
        "model": "N9K-C93180YC-EX",
        "softwareVersion": "10.3(1)",
        "hostname": hostname,
        "gatewayIpMask": "192.0.2.1/24",
        "fingerPrint": "fingerprint",
        "publicKey": "public-key",
        "switchRole": "spine",
        "data": {"models": ["N9K-C93180YC-EX"], "gatewayIpMask": "192.0.2.1/24"},
    }


def _resource(state="merged", *, config=None, check_mode=False, existing=None, output_level="normal", results=None):
    """Build an NDSwitchResourceModule shell without running its controller-querying constructor."""
    nd = FakeND()
    nd.module.check_mode = check_mode
    nd.module.params = {
        "config": config if config is not None else {},
        "fabric": "FAB1",
        "state": state,
        "output_level": output_level,
    }

    resource = NDSwitchResourceModule.__new__(NDSwitchResourceModule)
    resource.log = ListLogger()
    resource.nd = nd
    resource.module = nd.module
    resource.results = results or Results()
    resource.config = nd.module.params["config"]
    resource.fabric = "FAB1"
    resource.state = state
    resource.ctx = SwitchServiceContext(nd=nd, results=resource.results, fabric="FAB1", log=resource.log, save_config=False, deploy_config=False)

    existing_collection = NDConfigCollection(model_class=SwitchDataModel, items=existing or [])
    resource.proposed = NDConfigCollection(model_class=SwitchDataModel)
    resource.inventory = SimpleNamespace(collection=existing_collection, by_ip=lambda: {sw.fabric_management_ip: sw for sw in existing_collection})
    resource.existing = existing_collection
    resource.before = existing_collection.copy()
    resource.sent = NDConfigCollection(model_class=SwitchDataModel)
    resource.sent_adds = []
    resource.proposed_cfgs = []
    resource._plan = None
    resource.nd_logs = []
    resource.msg = ""
    resource.output = NDOutput(output_level=output_level)
    resource.output.assign(before=resource.before, after=resource.existing)

    resource.discovery = SimpleNamespace(discover=lambda configs: {}, build_proposed=lambda configs, discovered, existing_items: [])
    resource.fabric_ops = RecordingFabricOps()
    resource.poap_handler = SimpleNamespace(handle=lambda configs, existing_items=None: None)
    resource.rma_handler = SimpleNamespace(handle=lambda configs, existing_items: None)
    return resource


def test_request_with_retry_policy_applies_and_restores_settings_on_success_and_error():
    """The local request wrapper makes one short attempt and restores RestSend settings."""
    nd = FakeND(data={"ok": True})

    assert _request_with_retry_policy(nd, path="/x", verb="POST", data={"a": 1}) == {"ok": True}
    assert nd.calls[0]["timeout"] == 1
    assert nd.calls[0]["send_interval"] == 1
    assert (nd.rest_send.timeout, nd.rest_send.send_interval) == (300, 5)

    failing = FakeND(exc=ValueError("boom"))
    with pytest.raises(ValueError, match="boom"):
        _request_with_retry_policy(failing, path="/y", verb="POST")
    assert failing.calls[0]["timeout"] == 1
    assert (failing.rest_send.timeout, failing.rest_send.send_interval) == (300, 5)


def test_switch_service_context_api_call_registers_successful_result():
    """api_call sends through the retry wrapper and records result metadata."""
    results = Results()
    nd = FakeND(data={"ok": True})
    ctx = _ctx(nd=nd, results=results)

    response = ctx.api_call(
        ApiCallSpec(
            endpoint=SimpleNamespace(path="/api/test", verb="POST"),
            payload={"payload": True},
            action="create",
            op_type=OperationType.CREATE,
        )
    )

    assert response["DATA"] == {"ok": True}
    assert nd.calls[0]["timeout"] == 1
    assert results.metadata[0]["action"] == "create"
    assert results.diffs[0]["payload"] is True


def test_switch_service_context_api_call_fails_on_request_error_and_unsuccessful_result():
    """api_call turns request/setup failures and unsuccessful results into fail_json."""
    ctx = _ctx(nd=FakeND(exc=ValueError("request failed")))
    with pytest.raises(FailJsonError, match="create switch: request failed"):
        ctx.api_call(
            ApiCallSpec(
                endpoint=SimpleNamespace(path="/api/test", verb="POST"),
                payload={},
                action="create",
                op_type=OperationType.CREATE,
                context="create switch",
            )
        )

    failed_ctx = _ctx(nd=FakeND(result_current={"success": False}, response_current={"DATA": {}, "MESSAGE": "bad", "RETURN_CODE": 500}))
    with pytest.raises(FailJsonError, match="create switch failed"):
        failed_ctx.api_call(
            ApiCallSpec(
                endpoint=SimpleNamespace(path="/api/test", verb="POST"),
                payload={},
                action="create",
                op_type=OperationType.CREATE,
                context="create switch",
            )
        )


def test_validate_configs_accepts_dict_and_rejects_duplicates():
    """Raw config validation normalizes dict input and rejects duplicate seed IPs."""
    nd = FakeND()
    log = ListLogger()

    configs = SwitchDiffEngine.validate_configs({"seed_ip": "192.0.2.10", "username": "admin", "password": "password"}, "merged", nd, log)
    assert len(configs) == 1
    assert configs[0].role == "leaf"

    with pytest.raises(FailJsonError, match="Duplicate seed_ip"):
        SwitchDiffEngine.validate_configs(
            [
                {"seed_ip": "192.0.2.10", "username": "admin", "password": "password"},
                {"seed_ip": "192.0.2.10", "username": "admin", "password": "password"},
            ],
            "merged",
            nd,
            log,
        )


def test_compute_changes_classifies_normal_switches():
    """Normal switch diffing covers add, update, migration, idempotent, and delete buckets."""
    existing = [
        _sw("192.0.2.10", "IDEMP", role="leaf"),
        _sw("192.0.2.11", "UPDATE", role="spine"),
        _sw("192.0.2.12", "MIGRATE", role="leaf", system_mode="migration"),
        _sw("192.0.2.99", "DELETE", role="leaf"),
    ]
    proposed = [
        _cfg("192.0.2.10", role="leaf"),
        _cfg("192.0.2.11", role="leaf"),
        _cfg("192.0.2.12", role="leaf"),
        _cfg("192.0.2.13", role="leaf"),
    ]

    plan = SwitchDiffEngine.compute_changes(proposed, existing, ListLogger())

    assert [cfg.seed_ip for cfg in plan.idempotent] == ["192.0.2.10"]
    assert [cfg.seed_ip for cfg in plan.to_update] == ["192.0.2.11"]
    assert [cfg.seed_ip for cfg in plan.migration_mode] == ["192.0.2.12"]
    assert [cfg.seed_ip for cfg in plan.to_add] == ["192.0.2.13"]
    assert [sw.switch_id for sw in plan.to_delete] == ["DELETE"]


def test_compute_changes_classifies_poap_preprovision_swap_and_rma():
    """Special operation diffing covers all switch lifecycle buckets."""
    poap_new = _cfg("192.0.2.20", poap={"serial_number": "POAPNEW", "hostname": "poap-new"})
    poap_match = _cfg("192.0.2.21", poap={"serial_number": "POAPMATCH", "hostname": "poap-match"})
    poap_reachable_mismatch = _cfg("192.0.2.22", poap={"serial_number": "POAPNEW2", "hostname": "poap-readd"})
    poap_unreachable_mismatch = _cfg("192.0.2.23", poap={"serial_number": "POAPNEW3", "hostname": "poap-bootstrap"})
    preprov_new = _cfg(
        "192.0.2.30",
        preprovision={
            "serial_number": "PRENEW",
            "model": "N9K-C93180YC-EX",
            "version": "10.3(1)",
            "hostname": "pre-new",
            "config_data": {"models": ["N9K-C93180YC-EX"], "gateway": "192.0.2.1/24"},
        },
    )
    preprov_match = _cfg(
        "192.0.2.31",
        preprovision={
            "serial_number": "PREMATCH",
            "model": "N9K-C93180YC-EX",
            "version": "10.3(1)",
            "hostname": "pre-match",
            "config_data": {"models": ["N9K-C93180YC-EX"], "gateway": "192.0.2.1/24"},
        },
    )
    preprov_unreachable_mismatch = _cfg(
        "192.0.2.32",
        preprovision={
            "serial_number": "PRENEW2",
            "model": "N9K-C93180YC-EX",
            "version": "10.3(1)",
            "hostname": "pre-unreachable",
            "config_data": {"models": ["N9K-C93180YC-EX"], "gateway": "192.0.2.1/24"},
        },
    )
    preprov_reachable_mismatch = _cfg(
        "192.0.2.33",
        preprovision={
            "serial_number": "PRENEW3",
            "model": "N9K-C93180YC-EX",
            "version": "10.3(1)",
            "hostname": "pre-readd",
            "config_data": {"models": ["N9K-C93180YC-EX"], "gateway": "192.0.2.1/24"},
        },
    )
    swap = _cfg(
        "192.0.2.40",
        poap={"serial_number": "SWAPNEW", "hostname": "swap"},
        preprovision={
            "serial_number": "SWAPOLD",
            "model": "N9K-C93180YC-EX",
            "version": "10.3(1)",
            "hostname": "swap",
            "config_data": {"models": ["N9K-C93180YC-EX"], "gateway": "192.0.2.1/24"},
        },
    )
    rma = _cfg("192.0.2.50", rma=[{"new_serial_number": "RMANEW"}])

    existing = [
        _sw("192.0.2.21", "POAPMATCH", hostname="poap-match"),
        _sw("192.0.2.22", "POAPOLD", discovery_status="ok"),
        _sw("192.0.2.23", "POAPOLD2", discovery_status="unreachable"),
        _sw("192.0.2.31", "PREMATCH", hostname="pre-match"),
        _sw("192.0.2.32", "PREOLD", discovery_status="unreachable"),
        _sw("192.0.2.33", "PREOLD2", discovery_status="ok"),
    ]

    plan = SwitchDiffEngine.compute_changes(
        [
            poap_new,
            poap_match,
            poap_reachable_mismatch,
            poap_unreachable_mismatch,
            preprov_new,
            preprov_match,
            preprov_unreachable_mismatch,
            preprov_reachable_mismatch,
            swap,
            rma,
        ],
        existing,
        ListLogger(),
    )

    assert [cfg.seed_ip for cfg in plan.to_bootstrap] == ["192.0.2.20", "192.0.2.23"]
    assert [cfg.seed_ip for cfg in plan.normal_readd] == ["192.0.2.22", "192.0.2.33"]
    assert [cfg.seed_ip for cfg in plan.to_preprovision] == ["192.0.2.30", "192.0.2.32"]
    assert [cfg.seed_ip for cfg in plan.idempotent] == ["192.0.2.21", "192.0.2.31"]
    assert [cfg.seed_ip for cfg in plan.to_swap] == ["192.0.2.40"]
    assert [cfg.seed_ip for cfg in plan.to_rma] == ["192.0.2.50"]
    assert {sw.fabric_management_ip for sw in plan.to_delete_existing} == {"192.0.2.22", "192.0.2.23", "192.0.2.32", "192.0.2.33"}


def test_bootstrap_cache_caches_refreshes_and_invalidates(monkeypatch):
    """BootstrapCache queries once, refreshes on demand, and can be invalidated."""
    calls = []

    def fake_query(_nd, fabric, _log):
        calls.append(fabric)
        return [{"serialNumber": f"SERIAL{len(calls)}"}]

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_switches.nd_switch_resources.query_bootstrap_switches",
        fake_query,
    )
    cache = BootstrapCache(FakeND(), "FAB1", ListLogger())

    assert cache.get_index() == {"SERIAL1": {"serialNumber": "SERIAL1"}}
    assert cache.get_index() == {"SERIAL1": {"serialNumber": "SERIAL1"}}
    assert calls == ["FAB1"]
    assert cache.get_index(refresh=True) == {"SERIAL2": {"serialNumber": "SERIAL2"}}
    cache.invalidate()
    assert cache.get_index() == {"SERIAL3": {"serialNumber": "SERIAL3"}}


def test_bulk_discover_success_and_not_reachable_failure():
    """Bulk discovery extracts switches and fails early on notReachable API data."""
    success_data = {"switches": [{"ip": "192.0.2.10", "serialNumber": "SERIAL1", "status": "ok", "hostname": "leaf1"}]}
    service = SwitchDiscoveryService(_ctx(nd=FakeND(data=success_data, response_current={"DATA": success_data, "RETURN_CODE": 200})))

    result = service.bulk_discover(
        DiscoveryBatchSpec(
            switches=[_cfg("192.0.2.10")],
            username="admin",
            password="password",
            auth_proto="MD5",
            platform_type="nx-os",
        )
    )

    assert result["192.0.2.10"]["serialNumber"] == "SERIAL1"

    failure_data = {"warning": "not reachable", "switches": [{"ip": "192.0.2.11", "status": "notReachable"}]}
    failing_service = SwitchDiscoveryService(_ctx(nd=FakeND(data=failure_data, response_current={"DATA": failure_data, "RETURN_CODE": 200})))
    with pytest.raises(FailJsonError, match="Switch discovery failed: not reachable"):
        failing_service.bulk_discover(
            DiscoveryBatchSpec(
                switches=[_cfg("192.0.2.11")],
                username="admin",
                password="password",
                auth_proto="MD5",
                platform_type="nx-os",
            )
        )


def test_switch_fabric_ops_bulk_add_delete_credentials_roles_and_finalize():
    """SwitchFabricOps records expected API calls for common fabric operations."""
    ctx = _ctx(results=Results())
    fabric_ops = SwitchFabricOps(ctx, fabric_utils=SimpleNamespace(save_config=lambda: None, deploy_switches=lambda serials: None, deploy_config=lambda: None))

    fabric_ops.bulk_add(
        BulkAddSpec(
            switches=[
                (
                    _cfg("192.0.2.10"),
                    {
                        "hostname": "leaf1",
                        "ip": "192.0.2.10",
                        "serialNumber": "SERIAL1",
                        "model": "N9K-C93180YC-EX",
                        "softwareVersion": "10.3(1)",
                    },
                )
            ],
            username="admin",
            password="password",
            auth_proto="MD5",
            platform_type="nx-os",
            preserve_config=False,
        )
    )
    assert ctx.results.metadata[-1]["action"] == "create"

    deleted = fabric_ops.bulk_delete([_sw("192.0.2.10", "SERIAL1")])
    assert deleted == ["SERIAL1"]
    assert ctx.results.metadata[-1]["action"] == "delete"

    fabric_ops.bulk_save_credentials([("SERIAL1", _cfg("192.0.2.10"))])
    assert ctx.results.metadata[-1]["action"] == "save_credentials"

    fabric_ops.bulk_update_roles([("SERIAL1", _cfg("192.0.2.10", role="spine"))])
    assert ctx.results.metadata[-1]["action"] == "update_role"

    fabric_ops.finalize(["SERIAL1"])


def test_switch_fabric_ops_bulk_delete_without_serial_is_noop_and_bulk_add_validates_discovery_fields():
    """Fabric ops fail fast for invalid add data and ignore delete entries without serials."""
    fabric_ops = SwitchFabricOps(
        _ctx(), fabric_utils=SimpleNamespace(save_config=lambda: None, deploy_switches=lambda serials: None, deploy_config=lambda: None)
    )

    assert fabric_ops.bulk_delete([SimpleNamespace(fabric_management_ip="192.0.2.10")]) == []

    with pytest.raises(FailJsonError, match="Switch missing required fields"):
        fabric_ops.bulk_add(
            BulkAddSpec(
                switches=[(_cfg("192.0.2.10"), {"ip": "192.0.2.10"})],
                username="admin",
                password="password",
                auth_proto="MD5",
                platform_type="nx-os",
                preserve_config=False,
            )
        )


def test_switch_fabric_ops_bulk_delete_wraps_api_failures():
    """Delete API failures are raised as SwitchOperationError."""
    fabric_ops = SwitchFabricOps(_ctx(nd=FakeND(exc=ValueError("transport down"))), fabric_utils=SimpleNamespace())

    with pytest.raises(SwitchOperationError, match="Bulk delete failed"):
        fabric_ops.bulk_delete([_sw("192.0.2.10", "SERIAL1")])


def test_bulk_discover_rejects_not_manageable_and_missing_identifiers():
    """Discovery fails early for unusable controller response rows."""
    not_manageable = {"switches": [{"ip": "192.0.2.20", "serialNumber": "BAD1", "status": "notManageable", "statusReason": "unsupported"}]}
    service = SwitchDiscoveryService(_ctx(nd=FakeND(data=not_manageable, response_current={"DATA": not_manageable, "RETURN_CODE": 200})))
    with pytest.raises(FailJsonError, match="not manageable: unsupported"):
        service.bulk_discover(DiscoveryBatchSpec([_cfg("192.0.2.20")], "admin", "password", "MD5", "nx-os"))

    missing_serial = {"switches": [{"ip": "192.0.2.21", "status": "ok"}]}
    service = SwitchDiscoveryService(_ctx(nd=FakeND(data=missing_serial, response_current={"DATA": missing_serial, "RETURN_CODE": 200})))
    with pytest.raises(FailJsonError, match="missing serial number"):
        service.bulk_discover(DiscoveryBatchSpec([_cfg("192.0.2.21")], "admin", "password", "MD5", "nx-os"))

    missing_ip = {"switches": [{"serialNumber": "NOIP", "status": "ok"}]}
    service = SwitchDiscoveryService(_ctx(nd=FakeND(data=missing_ip, response_current={"DATA": missing_ip, "RETURN_CODE": 200})))
    with pytest.raises(FailJsonError, match="missing IP address"):
        service.bulk_discover(DiscoveryBatchSpec([_cfg("192.0.2.22")], "admin", "password", "MD5", "nx-os"))


def test_discover_groups_credentials_and_build_proposed_fallbacks(monkeypatch):
    """Discovery groups by credentials and proposed models use discovery or existing inventory."""
    service = SwitchDiscoveryService(_ctx())
    seen_batches = []

    def fake_bulk_discover(spec):
        seen_batches.append([sw.seed_ip for sw in spec.switches])
        return {
            sw.seed_ip: {"ip": sw.seed_ip, "serialNumber": f"SERIAL-{idx}", "hostname": f"host-{idx}", "role": "leaf"} for idx, sw in enumerate(spec.switches)
        }

    monkeypatch.setattr(service, "bulk_discover", fake_bulk_discover)
    discovered = service.discover([_cfg("192.0.2.10"), _cfg("192.0.2.11", username="other")])

    assert sorted(discovered) == ["192.0.2.10", "192.0.2.11"]
    assert seen_batches == [["192.0.2.10"], ["192.0.2.11"]]

    existing = [_sw("192.0.2.12", "EXISTING", role="leaf")]
    proposed = service.build_proposed(
        [_cfg("192.0.2.10", role="spine"), _cfg("192.0.2.12", role="border")],
        {"192.0.2.10": {"ip": "192.0.2.10", "serialNumber": "NEW1", "hostname": "new1", "role": "leaf"}},
        existing,
    )
    assert [sw.switch_id for sw in proposed] == ["NEW1", "EXISTING"]
    assert [sw.switch_role for sw in proposed] == ["spine", "border"]

    with pytest.raises(FailJsonError, match="not discovered and not found"):
        service.build_proposed([_cfg("192.0.2.99")], {}, existing)


def test_post_add_processing_waits_saves_updates_roles_and_finalize_paths():
    """Post-add processing covers wait kwargs, role update, finalize, and failure branches."""
    ctx = _ctx()
    ops = SwitchFabricOps(ctx, fabric_utils=SimpleNamespace(save_config=lambda: None, deploy_switches=lambda serials: None, deploy_config=lambda: None))
    wait = RecordingWait()
    ops.post_add_processing(
        PostAddProcessingSpec(
            switch_actions=[("SERIAL1", _cfg("192.0.2.10", preserve_config=True))],
            wait_utils=wait,
            context="merged",
            all_preserve_config=True,
            skip_greenfield_check=True,
            update_roles=True,
        )
    )
    assert wait.manageable_calls == [(["SERIAL1"], {"all_preserve_config": True, "skip_greenfield_check": True})]
    assert [entry["action"] for entry in ctx.results.metadata] == ["save_credentials", "update_role"]

    failing_wait = RecordingWait(manageable=False)
    with pytest.raises(FailJsonError, match="failed to become manageable"):
        ops.post_add_processing(PostAddProcessingSpec([("SERIAL2", _cfg("192.0.2.11"))], failing_wait, "merged"))

    bad_finalize_ops = SwitchFabricOps(
        _ctx(nd=FakeND()),
        fabric_utils=SimpleNamespace(
            save_config=lambda: raise_switch_operation_error("save failed"),
            deploy_switches=lambda serials: None,
            deploy_config=lambda: None,
        ),
    )
    bad_finalize_ops.ctx.save_config = True
    with pytest.raises(FailJsonError, match="Failed to finalize"):
        bad_finalize_ops.post_add_processing(PostAddProcessingSpec([("SERIAL3", _cfg("192.0.2.12"))], RecordingWait(), "merged"))


def test_fabric_ops_finalize_honors_switch_and_global_deploy_modes():
    """Finalize chooses save, switch deploy, global deploy, and check-mode no-op correctly."""
    calls = []
    fabric_utils = SimpleNamespace(
        save_config=lambda: calls.append(("save", None)),
        deploy_switches=lambda serials: calls.append(("deploy_switches", list(serials))),
        deploy_config=lambda: calls.append(("deploy_config", None)),
    )
    ctx = SwitchServiceContext(FakeND(), Results(), "FAB1", ListLogger(), save_config=True, deploy_config=True, deploy_type="switch")
    SwitchFabricOps(ctx, fabric_utils).finalize(["SERIAL1"])
    assert calls == [("save", None), ("deploy_switches", ["SERIAL1"])]

    calls.clear()
    ctx.deploy_type = "global"
    SwitchFabricOps(ctx, fabric_utils).finalize(["SERIAL1"])
    assert calls == [("save", None), ("deploy_config", None)]

    calls.clear()
    ctx.nd.module.check_mode = True
    SwitchFabricOps(ctx, fabric_utils).finalize(["SERIAL1"])
    assert calls == []


def test_poap_handler_check_mode_noop_and_bootstrap_not_found():
    """POAP handler records check-mode previews and fails when serial is absent from bootstrap."""
    nd = FakeND()
    nd.module.check_mode = True
    ctx = _ctx(nd=nd, results=Results())
    handler = POAPHandler(ctx, RecordingFabricOps(), RecordingWait(), StaticBootstrapCache({}))
    handler.handle([_cfg("192.0.2.10", poap={"serial_number": "POAP1", "hostname": "poap1"})])
    assert ctx.results.metadata[0]["action"] == "poap"
    assert ctx.results.diffs[0]["bootstrap"] == ["192.0.2.10"]

    nd = FakeND()
    handler = POAPHandler(_ctx(nd=nd), RecordingFabricOps(), RecordingWait(), StaticBootstrapCache({}))
    with pytest.raises(FailJsonError, match="not found in bootstrap API"):
        handler.handle([_cfg("192.0.2.10", poap={"serial_number": "POAP1", "hostname": "poap1"})])


def test_poap_handler_builds_and_submits_bootstrap_preprovision_and_swap():
    """POAP workflow submits bootstrap, preprovision, and serial-swap calls."""
    bootstrap = _bootstrap_entry("POAP1")
    ctx = _ctx(results=Results())
    fabric_ops = RecordingFabricOps()
    handler = POAPHandler(ctx, fabric_ops, RecordingWait(), StaticBootstrapCache({"POAP1": bootstrap}))

    handler.handle([_cfg("192.0.2.10", poap={"serial_number": "POAP1", "hostname": "user-host"})])
    assert ctx.results.metadata[-1]["action"] == "bootstrap"
    assert ctx.results.diffs[-1]["switches"][0]["hostname"] == "api-host"
    assert ctx.results.diffs[-1]["switches"][0]["switchRole"] == "spine"
    assert fabric_ops.post_add_calls[-1].context == "bootstrap"

    preprov_cfg = _cfg(
        "192.0.2.20",
        preprovision={
            "serial_number": "PRE1",
            "model": "N9K-C93180YC-EX",
            "version": "10.3(1)",
            "hostname": "pre1",
            "config_data": {"models": ["N9K-C93180YC-EX"], "gateway": "192.0.2.1/24"},
        },
    )
    handler.handle([preprov_cfg])
    assert ctx.results.metadata[-1]["action"] == "preprovision"
    assert ctx.results.diffs[-1]["switches"][0]["serialNumber"] == "PRE1"

    swap_cfg = _cfg(
        "192.0.2.30",
        poap={"serial_number": "NEW1", "hostname": "swap"},
        preprovision={
            "serial_number": "OLD1",
            "model": "N9K-C93180YC-EX",
            "version": "10.3(1)",
            "hostname": "swap",
            "config_data": {"models": ["N9K-C93180YC-EX"], "gateway": "192.0.2.1/24"},
        },
    )
    cache = StaticBootstrapCache({"NEW1": _bootstrap_entry("NEW1")}, {"NEW1": _bootstrap_entry("NEW1", hostname="new-api")})
    swap_handler = POAPHandler(_ctx(results=Results()), RecordingFabricOps(), RecordingWait(), cache)
    swap_handler.handle([swap_cfg], [_sw("192.0.2.30", "OLD1")])
    assert cache.refreshes == 1
    assert [entry["action"] for entry in swap_handler.ctx.results.metadata] == ["swap_serial", "bootstrap"]


def test_poap_handler_requires_bootstrap_identity_fields():
    """POAP bootstrap import fails clearly when call-home identity fields are missing."""
    missing_public_key = _bootstrap_entry("POAP1")
    missing_public_key.pop("publicKey")
    nd = FakeND()
    handler = POAPHandler(_ctx(nd=nd), RecordingFabricOps(), RecordingWait(), StaticBootstrapCache({"POAP1": missing_public_key}))
    with pytest.raises(FailJsonError, match="POAP1.*publicKey.*finish calling home"):
        handler.handle([_cfg("192.0.2.10", poap={"serial_number": "POAP1", "hostname": "poap1"})])
    assert nd.calls == []

    lowercase_fingerprint = _bootstrap_entry("POAP2")
    lowercase_fingerprint["fingerprint"] = lowercase_fingerprint.pop("fingerPrint")
    nd = FakeND()
    handler = POAPHandler(_ctx(nd=nd), RecordingFabricOps(), RecordingWait(), StaticBootstrapCache({"POAP2": lowercase_fingerprint}))
    handler.handle([_cfg("192.0.2.20", poap={"serial_number": "POAP2", "hostname": "poap2"})])
    assert len(nd.calls) == 1


def test_poap_swap_validates_old_and_new_serials():
    """Serial swap fails before API calls when inventory/bootstrap prerequisites are missing."""
    swap_cfg = _cfg(
        "192.0.2.30",
        poap={"serial_number": "NEW1", "hostname": "swap"},
        preprovision={
            "serial_number": "OLD1",
            "model": "N9K-C93180YC-EX",
            "version": "10.3(1)",
            "hostname": "swap",
            "config_data": {"models": ["N9K-C93180YC-EX"], "gateway": "192.0.2.1/24"},
        },
    )
    handler = POAPHandler(_ctx(), RecordingFabricOps(), RecordingWait(), StaticBootstrapCache({"NEW1": _bootstrap_entry("NEW1")}))
    with pytest.raises(FailJsonError, match="OLD1.*not found"):
        handler.handle([swap_cfg], [])

    handler = POAPHandler(_ctx(), RecordingFabricOps(), RecordingWait(), StaticBootstrapCache({}))
    with pytest.raises(FailJsonError, match="NEW1.*not found"):
        handler.handle([swap_cfg], [_sw("192.0.2.30", "OLD1")])


def test_rma_handler_check_mode_empty_success_and_prerequisite_failures():
    """RMA handler covers check-mode, no-op, and prerequisite validation failures."""
    nd = FakeND()
    nd.module.check_mode = True
    ctx = _ctx(nd=nd, results=Results())
    handler = RMAHandler(ctx, RecordingFabricOps(), RecordingWait(), StaticBootstrapCache({}))
    handler.handle([_cfg("192.0.2.10", rma=[{"new_serial_number": "NEW1"}])], [])
    assert ctx.results.metadata[0]["action"] == "rma"
    assert ctx.results.diffs[0]["rma_switches"] == ["192.0.2.10"]

    ctx = _ctx(results=Results())
    handler = RMAHandler(ctx, RecordingFabricOps(), RecordingWait(), StaticBootstrapCache({}))
    handler.handle([_cfg("192.0.2.11")], [])
    assert ctx.results.metadata[0]["action"] == "rma"
    assert ctx.results.diffs[0]["sequence_number"] == 1

    handler = RMAHandler(_ctx(), RecordingFabricOps(), RecordingWait(), StaticBootstrapCache({"NEW1": _bootstrap_entry("NEW1")}))
    with pytest.raises(FailJsonError, match="not found in fabric"):
        handler.handle([_cfg("192.0.2.12", rma=[{"new_serial_number": "NEW1"}])], [])

    old_switch = _sw("192.0.2.12", "OLD1", discovery_status="ok", system_mode="maintenance")
    with pytest.raises(FailJsonError, match="expected 'unreachable'"):
        handler.handle([_cfg("192.0.2.12", rma=[{"new_serial_number": "NEW1"}])], [old_switch])

    old_switch = _sw("192.0.2.12", "OLD1", discovery_status="unreachable", system_mode="normal")
    with pytest.raises(FailJsonError, match="expected 'maintenance'"):
        handler.handle([_cfg("192.0.2.12", rma=[{"new_serial_number": "NEW1"}])], [old_switch])


def test_rma_handler_requires_bootstrap_identity_fields():
    """RMA provisioning fails clearly when call-home identity fields are missing."""
    old_switch = _sw("192.0.2.12", "OLD1", discovery_status="unreachable", system_mode="maintenance", hostname="old-host")
    missing_fingerprint = _bootstrap_entry("NEW1")
    missing_fingerprint.pop("fingerPrint")
    nd = FakeND()
    handler = RMAHandler(_ctx(nd=nd), RecordingFabricOps(), RecordingWait(), StaticBootstrapCache({"NEW1": missing_fingerprint}))
    with pytest.raises(FailJsonError, match="NEW1.*fingerPrint.*finish calling home"):
        handler.handle([_cfg("192.0.2.12", rma=[{"new_serial_number": "NEW1"}])], [old_switch])
    assert nd.calls == []


def test_rma_handler_full_success_and_ready_finalize_failures():
    """RMA success submits provision, waits for replacement, saves credentials, and finalizes."""
    old_switch = _sw("192.0.2.12", "OLD1", discovery_status="unreachable", system_mode="maintenance", hostname="old-host")
    cfg = _cfg("192.0.2.12", rma=[{"new_serial_number": "NEW1", "image_policy": "gold"}])
    fabric_ops = RecordingFabricOps()
    wait = RecordingWait()
    ctx = _ctx(results=Results())
    handler = RMAHandler(ctx, fabric_ops, wait, StaticBootstrapCache({"NEW1": _bootstrap_entry("NEW1")}))

    handler.handle([cfg], [old_switch])

    assert ctx.results.metadata[0]["action"] == "rma"
    assert ctx.results.diffs[0]["old_switch_id"] == "OLD1"
    assert ctx.results.diffs[0]["new_switch_id"] == "NEW1"
    assert wait.rma_calls == [["NEW1"]]
    assert fabric_ops.saved_credentials == [[("NEW1", cfg)]]
    assert fabric_ops.finalized == [["NEW1"]]

    handler = RMAHandler(_ctx(), RecordingFabricOps(), RecordingWait(rma_ready=False), StaticBootstrapCache({"NEW1": _bootstrap_entry("NEW1")}))
    with pytest.raises(FailJsonError, match="failed to become discoverable"):
        handler.handle([cfg], [old_switch])

    handler = RMAHandler(_ctx(), RecordingFabricOps(fail_finalize=True), RecordingWait(), StaticBootstrapCache({"NEW1": _bootstrap_entry("NEW1")}))
    with pytest.raises(FailJsonError, match="Failed to finalize"):
        handler.handle([cfg], [old_switch])


def test_resource_module_check_mode_output_and_deleted_state():
    """Thin resource helpers build check-mode output and deleted-state metadata."""
    resource = NDSwitchResourceModule.__new__(NDSwitchResourceModule)
    nd = FakeND()
    nd.module.check_mode = True
    nd.module.params = {"output_level": "info"}
    existing = [_sw("192.0.2.10", "SERIAL1"), _sw("192.0.2.11", "SERIAL2", role="spine")]
    resource.nd = nd
    resource.module = nd.module
    resource.results = Results()
    resource.log = ListLogger()
    resource.fabric = "FAB1"
    resource.state = "deleted"
    resource.before = NDConfigCollection(model_class=SwitchDataModel, items=existing)
    resource.existing = NDConfigCollection(model_class=SwitchDataModel, items=existing)
    resource.inventory = SimpleNamespace(by_ip=lambda: {sw.fabric_management_ip: sw for sw in existing})
    resource.sent = NDConfigCollection(model_class=SwitchDataModel)
    resource.sent_adds = []
    resource.proposed_cfgs = [_cfg("192.0.2.10", state="deleted")]
    resource._plan = _empty_plan()
    resource.msg = ""
    resource.nd_logs = []

    resource._handle_deleted_state([_cfg("192.0.2.10", state="deleted")])
    assert resource.results.metadata[0]["action"] == "delete"
    assert resource.results.diffs[0]["to_delete"] == ["192.0.2.10"]

    output = resource._build_check_mode_output()
    assert output["changed"] is True
    assert output["diff"] == [{"seed_ip": "192.0.2.10", "role": "leaf", "_action": "deleted"}]
    assert output["after"] == [
        {"seed_ip": "192.0.2.11", "role": "spine", "auth_proto": "MD5", "preserve_config": False, "username": "<username>", "password": "<password>"}
    ]


def test_execute_add_phase_handles_bulk_add_migration_and_wait_processing():
    """The shared add phase groups additions, appends migration switches, and post-processes serials."""
    resource = NDSwitchResourceModule.__new__(NDSwitchResourceModule)
    resource.log = ListLogger()
    resource.wait_utils = RecordingWait()
    resource.fabric_ops = RecordingFabricOps()
    resource.sent_adds = []
    resource.nd_logs = []
    resource._log_operation = lambda operation, identifier: resource.nd_logs.append({"operation": operation, "identifier": identifier})

    cfg_add = _cfg("192.0.2.10", preserve_config=True)
    cfg_migrate = _cfg("192.0.2.11", role="spine", preserve_config=True)
    existing = _sw("192.0.2.11", "MIGRATE", system_mode="migration")
    plan = _empty_plan(migration_mode=[cfg_migrate])
    actions = resource._execute_add_phase(
        AddPhaseSpec(
            add_configs=[cfg_add],
            plan=plan,
            discovered_data={
                "192.0.2.10": {
                    "hostname": "leaf1",
                    "ip": "192.0.2.10",
                    "serialNumber": "ADD1",
                    "model": "N9K-C93180YC-EX",
                    "softwareVersion": "10.3(1)",
                }
            },
            existing_by_ip={"192.0.2.11": existing},
            context="merged",
        )
    )

    assert actions == [("ADD1", cfg_add), ("MIGRATE", cfg_migrate)]
    assert len(resource.fabric_ops.bulk_adds) == 1
    assert resource.fabric_ops.post_add_calls[0].update_roles is True
    assert resource.fabric_ops.post_add_calls[0].all_preserve_config is True


def test_manage_state_routes_gathered_deleted_and_required_config_paths():
    """manage_state validates simple states and routes them to their thin handlers."""
    with pytest.raises(FailJsonError, match="must not be provided"):
        _resource(state="gathered", config=[{"seed_ip": "192.0.2.10"}]).manage_state()

    gathered_calls = []
    resource = _resource(state="gathered")
    resource._handle_gathered_state = lambda: gathered_calls.append("gathered")
    resource.manage_state()
    assert gathered_calls == ["gathered"]

    deleted_calls = []
    resource = _resource(state="deleted", config=[{"seed_ip": "192.0.2.10", "role": "leaf"}])
    resource._handle_deleted_state = lambda proposed: deleted_calls.append(proposed)
    resource.manage_state()
    assert len(deleted_calls[0]) == 1
    assert deleted_calls[0][0].seed_ip == "192.0.2.10"

    resource = _resource(state="overridden")
    resource._handle_deleted_state = lambda proposed: deleted_calls.append(proposed)
    resource.manage_state()
    assert deleted_calls[-1] is None

    with pytest.raises(FailJsonError, match="'config' is required"):
        _resource(state="merged").manage_state()
    with pytest.raises(FailJsonError, match="'config' is required"):
        _resource(state="replaced").manage_state()


def test_manage_state_enforces_rma_state_constraint_and_unsupported_state():
    """manage_state rejects RMA outside merged and unsupported states after validation."""
    rma_config = [{"seed_ip": "192.0.2.10", "username": "admin", "password": "password", "rma": [{"new_serial_number": "NEW1"}]}]
    with pytest.raises(FailJsonError, match="RMA operations require 'merged' state"):
        _resource(state="replaced", config=rma_config).manage_state()

    resource = _resource(state="unknown", config=[{"seed_ip": "192.0.2.10", "username": "admin", "password": "password"}])
    with pytest.raises(FailJsonError, match="Unsupported state"):
        resource.manage_state()


def test_manage_state_discovers_builds_proposed_and_dispatches_merged():
    """manage_state performs validation, diffing, discovery, proposed build, and merged dispatch."""
    config = [{"seed_ip": "192.0.2.10", "username": "admin", "password": "password", "role": "leaf"}]
    resource = _resource(state="merged", config=config)
    calls = {"discover": [], "build": [], "merged": []}

    def fake_discover(configs):
        calls["discover"].append([cfg.seed_ip for cfg in configs])
        return {
            "192.0.2.10": {
                "ip": "192.0.2.10",
                "serialNumber": "SERIAL1",
                "hostname": "leaf1",
                "role": "leaf",
                "model": "N9K-C93180YC-EX",
                "softwareVersion": "10.3(1)",
            }
        }

    def fake_build(configs, discovered, existing):
        calls["build"].append(([cfg.seed_ip for cfg in configs], sorted(discovered), list(existing)))
        return [_sw("192.0.2.10", "SERIAL1")]

    resource.discovery = SimpleNamespace(discover=fake_discover, build_proposed=fake_build)
    resource._handle_merged_state = lambda plan, discovered: calls["merged"].append((plan, discovered))

    resource.manage_state()

    assert calls["discover"] == [["192.0.2.10"]]
    assert calls["build"][0][0] == ["192.0.2.10"]
    assert calls["build"][0][1] == ["192.0.2.10"]
    assert calls["merged"][0][0].to_add[0].seed_ip == "192.0.2.10"
    assert calls["merged"][0][1]["192.0.2.10"]["serialNumber"] == "SERIAL1"
    assert [sw.switch_id for sw in resource.proposed] == ["SERIAL1"]


def test_manage_state_check_mode_skips_discovery_and_routes_all_mutating_states():
    """Check mode does not discover new switches and dispatches merged/replaced/overridden handlers."""
    config = [{"seed_ip": "192.0.2.10", "username": "admin", "password": "password", "role": "leaf"}]
    for state, handler_name in (("merged", "_handle_merged_state"), ("replaced", "_handle_replaced_state"), ("overridden", "_handle_overridden_state")):
        resource = _resource(state=state, config=config, check_mode=True)
        calls = []

        def discover(_configs):
            raise AssertionError("discovery should be skipped in check mode")

        resource.discovery = SimpleNamespace(discover=discover, build_proposed=lambda configs, discovered, existing: [])
        setattr(resource, handler_name, lambda plan, discovered, state=state: calls.append((state, plan, discovered)))
        resource.manage_state()

        assert calls[0][0] == state
        assert calls[0][1].to_add[0].seed_ip == "192.0.2.10"
        assert calls[0][2] == {}
        assert list(resource.proposed) == []


def test_exit_json_gathered_outputs_existing_inventory_without_requery():
    """exit_json gathered branch converts existing inventory into gathered config output."""
    resource = _resource(state="gathered", existing=[_sw("192.0.2.10", "SERIAL1")], output_level="info")
    resource._handle_gathered_state()
    resource.exit_json()

    final = resource.module.exit_kwargs
    assert final["changed"] is False
    assert final["gathered"][0]["seed_ip"] == "192.0.2.10"
    assert final["gathered"][0]["password"] == "<password>"
    assert final["after"][0]["switch_id"] == "SERIAL1"


def test_exit_json_check_mode_uses_synthetic_before_after_diff():
    """exit_json check-mode branch delegates to the synthetic check-mode output builder."""
    existing = [_sw("192.0.2.10", "SERIAL1")]
    resource = _resource(state="merged", config=[{"seed_ip": "192.0.2.11", "username": "admin", "password": "password"}], check_mode=True, existing=existing)
    cfg = _cfg("192.0.2.11")
    resource.proposed_cfgs = [cfg]
    resource._plan = _empty_plan(to_add=[cfg])
    resource.exit_json()

    final = resource.module.exit_kwargs
    assert final["changed"] is True
    assert final["before"][0]["seed_ip"] == "192.0.2.10"
    assert final["after"][1]["seed_ip"] == "192.0.2.11"
    assert final["diff"][0]["_action"] == "added"


def test_exit_json_normal_requeries_inventory_and_builds_delete_add_diff(monkeypatch):
    """exit_json normal branch re-queries successful runs and combines delete/add diffs."""
    before = [_sw("192.0.2.10", "SERIAL1")]
    after = [_sw("192.0.2.11", "SERIAL2")]
    resource = _resource(state="merged", existing=before, output_level="info")
    resource.sent.add(before[0])
    resource.sent_adds.append(_cfg("192.0.2.11"))
    resource.proposed_cfgs = [_cfg("192.0.2.11")]
    resource.results.action = "create"
    resource.results.operation_type = OperationType.CREATE
    resource.results.response_current = {"MESSAGE": "created"}
    resource.results.result_current = {"success": True, "changed": True}
    resource.results.diff_current = {"created": ["SERIAL2"]}
    resource.results.register_api_call()

    requery_calls = []

    def fake_from_fabric(nd, fabric, log, model_class):  # pylint: disable=unused-argument
        requery_calls.append(fabric)
        return SimpleNamespace(collection=NDConfigCollection(model_class=SwitchDataModel, items=after))

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_switches.nd_switch_resources.FabricSwitchInventory.from_fabric",
        fake_from_fabric,
    )

    resource.exit_json()

    final = resource.module.exit_kwargs
    assert requery_calls == ["FAB1"]
    assert final["changed"] is True
    assert final["before"][0]["seed_ip"] == "192.0.2.10"
    assert final["after"][0]["seed_ip"] == "192.0.2.11"
    assert [entry["_action"] for entry in final["diff"]] == ["deleted", "added"]
    assert final["proposed"][0]["seed_ip"] == "192.0.2.11"


def test_exit_json_failed_results_skip_requery_and_fail_json(monkeypatch):
    """Failed aggregated results are returned through fail_json and do not re-query inventory."""
    resource = _resource(state="merged", existing=[_sw("192.0.2.10", "SERIAL1")])
    resource.results.action = "create"
    resource.results.operation_type = OperationType.CREATE
    resource.results.response_current = {"MESSAGE": "bad"}
    resource.results.result_current = {"success": False, "changed": False}
    resource.results.diff_current = {"attempted": True}
    resource.results.register_api_call()

    def fail_from_fabric(*_args, **_kwargs):
        raise AssertionError("failed runs should not re-query inventory")

    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.manage_switches.nd_switch_resources.FabricSwitchInventory.from_fabric",
        fail_from_fabric,
    )

    with pytest.raises(FailJsonError):
        resource.exit_json()


def test_utils_payload_masking_and_payload_builders_do_not_mutate_input():
    """Payload helpers build simple payloads and mask credentials on a deep copy."""
    payload = {
        "password": "top-secret",
        "switches": [
            {"serialNumber": "SERIAL1", "password": "switch-secret"},
            {"serialNumber": "SERIAL2"},
        ],
    }

    masked = mask_password(payload)

    assert masked["password"] == "********"
    assert masked["switches"][0]["password"] == "********"
    assert payload["password"] == "top-secret"
    assert payload["switches"][0]["password"] == "switch-secret"

    utils = PayloadUtils()
    assert utils.build_credentials_payload(["SERIAL1"], "admin", "password") == {
        "switchIds": ["SERIAL1"],
        "username": "admin",
        "password": "password",
    }
    assert utils.build_switch_ids_payload(["SERIAL1", "SERIAL2"]) == {"switchIds": ["SERIAL1", "SERIAL2"]}


def test_utils_switch_field_operation_type_and_credential_grouping():
    """Switch helpers read dict/model values, classify operation type, and group credentials."""
    assert get_switch_field({"switchRole": "leaf"}, ["switch_role"]) == "leaf"
    assert get_switch_field(SimpleNamespace(role="spine"), ["role"]) == "spine"
    assert get_switch_field({"role": None}, ["role", "missing"]) is None

    assert determine_operation_type(_cfg("192.0.2.10")) == "normal"
    assert determine_operation_type({"poap": {"serial_number": "POAP1"}}) == "poap"
    assert determine_operation_type({"oldSerial": "OLD1"}) == "rma"
    assert determine_operation_type({}) == "normal"

    cfgs = [
        _cfg("192.0.2.10", username="admin", password="same", preserve_config=False),
        _cfg("192.0.2.11", username="admin", password="same", preserve_config=False),
        _cfg("192.0.2.12", username="admin", password="different", preserve_config=False),
        _cfg("192.0.2.13", username="admin", password="same", preserve_config=True),
    ]
    groups = group_switches_by_credentials(cfgs, ListLogger())

    assert sorted(len(group) for group in groups.values()) == [1, 1, 2]
    assert sum(len(group) for group in groups.values()) == 4


def test_utils_bootstrap_query_index_and_poap_data_block():
    """Bootstrap helpers normalize API response shapes and build serial/data indexes."""
    log = ListLogger()
    nd = FakeND(data={"switches": [{"serialNumber": "SERIAL1"}]})
    assert query_bootstrap_switches(nd, "FAB1", log) == [{"serialNumber": "SERIAL1"}]
    assert nd.calls[0]["path"].endswith("/bootstrap")

    nd = FakeND(data=[{"serialNumber": "SERIAL2"}])
    assert query_bootstrap_switches(nd, "FAB1", log) == [{"serialNumber": "SERIAL2"}]

    nd = FakeND(data="unexpected")
    assert query_bootstrap_switches(nd, "FAB1", log) == []

    failing_nd = FakeND(exc=ValueError("boom"))
    with pytest.raises(FailJsonError, match="Failed to query bootstrap switches"):
        query_bootstrap_switches(failing_nd, "FAB1", log)

    index = build_bootstrap_index([{"serialNumber": "SERIAL1"}, {"serial_number": "SERIAL2"}, {"hostname": "missing-serial"}])
    assert index["SERIAL1"]["serialNumber"] == "SERIAL1"
    assert index["SERIAL2"]["serial_number"] == "SERIAL2"
    assert index[""]["hostname"] == "missing-serial"

    preprov = _cfg(
        "192.0.2.20",
        preprovision={
            "serial_number": "PRE1",
            "model": "N9K-C93180YC-EX",
            "version": "10.3(1)",
            "hostname": "pre1",
            "config_data": {"models": ["N9K-C93180YC-EX"], "gateway": "192.0.2.1/24"},
        },
    ).preprovision
    assert build_poap_data_block(preprov) == {"gatewayIpMask": "192.0.2.1/24", "models": ["N9K-C93180YC-EX"]}
    assert build_poap_data_block(SimpleNamespace(config_data=None)) is None


def test_switch_wait_utils_filters_statuses_and_fetch_helpers():
    """Wait utility pure filters and API helpers handle present/empty/error data."""
    switch_data = [
        {"serialNumber": "SERIAL1", "additionalData": {"systemMode": "migration", "discoveryStatus": "ok"}},
        {"serialNumber": "SERIAL2", "additionalData": {"systemMode": "normal", "discoveryStatus": "unreachable"}},
    ]

    assert SwitchWaitUtils._filter_by_system_mode(["SERIAL1", "SERIAL2", "MISSING"], switch_data, "migration", True) == ["SERIAL1", "MISSING"]
    assert SwitchWaitUtils._filter_by_system_mode(["SERIAL1", "SERIAL2"], switch_data, "normal", False) == ["SERIAL1"]
    assert SwitchWaitUtils._filter_by_discovery_status(["SERIAL1", "SERIAL2", "MISSING"], switch_data, "ok") == ["SERIAL2", "MISSING"]

    nd = FakeND(data={"switches": switch_data})
    wait = SwitchWaitUtils(SimpleNamespace(nd=nd), "FAB1", ListLogger(), max_attempts=1, wait_interval=1, fabric_utils=SimpleNamespace())
    assert wait._fetch_switch_data() == switch_data

    empty_nd = FakeND(data={"switches": []})
    wait = SwitchWaitUtils(SimpleNamespace(nd=empty_nd), "FAB1", ListLogger(), max_attempts=1, wait_interval=1, fabric_utils=SimpleNamespace())
    assert wait._fetch_switch_data() == []

    missing_switches_nd = FakeND(data={})
    wait = SwitchWaitUtils(SimpleNamespace(nd=missing_switches_nd), "FAB1", ListLogger(), max_attempts=1, wait_interval=1, fabric_utils=SimpleNamespace())
    assert wait._fetch_switch_data() == []

    failing_nd = FakeND(exc=ValueError("down"))
    wait = SwitchWaitUtils(SimpleNamespace(nd=failing_nd), "FAB1", ListLogger(), max_attempts=1, wait_interval=1, fabric_utils=SimpleNamespace())
    assert wait._fetch_switch_data() is None

    nd = FakeND(data={"ok": True})
    wait = SwitchWaitUtils(SimpleNamespace(nd=nd), "FAB1", ListLogger(), max_attempts=1, wait_interval=1, fabric_utils=SimpleNamespace())
    wait._trigger_rediscovery(["SERIAL1"])
    assert nd.calls[0]["data"] == {"switchIds": ["SERIAL1"]}
    wait._trigger_rediscovery([])
    assert len(nd.calls) == 1

    nd = FakeND(data={"switches": [{"ip": "192.0.2.10", "status": "ok"}, {"ipaddr": "192.0.2.11", "status": "manageable"}]})
    wait = SwitchWaitUtils(SimpleNamespace(nd=nd), "FAB1", ListLogger(), max_attempts=1, wait_interval=1, fabric_utils=SimpleNamespace())
    assert wait._get_discovery_status("192.0.2.10")["status"] == "ok"
    assert wait._get_discovery_status("192.0.2.11")["status"] == "manageable"
    assert wait._get_discovery_status("192.0.2.12") is None


def test_switch_wait_utils_public_wait_shortcuts_and_polling(monkeypatch):
    """Public wait methods honor brownfield/greenfield shortcuts and polling outcomes."""
    sleep_calls = []
    monkeypatch.setattr("ansible_collections.cisco.nd.plugins.module_utils.manage_switches.utils.time.sleep", lambda seconds: sleep_calls.append(seconds))

    wait = SwitchWaitUtils(SimpleNamespace(nd=FakeND()), "FAB1", ListLogger(), max_attempts=1, wait_interval=1, fabric_utils=SimpleNamespace())
    wait._wait_for_system_mode = lambda serials: True
    wait._wait_for_discovery_state = lambda serials, state: raise_assertion("discovery should be skipped")
    assert wait.wait_for_switch_manageable(["SERIAL1"], all_preserve_config=True) is True

    fabric_utils = SimpleNamespace(get_fabric_info=lambda: {"management": {"greenfieldDebugFlag": "enable"}})
    wait = SwitchWaitUtils(SimpleNamespace(nd=FakeND()), "FAB1", ListLogger(), max_attempts=1, wait_interval=1, fabric_utils=fabric_utils)
    wait._wait_for_system_mode = lambda serials: True
    wait._wait_for_discovery_state = lambda serials, state: raise_assertion("discovery should be skipped")
    assert wait.wait_for_switch_manageable(["SERIAL1"]) is True
    assert wait._is_greenfield_debug_enabled() is True

    states_seen = []
    wait = SwitchWaitUtils(SimpleNamespace(nd=FakeND()), "FAB1", ListLogger(), max_attempts=1, wait_interval=1, fabric_utils=SimpleNamespace())
    wait._wait_for_system_mode = lambda serials: True
    wait._wait_for_discovery_state = lambda serials, state: states_seen.append(state) or True
    assert wait.wait_for_switch_manageable(["SERIAL1"], skip_greenfield_check=True) is True
    assert states_seen == ["unreachable", "ok"]

    wait = SwitchWaitUtils(SimpleNamespace(nd=FakeND()), "FAB1", ListLogger(), max_attempts=2, wait_interval=1, fabric_utils=SimpleNamespace())
    wait._fetch_switch_data = lambda: [{"serialNumber": "SERIAL1", "additionalData": {"systemMode": "normal", "discoveryStatus": "ok"}}]
    assert wait._wait_for_switches_in_fabric(["SERIAL1"]) is True
    assert wait._wait_for_discovery_state(["SERIAL1"], "ok") is True
    assert wait._poll_system_mode(["SERIAL1"], "normal", expect_match=False) == []

    wait = SwitchWaitUtils(SimpleNamespace(nd=FakeND()), "FAB1", ListLogger(), max_attempts=1, wait_interval=1, fabric_utils=SimpleNamespace())
    wait._fetch_switch_data = lambda: [{"serialNumber": "OTHER", "additionalData": {"systemMode": "migration", "discoveryStatus": "unreachable"}}]
    assert wait._wait_for_switches_in_fabric(["SERIAL1"]) is False
    assert wait._wait_for_discovery_state(["SERIAL1"], "ok") is False

    wait = SwitchWaitUtils(SimpleNamespace(nd=FakeND()), "FAB1", ListLogger(), max_attempts=1, wait_interval=1, fabric_utils=SimpleNamespace())
    wait._fetch_switch_data = lambda: []
    assert wait._wait_for_switches_in_fabric(["SERIAL1"]) is False
    assert wait._wait_for_discovery_state(["SERIAL1"], "ok") is False
    assert wait._poll_system_mode(["SERIAL1"], "normal", expect_match=False) is None


def test_switch_wait_utils_wait_for_discovery_success_failure_and_timeout(monkeypatch):
    """wait_for_discovery returns data on success and None on failed/timeout paths."""
    monkeypatch.setattr("ansible_collections.cisco.nd.plugins.module_utils.manage_switches.utils.time.sleep", lambda _seconds: None)

    wait = SwitchWaitUtils(SimpleNamespace(nd=FakeND()), "FAB1", ListLogger(), max_attempts=1, wait_interval=1, fabric_utils=SimpleNamespace())
    wait._get_discovery_status = lambda seed_ip: {"status": "ok", "ip": seed_ip}
    assert wait.wait_for_discovery("192.0.2.10", max_attempts=1, wait_interval=1) == {"status": "ok", "ip": "192.0.2.10"}

    wait._get_discovery_status = lambda seed_ip: {"status": "failed", "ip": seed_ip}
    assert wait.wait_for_discovery("192.0.2.10", max_attempts=1, wait_interval=1) is None

    wait._get_discovery_status = lambda seed_ip: {"status": "discovering", "ip": seed_ip}
    assert wait.wait_for_discovery("192.0.2.10", max_attempts=1, wait_interval=1) is None

    wait._wait_for_switches_in_fabric = lambda serials: True
    wait._wait_for_discovery_state = lambda serials, state: state == "ok"
    assert wait.wait_for_rma_switch_ready(["SERIAL1"]) is True

    wait._wait_for_switches_in_fabric = lambda serials: False
    assert wait.wait_for_rma_switch_ready(["SERIAL1"]) is False
