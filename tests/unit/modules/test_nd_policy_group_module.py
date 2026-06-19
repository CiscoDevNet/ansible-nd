# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``plugins/modules/nd_manage_policy_group.py`` module-level helpers.

This file covers the four module-private helpers that orchestrate config
resolution and switch-IP-to-serial translation before the state machine
runs:

- ``_looks_like_ipv4`` -- dotted-quad detector
- ``_resolve_config`` -- expands ``POLICY-GROUP-*`` IDs and template-only
  ``state: deleted`` entries against the API's current view
- ``_handle_gathered_state`` -- orchestrator query routing for the
  ``state: gathered`` read-only path
- ``_resolve_switch_ips_in_config`` -- in-place IPv4 -> serial-number
  rewrite of every ``switch_ids`` entry using ``FabricSwitchInventory``

The state machine (``manage_state`` / ``_handle_*_state`` for merged /
deleted / query) is **not** exercised here -- it requires the full
``RestSend`` harness and is covered by the integration suite under
``tests/integration/targets/nd_manage_policy_group``.
"""

# pylint: disable=protected-access

from __future__ import annotations

from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.modules import nd_manage_policy_group
from ansible_collections.cisco.nd.plugins.modules.nd_manage_policy_group import (
    _handle_gathered_state,
    _looks_like_ipv4,
    _resolve_config,
    _resolve_switch_ips_in_config,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Lightweight test harness (file-private)
# =============================================================================


class FailJsonError(Exception):
    """Raised by ``FakeModule.fail_json`` so tests can ``pytest.raises`` cleanly."""


class FakeModule:
    """Minimal ``AnsibleModule`` stand-in. Only the surface used by the
    helpers is implemented: ``params``, ``check_mode``, ``fail_json``,
    ``warn`` / ``warnings``."""

    def __init__(self, params: dict[str, Any] | None = None, check_mode: bool = False) -> None:
        self.params: dict[str, Any] = params or {}
        self.check_mode: bool = check_mode
        self.warnings: list[str] = []
        self.fail_json_called: dict[str, Any] | None = None

    def fail_json(self, msg: str, **kwargs: Any) -> None:
        """Capture the call and raise ``FailJsonError`` so callers stop."""
        self.fail_json_called = {"msg": msg, **kwargs}
        raise FailJsonError(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


class ListLogger:
    """Drop-in ``logging.Logger`` stand-in capturing %-formatted messages."""

    def __init__(self) -> None:
        self.debug_msgs: list[str] = []
        self.info_msgs: list[str] = []
        self.warning_msgs: list[str] = []
        self.error_msgs: list[str] = []

    @staticmethod
    def _fmt(msg: object, args: tuple) -> str:
        if args:
            try:
                return str(msg) % args
            except Exception:  # noqa: BLE001
                return str(msg)
        return str(msg)

    def debug(self, msg: object, *args: object) -> None:
        self.debug_msgs.append(self._fmt(msg, args))

    def info(self, msg: object, *args: object) -> None:
        self.info_msgs.append(self._fmt(msg, args))

    def warning(self, msg: object, *args: object) -> None:
        self.warning_msgs.append(self._fmt(msg, args))

    def error(self, msg: object, *args: object) -> None:
        self.error_msgs.append(self._fmt(msg, args))


class FakeOrchestrator:
    """Stub ``PolicyGroupOrchestrator`` exposing only the four query
    surfaces ``_handle_gathered_state`` consumes. Each call records its
    arguments and returns the pre-programmed responses."""

    def __init__(
        self,
        *,
        query_all_result: list | None = None,
        query_by_id_result: dict | None = None,
        query_filtered_result: list | None = None,
    ) -> None:
        self._query_all_result = query_all_result or []
        self._query_by_id_result = query_by_id_result
        self._query_filtered_result = query_filtered_result or []
        self.calls: list[tuple[str, dict]] = []

    def query_all(self, **kwargs: Any) -> list:
        self.calls.append(("query_all", dict(kwargs)))
        return list(self._query_all_result)

    def query_by_id(self, policy_id: str) -> dict | None:
        self.calls.append(("query_by_id", {"policy_id": policy_id}))
        return self._query_by_id_result

    def query_filtered(self, **kwargs: Any) -> list:
        self.calls.append(("query_filtered", dict(kwargs)))
        return list(self._query_filtered_result)


# =============================================================================
# Test: _looks_like_ipv4
# =============================================================================


def test_nd_policy_group_module_00010() -> None:
    """
    # Summary

    Valid dotted-quad IPv4 addresses are recognised, including the
    edge values ``0`` and ``255`` and any padded combination thereof.

    ## Classes and Methods

    - ``_looks_like_ipv4``
    """
    assert _looks_like_ipv4("192.168.1.1") is True
    assert _looks_like_ipv4("0.0.0.0") is True
    assert _looks_like_ipv4("255.255.255.255") is True
    assert _looks_like_ipv4("10.0.0.1") is True


def test_nd_policy_group_module_00020() -> None:
    """
    # Summary

    Serial numbers, hostnames, and other non-dotted-quad strings are
    rejected.

    ## Classes and Methods

    - ``_looks_like_ipv4``
    """
    assert _looks_like_ipv4("FDO251205AB") is False
    assert _looks_like_ipv4("leaf-01.example.com") is False
    assert _looks_like_ipv4("not-an-ip") is False


def test_nd_policy_group_module_00030() -> None:
    """
    # Summary

    Empty input is always rejected: ``""`` short-circuits without
    raising; ``None`` is tolerated via the ``if not value`` guard.

    ## Classes and Methods

    - ``_looks_like_ipv4``
    """
    assert _looks_like_ipv4("") is False
    assert _looks_like_ipv4(None) is False  # type: ignore[arg-type]


def test_nd_policy_group_module_00040() -> None:
    """
    # Summary

    Out-of-range octets (``> 255`` or ``< 0``), wrong segment counts,
    and non-numeric segments are rejected.

    ## Classes and Methods

    - ``_looks_like_ipv4``
    """
    assert _looks_like_ipv4("256.1.1.1") is False
    assert _looks_like_ipv4("192.168.1") is False
    assert _looks_like_ipv4("192.168.1.1.1") is False
    assert _looks_like_ipv4("192.168.1.abc") is False
    assert _looks_like_ipv4("-1.0.0.0") is False  # '-1'.isdigit() is False
    assert _looks_like_ipv4("a.b.c.d") is False


# =============================================================================
# Test: _resolve_config -- POLICY-GROUP-* ID resolution
# =============================================================================


def test_nd_policy_group_module_00100() -> None:
    """
    # Summary

    A ``POLICY-GROUP-*`` ID that exists on the controller resolves into a
    config entry carrying the resolved ``name`` (templateName), the
    user-supplied ``description``, the original ``policy_id``, and the
    bookkeeping field ``_existing_description``.

    ## Classes and Methods

    - ``_resolve_config``
    """
    existing = [
        {"policyId": "POLICY-GROUP-1", "templateName": "feature_enable", "description": "old-desc"},
    ]
    config = [
        {"name": "POLICY-GROUP-1", "description": "new-desc", "switch_ids": ["FDO111"]},
    ]
    log = ListLogger()
    module = FakeModule()

    result = _resolve_config(config, existing, state="merged", module=module, log=log)

    assert len(result) == 1
    entry = result[0]
    assert entry["name"] == "feature_enable"
    assert entry["description"] == "new-desc"  # user-supplied wins
    assert entry["policy_id"] == "POLICY-GROUP-1"
    assert entry["_existing_description"] == "old-desc"


def test_nd_policy_group_module_00110() -> None:
    """
    # Summary

    When the user omits ``description`` on a ``POLICY-GROUP-*`` entry,
    the existing description is used so the state machine has a valid
    composite identifier.

    ## Classes and Methods

    - ``_resolve_config``
    """
    existing = [
        {"policyId": "POLICY-GROUP-2", "templateName": "tpl", "description": "existing-desc"},
    ]
    config = [{"name": "POLICY-GROUP-2", "switch_ids": ["FDO111"]}]
    log = ListLogger()
    module = FakeModule()

    result = _resolve_config(config, existing, state="merged", module=module, log=log)

    assert len(result) == 1
    assert result[0]["description"] == "existing-desc"


def test_nd_policy_group_module_00120() -> None:
    """
    # Summary

    When the user passes ``description=""`` on a ``POLICY-GROUP-*`` entry,
    the existing description is used as the safe default (empty string
    is treated as "not supplied" for this fallback decision).

    ## Classes and Methods

    - ``_resolve_config``
    """
    existing = [
        {"policyId": "POLICY-GROUP-3", "templateName": "tpl", "description": "existing-desc"},
    ]
    config = [{"name": "POLICY-GROUP-3", "description": "", "switch_ids": []}]
    log = ListLogger()
    module = FakeModule()

    result = _resolve_config(config, existing, state="merged", module=module, log=log)

    assert result[0]["description"] == "existing-desc"


def test_nd_policy_group_module_00130() -> None:
    """
    # Summary

    A ``POLICY-GROUP-*`` ID that is **not** on the controller is skipped
    silently when ``state=deleted`` (the group is already gone -- no
    work to do).

    ## Classes and Methods

    - ``_resolve_config``
    """
    config = [{"name": "POLICY-GROUP-MISSING", "switch_ids": []}]
    log = ListLogger()
    module = FakeModule()

    result = _resolve_config(config, existing_groups=[], state="deleted", module=module, log=log)

    assert result == []
    assert module.fail_json_called is None


def test_nd_policy_group_module_00140() -> None:
    """
    # Summary

    A ``POLICY-GROUP-*`` ID that is not on the controller and not in
    ``state=deleted`` is a hard error: ``module.fail_json`` is called
    with a self-documenting message.

    ## Classes and Methods

    - ``_resolve_config``
    """
    config = [{"name": "POLICY-GROUP-MISSING"}]
    log = ListLogger()
    module = FakeModule()

    with pytest.raises(FailJsonError):
        _resolve_config(config, existing_groups=[], state="merged", module=module, log=log)

    assert module.fail_json_called is not None
    assert "POLICY-GROUP-MISSING" in module.fail_json_called["msg"]
    assert "not found on controller" in module.fail_json_called["msg"]


def test_nd_policy_group_module_00150() -> None:
    """
    # Summary

    An explicit ``policy_id`` field (e.g. coming from a gathered
    round-trip) is promoted into the ``POLICY-GROUP-*`` resolution path
    even when ``name`` carries the template name instead of the ID.

    ## Classes and Methods

    - ``_resolve_config``
    """
    existing = [
        {"policyId": "POLICY-GROUP-9", "templateName": "feature_enable", "description": "d"},
    ]
    config = [
        {
            "name": "feature_enable",
            "policy_id": "POLICY-GROUP-9",
            "description": "new",
            "switch_ids": ["FDO111"],
        }
    ]
    log = ListLogger()
    module = FakeModule()

    result = _resolve_config(config, existing, state="merged", module=module, log=log)

    assert len(result) == 1
    assert result[0]["policy_id"] == "POLICY-GROUP-9"
    assert result[0]["name"] == "feature_enable"
    assert result[0]["description"] == "new"


# =============================================================================
# Test: _resolve_config -- template-only deleted-state expansion
# =============================================================================


def test_nd_policy_group_module_00200() -> None:
    """
    # Summary

    A template-only entry (no description) with ``state=deleted``
    expands into one resolved entry per matching policy group, each
    inheriting the existing description.

    ## Classes and Methods

    - ``_resolve_config``
    """
    existing = [
        {"policyId": "P1", "templateName": "feature_enable", "description": "d1"},
        {"policyId": "P2", "templateName": "feature_enable", "description": "d2"},
        {"policyId": "P3", "templateName": "other_template", "description": "other"},
    ]
    config = [{"name": "feature_enable"}]
    log = ListLogger()
    module = FakeModule()

    result = _resolve_config(config, existing, state="deleted", module=module, log=log)

    assert len(result) == 2
    assert {e["description"] for e in result} == {"d1", "d2"}
    assert all(e["name"] == "feature_enable" for e in result)


def test_nd_policy_group_module_00210() -> None:
    """
    # Summary

    A template-only deleted entry that matches no existing groups is
    skipped silently -- no entry is produced and no error is raised.

    ## Classes and Methods

    - ``_resolve_config``
    """
    config = [{"name": "feature_enable"}]
    log = ListLogger()
    module = FakeModule()

    result = _resolve_config(config, existing_groups=[], state="deleted", module=module, log=log)

    assert result == []


def test_nd_policy_group_module_00220() -> None:
    """
    # Summary

    The normal case (``name`` + ``description``) is a pass-through: the
    entry is appended to the resolved list unchanged.

    ## Classes and Methods

    - ``_resolve_config``
    """
    config = [{"name": "feature_enable", "description": "my-desc", "switch_ids": ["FDO111"]}]
    log = ListLogger()
    module = FakeModule()

    result = _resolve_config(config, existing_groups=[], state="merged", module=module, log=log)

    assert result == config


def test_nd_policy_group_module_00230() -> None:
    """
    # Summary

    Mixed config: a normal entry, a ``POLICY-GROUP-*`` resolution, and
    a template-only ``deleted`` expansion all produce the expected
    resolved entries in order.

    ## Classes and Methods

    - ``_resolve_config``
    """
    existing = [
        {"policyId": "POLICY-GROUP-1", "templateName": "tpl-a", "description": "old"},
        {"policyId": "P2", "templateName": "tpl-b", "description": "b1"},
        {"policyId": "P3", "templateName": "tpl-b", "description": "b2"},
    ]
    config = [
        {"name": "normal", "description": "norm-d"},
        {"name": "POLICY-GROUP-1", "description": "renamed"},
        {"name": "tpl-b"},
    ]
    log = ListLogger()
    module = FakeModule()

    result = _resolve_config(config, existing, state="deleted", module=module, log=log)

    # 1 pass-through + 1 id-resolved + 2 template-expanded
    assert len(result) == 4
    assert result[0] == {"name": "normal", "description": "norm-d"}
    assert result[1]["policy_id"] == "POLICY-GROUP-1"
    assert {e["description"] for e in result[2:]} == {"b1", "b2"}


# =============================================================================
# Test: _handle_gathered_state
# =============================================================================


def test_nd_policy_group_module_00300() -> None:
    """
    # Summary

    With an empty config, ``_handle_gathered_state`` fetches every
    policy group on the fabric via ``query_all(include_no_description=True,
    deduplicate=False)`` -- both flags matter for ``state: gathered``.

    ## Classes and Methods

    - ``_handle_gathered_state``
    """
    raw = [
        {"policyId": "P1", "templateName": "tpl", "description": "d1", "switchIds": []},
        {"policyId": "P2", "templateName": "tpl", "description": "d2", "switchIds": []},
    ]
    orch = FakeOrchestrator(query_all_result=raw)
    log = ListLogger()

    result = _handle_gathered_state(orch, config=[], log=log)

    assert len(result) == 2
    assert orch.calls == [("query_all", {"include_no_description": True, "deduplicate": False})]


def test_nd_policy_group_module_00310() -> None:
    """
    # Summary

    A config filter of ``name=POLICY-GROUP-*`` routes to
    ``query_by_id``; the returned dict is rendered into a playbook config.

    ## Classes and Methods

    - ``_handle_gathered_state``
    """
    body = {"policyId": "POLICY-GROUP-1", "templateName": "tpl", "description": "d", "switchIds": ["s1"]}
    orch = FakeOrchestrator(query_by_id_result=body)
    log = ListLogger()

    result = _handle_gathered_state(orch, config=[{"name": "POLICY-GROUP-1"}], log=log)

    assert orch.calls == [("query_by_id", {"policy_id": "POLICY-GROUP-1"})]
    assert len(result) == 1
    assert result[0]["policy_id"] == "POLICY-GROUP-1"


def test_nd_policy_group_module_00320() -> None:
    """
    # Summary

    ``query_by_id`` returning ``None`` (not found) yields no gathered
    entry -- the filter is dropped silently.

    ## Classes and Methods

    - ``_handle_gathered_state``
    """
    orch = FakeOrchestrator(query_by_id_result=None)
    log = ListLogger()

    result = _handle_gathered_state(orch, config=[{"name": "POLICY-GROUP-MISSING"}], log=log)

    assert result == []


def test_nd_policy_group_module_00330() -> None:
    """
    # Summary

    A filter with both ``name`` and ``description`` routes to
    ``query_filtered`` with both parameters and ``deduplicate=False``
    (so legitimate duplicates by ``policyId`` are visible).

    ## Classes and Methods

    - ``_handle_gathered_state``
    """
    filtered = [{"policyId": "P1", "templateName": "tpl-a", "description": "alpha", "switchIds": []}]
    orch = FakeOrchestrator(query_filtered_result=filtered)
    log = ListLogger()

    _handle_gathered_state(orch, config=[{"name": "tpl-a", "description": "alpha"}], log=log)

    assert orch.calls == [
        (
            "query_filtered",
            {"template_name": "tpl-a", "description": "alpha", "deduplicate": False},
        )
    ]


def test_nd_policy_group_module_00340() -> None:
    """
    # Summary

    A filter with ``name`` only routes to ``query_filtered`` with just
    ``template_name``.

    ## Classes and Methods

    - ``_handle_gathered_state``
    """
    filtered = [{"policyId": "P1", "templateName": "tpl-a", "description": "d", "switchIds": []}]
    orch = FakeOrchestrator(query_filtered_result=filtered)
    log = ListLogger()

    _handle_gathered_state(orch, config=[{"name": "tpl-a"}], log=log)

    assert orch.calls == [("query_filtered", {"template_name": "tpl-a", "deduplicate": False})]


def test_nd_policy_group_module_00350() -> None:
    """
    # Summary

    A filter with ``description`` only (no ``name``) routes to
    ``query_filtered`` with just ``description``.

    ## Classes and Methods

    - ``_handle_gathered_state``
    """
    filtered = [{"policyId": "P1", "templateName": "tpl", "description": "alpha", "switchIds": []}]
    orch = FakeOrchestrator(query_filtered_result=filtered)
    log = ListLogger()

    _handle_gathered_state(orch, config=[{"description": "alpha"}], log=log)

    assert orch.calls == [("query_filtered", {"description": "alpha", "deduplicate": False})]


def test_nd_policy_group_module_00360() -> None:
    """
    # Summary

    Duplicate ``policyId`` rows across multiple filter calls are
    de-duplicated in the final gathered output (first occurrence wins).

    ## Classes and Methods

    - ``_handle_gathered_state``
    """
    # Same policyId returned twice -- once from the template-only filter,
    # once from the description-only filter (e.g., if the user listed both)
    dup = {"policyId": "P-DUP", "templateName": "tpl", "description": "alpha", "switchIds": []}
    orch = FakeOrchestrator(query_filtered_result=[dup])
    log = ListLogger()

    result = _handle_gathered_state(
        orch,
        config=[{"name": "tpl"}, {"description": "alpha"}],
        log=log,
    )

    assert len(result) == 1
    assert result[0]["policy_id"] == "P-DUP"


def test_nd_policy_group_module_00370() -> None:
    """
    # Summary

    Per-policy parsing failures are logged at WARNING and skipped --
    they do not abort the whole gather (one bad row shouldn't lose the
    rest of the fabric).

    ## Test

    - Two raw groups: one malformed (missing required ``policyId``),
      one good. Only the good one appears in the result.

    ## Classes and Methods

    - ``_handle_gathered_state``
    """
    raw = [
        {"templateName": "tpl", "description": "bad"},  # no policyId -> filtered out
        {"policyId": "P-OK", "templateName": "tpl", "description": "good", "switchIds": []},
    ]
    orch = FakeOrchestrator(query_all_result=raw)
    log = ListLogger()

    result = _handle_gathered_state(orch, config=[], log=log)

    # Bad entry has no policyId so the dedup-filter drops it before parsing.
    assert len(result) == 1
    assert result[0]["policy_id"] == "P-OK"


# =============================================================================
# Test: _resolve_switch_ips_in_config
# =============================================================================


class _FakeSwitch:
    """Stand-in switch model exposing the ``switch_id`` attribute the
    helper reads after ``ip_map[ip]`` lookup."""

    def __init__(self, switch_id: str) -> None:
        self.switch_id = switch_id


class _FakeInventory:
    """Stub ``FabricSwitchInventory`` exposing ``by_ip`` only."""

    def __init__(self, mapping: dict[str, _FakeSwitch]) -> None:
        self._mapping = mapping

    def by_ip(self) -> dict[str, _FakeSwitch]:
        return self._mapping


class _FakeRestSend:
    """Tracks ``save_settings`` / ``restore_settings`` calls and the
    ``check_mode`` override that ``_resolve_switch_ips_in_config``
    performs around the inventory fetch."""

    def __init__(self) -> None:
        self.check_mode = True
        self.events: list[str] = []

    def save_settings(self) -> None:
        self.events.append("save")

    def restore_settings(self) -> None:
        self.events.append("restore")


class _FakeNDModule:
    """Stand-in for ``NDModule`` returning a stub ``rest_send``."""

    def __init__(self) -> None:
        self.rest_send = _FakeRestSend()

    def get_rest_send(self) -> _FakeRestSend:
        return self.rest_send


def _install_inventory_stubs(monkeypatch: pytest.MonkeyPatch, ip_map: dict[str, _FakeSwitch]) -> _FakeNDModule:
    """Patch ``NDModule`` and ``FabricSwitchInventory.from_fabric`` so
    ``_resolve_switch_ips_in_config`` runs without touching the network.
    Returns the ``_FakeNDModule`` instance used for the call so tests
    can assert on ``check_mode`` / save / restore behaviour."""
    fake_nd = _FakeNDModule()
    monkeypatch.setattr(nd_manage_policy_group, "NDModule", lambda _module: fake_nd)
    inventory = _FakeInventory(ip_map)
    monkeypatch.setattr(
        nd_manage_policy_group.FabricSwitchInventory,
        "from_fabric",
        classmethod(lambda cls, nd, fabric, log, model_class: inventory),
    )
    return fake_nd


def test_nd_policy_group_module_00400() -> None:
    """
    # Summary

    Empty config -> the helper returns immediately without touching
    ``NDModule`` or the inventory.

    ## Classes and Methods

    - ``_resolve_switch_ips_in_config``
    """
    module = FakeModule()
    log = ListLogger()
    config: list[dict[str, Any]] = []

    with does_not_raise():
        _resolve_switch_ips_in_config(module, log, config, fabric_name="fab")

    assert config == []


def test_nd_policy_group_module_00410(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    A config containing only serial numbers -> the helper short-circuits
    on the ``has_ip`` check; no ``NDModule`` is instantiated.

    ## Test

    - ``NDModule`` is replaced with a sentinel that raises if called.

    ## Classes and Methods

    - ``_resolve_switch_ips_in_config``
    """

    def _boom(_module: object) -> None:
        raise AssertionError("NDModule should not be instantiated for serial-only configs")

    monkeypatch.setattr(nd_manage_policy_group, "NDModule", _boom)

    config = [{"switch_ids": ["FDO111", "FDO222"]}]
    module = FakeModule()
    log = ListLogger()

    with does_not_raise():
        _resolve_switch_ips_in_config(module, log, config, fabric_name="fab")

    assert config == [{"switch_ids": ["FDO111", "FDO222"]}]


def test_nd_policy_group_module_00420(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Mixed serial + IP entries -> IPs are resolved to serial numbers via
    the inventory; pre-existing serials pass through unchanged in the
    original list order.

    ## Classes and Methods

    - ``_resolve_switch_ips_in_config``
    """
    _install_inventory_stubs(
        monkeypatch,
        {"192.168.1.10": _FakeSwitch("FDO_FROM_IP")},
    )

    config = [{"switch_ids": ["FDO_KEEP", "192.168.1.10"]}]
    module = FakeModule()
    log = ListLogger()

    _resolve_switch_ips_in_config(module, log, config, fabric_name="fab")

    assert config[0]["switch_ids"] == ["FDO_KEEP", "FDO_FROM_IP"]


def test_nd_policy_group_module_00430(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    All-IP config -> every entry is resolved to its serial number.
    Multiple entries in the same and across different config items are
    handled in a single inventory fetch.

    ## Classes and Methods

    - ``_resolve_switch_ips_in_config``
    """
    _install_inventory_stubs(
        monkeypatch,
        {
            "10.0.0.1": _FakeSwitch("FDO_AAA"),
            "10.0.0.2": _FakeSwitch("FDO_BBB"),
            "10.0.0.3": _FakeSwitch("FDO_CCC"),
        },
    )

    config = [
        {"switch_ids": ["10.0.0.1", "10.0.0.2"]},
        {"switch_ids": ["10.0.0.3"]},
    ]
    module = FakeModule()
    log = ListLogger()

    _resolve_switch_ips_in_config(module, log, config, fabric_name="fab")

    assert config[0]["switch_ids"] == ["FDO_AAA", "FDO_BBB"]
    assert config[1]["switch_ids"] == ["FDO_CCC"]


def test_nd_policy_group_module_00440(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    An IP that the inventory does not know is a hard error:
    ``module.fail_json`` is called with the index of the offending
    ``switch_ids`` entry and the fabric name.

    ## Classes and Methods

    - ``_resolve_switch_ips_in_config``
    """
    _install_inventory_stubs(monkeypatch, {"10.0.0.1": _FakeSwitch("FDO_AAA")})

    config = [{"switch_ids": ["10.0.0.1", "192.168.99.99"]}]
    module = FakeModule()
    log = ListLogger()

    with pytest.raises(FailJsonError):
        _resolve_switch_ips_in_config(module, log, config, fabric_name="my-fab")

    assert module.fail_json_called is not None
    msg = module.fail_json_called["msg"]
    assert "192.168.99.99" in msg
    assert "my-fab" in msg


def test_nd_policy_group_module_00450(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Entries whose ``switch_ids`` is missing or empty are skipped (no
    ``resolved_list`` re-assignment) so that the original key state is
    preserved.

    ## Test

    - Three entries: one with an IP (triggers the resolver path), one
      with ``switch_ids=[]``, one with no ``switch_ids`` key at all.
    - Only the first is mutated; the other two are unchanged.

    ## Classes and Methods

    - ``_resolve_switch_ips_in_config``
    """
    _install_inventory_stubs(monkeypatch, {"10.0.0.1": _FakeSwitch("FDO_AAA")})

    config = [
        {"switch_ids": ["10.0.0.1"]},
        {"switch_ids": []},
        {"other_key": "value"},
    ]
    module = FakeModule()
    log = ListLogger()

    _resolve_switch_ips_in_config(module, log, config, fabric_name="fab")

    assert config[0]["switch_ids"] == ["FDO_AAA"]
    assert config[1]["switch_ids"] == []
    assert "switch_ids" not in config[2]


def test_nd_policy_group_module_00460(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Check-mode safety: ``rest_send.save_settings()`` is invoked
    before the inventory fetch and ``restore_settings()`` after it,
    so a check-mode caller has its ``check_mode`` flag preserved
    around the read-only GET.

    ## Classes and Methods

    - ``_resolve_switch_ips_in_config``
    """
    fake_nd = _install_inventory_stubs(monkeypatch, {"10.0.0.1": _FakeSwitch("FDO_AAA")})

    config = [{"switch_ids": ["10.0.0.1"]}]
    module = FakeModule(check_mode=True)
    log = ListLogger()

    _resolve_switch_ips_in_config(module, log, config, fabric_name="fab")

    # save/restore bracket the inventory fetch
    assert fake_nd.rest_send.events == ["save", "restore"]
