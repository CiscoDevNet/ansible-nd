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
import yaml
from ansible_collections.cisco.nd.plugins.modules import nd_manage_policy_group
from ansible_collections.cisco.nd.plugins.modules.nd_manage_policy_group import (
    _FabricInventoryRestClient,
    _handle_gathered_state,
    _looks_like_ipv4,
    _pending_cleanup_candidates,
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


def test_nd_policy_group_module_00005_deploy_default_matches_documentation() -> None:
    """Verify the safe deploy default is identical in docs and argument spec."""
    documentation = yaml.safe_load(nd_manage_policy_group.DOCUMENTATION)
    argument_spec = nd_manage_policy_group.PolicyGroupCreate.get_argument_spec()

    assert documentation["options"]["deploy"]["default"] is False
    assert argument_spec["deploy"]["default"] is False


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

    @staticmethod
    def _is_active_user_group(group: dict) -> bool:
        return not group.get("source") and not group.get("markDeleted", False)


class FakeValidationOrchestrator:
    """Stub ``PolicyGroupOrchestrator`` exposing only the two surfaces the
    template-input validation hook touches:

    - ``_request(path, verb, not_found_ok)``: returns the next pre-queued
      response (or raises the next pre-queued exception).  Calls are
      recorded for assertions on cache-hit / cache-miss behaviour.
    - ``_apply_endpoint_params(ep, *, with_ticket)``: records the call so
      tests can assert that ``with_ticket=False`` is used for the
      parameters GET (it's a read endpoint that does not accept ticketId).
    """

    def __init__(self, responses: list[Any] | None = None) -> None:
        self._responses: list[Any] = list(responses or [])
        self.request_calls: list[tuple[str, Any, bool]] = []
        self.apply_params_calls: list[dict[str, Any]] = []

    def queue(self, *responses: Any) -> None:
        """Append one or more responses to the FIFO queue.  Each entry is
        either a payload dict (returned) or an Exception instance
        (raised)."""
        self._responses.extend(responses)

    def _request(self, *, path: str, verb: Any, not_found_ok: bool = False) -> Any:
        self.request_calls.append((path, verb, not_found_ok))
        if not self._responses:
            raise AssertionError(f"FakeValidationOrchestrator._request called with no queued response: " f"path={path!r}, verb={verb!r}")
        nxt = self._responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    def _apply_endpoint_params(self, ep: Any, *, with_ticket: bool = True) -> None:
        self.apply_params_calls.append({"endpoint_type": type(ep).__name__, "with_ticket": with_ticket})


def _make_params_response(params: list[dict]) -> dict:
    """Shape-mimic of ``GET /api/v1/manage/configTemplates/<name>/parameters``."""
    return {"parameters": params}


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
# Test: _pending_cleanup_candidates
# =============================================================================


def test_nd_policy_group_module_00240() -> None:
    """
    # Summary

    Delete+deploy entries that are absent from the active policy-group view
    are returned as pending-cleanup candidates.  The helper covers
    policy ID, description+template, and template-only misses.

    ## Classes and Methods

    - ``_pending_cleanup_candidates``
    """
    existing = [
        {"policyId": "POLICY-GROUP-ACTIVE", "templateName": "feature_enable", "description": "active"},
    ]
    config = [
        {"name": "POLICY-GROUP-MISSING", "switch_ids": ["SN1"]},
        {"name": "switch_freeform", "description": "missing desc", "switch_ids": ["SN2"]},
        {"name": "missing_template", "switch_ids": ["SN3"]},
    ]
    log = ListLogger()

    result = _pending_cleanup_candidates(config, existing, log)

    assert result == config
    assert len(log.info_msgs) == 3


def test_nd_policy_group_module_00250() -> None:
    """
    # Summary

    Delete+deploy entries that are present in the active policy-group view
    are excluded from pending-cleanup scheduling because the normal
    delete path will handle them.

    ## Classes and Methods

    - ``_pending_cleanup_candidates``
    """
    existing = [
        {"policyId": "POLICY-GROUP-1", "templateName": "feature_enable", "description": "active"},
        {"policyId": "POLICY-GROUP-2", "templateName": "switch_freeform", "description": "freeform"},
    ]
    config = [
        {"name": "POLICY-GROUP-1", "switch_ids": ["SN1"]},
        {"name": "feature_enable", "description": "active", "switch_ids": ["SN1"]},
        {"name": "switch_freeform", "switch_ids": ["SN2"]},
    ]
    log = ListLogger()

    result = _pending_cleanup_candidates(config, existing, log)

    assert result == []
    assert log.info_msgs == []


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


def test_nd_policy_group_module_00325() -> None:
    """
    # Summary

    Gathered-by-ID still hides controller artifacts and pending-delete
    records, matching the default gathered-all behavior.

    ## Classes and Methods

    - ``_handle_gathered_state``
    """
    for body in (
        {
            "policyId": "POLICY-GROUP-SOURCE",
            "templateName": "tpl",
            "description": "d",
            "switchIds": ["s1"],
            "source": "POLICY-GROUP-ORIG",
        },
        {
            "policyId": "POLICY-GROUP-DELETED",
            "templateName": "tpl",
            "description": "d",
            "switchIds": ["s1"],
            "markDeleted": True,
        },
    ):
        orch = FakeOrchestrator(query_by_id_result=body)
        log = ListLogger()

        result = _handle_gathered_state(orch, config=[{"name": body["policyId"]}], log=log)

        assert orch.calls == [("query_by_id", {"policy_id": body["policyId"]})]
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
        self.sender = None
        self.response_handler = None
        self.path = None
        self.verb = None
        self.commit_count = 0
        self.response_current = {"DATA": {"switches": []}, "RETURN_CODE": 200}
        self.inventory_clients: list[Any] = []

    def save_settings(self) -> None:
        self.events.append("save")

    def restore_settings(self) -> None:
        self.events.append("restore")

    def commit(self) -> None:
        self.commit_count += 1


def _install_inventory_stubs(monkeypatch: pytest.MonkeyPatch, ip_map: dict[str, _FakeSwitch]) -> _FakeRestSend:
    """Patch ``RestSend`` and ``FabricSwitchInventory.from_fabric`` so
    ``_resolve_switch_ips_in_config`` runs without touching the network.
    Returns the ``_FakeRestSend`` instance used for the call so tests
    can assert on ``check_mode`` / save / restore behaviour."""
    fake_rest_send = _FakeRestSend()
    monkeypatch.setattr(nd_manage_policy_group, "RestSend", lambda _params: fake_rest_send)
    inventory = _FakeInventory(ip_map)

    def _from_fabric(cls, client, fabric, log, model_class):
        fake_rest_send.inventory_clients.append(client)
        assert client.rest_send is fake_rest_send
        assert callable(client.request)
        assert client.rest_send.check_mode is False
        return inventory

    monkeypatch.setattr(
        nd_manage_policy_group.FabricSwitchInventory,
        "from_fabric",
        classmethod(_from_fabric),
    )
    return fake_rest_send


def test_nd_policy_group_module_00390() -> None:
    """
    # Summary

    The local inventory adapter exposes the small ``NDModule``-like
    surface that ``FabricSwitchInventory.from_fabric`` expects while
    using an already-created ``RestSend`` instance under the hood.

    ## Classes and Methods

    - ``_FabricInventoryRestClient.request``
    """
    rest_send = _FakeRestSend()
    rest_send.response_current = {"DATA": {"switches": [{"switchId": "FDO_AAA"}]}, "RETURN_CODE": 200}
    module = FakeModule()
    client = _FabricInventoryRestClient(module, rest_send)

    result = client.request(path="/api/v1/manage/fabrics/fab/switches", verb="GET")

    assert client.module is module
    assert client.rest_send is rest_send
    assert rest_send.path == "/api/v1/manage/fabrics/fab/switches"
    assert rest_send.verb == "GET"
    assert rest_send.commit_count == 1
    assert result == {"switches": [{"switchId": "FDO_AAA"}]}


def test_nd_policy_group_module_00400() -> None:
    """
    # Summary

    Empty config -> the helper returns immediately without touching
    ``RestSend`` or the inventory.

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
    on the ``has_ip`` check; no ``RestSend`` is instantiated.

    ## Test

    - ``RestSend`` is replaced with a sentinel that raises if called.

    ## Classes and Methods

    - ``_resolve_switch_ips_in_config``
    """

    def _boom(_params: object) -> None:
        raise AssertionError("RestSend should not be instantiated for serial-only configs")

    monkeypatch.setattr(nd_manage_policy_group, "RestSend", _boom)

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
    fake_rest_send = _install_inventory_stubs(monkeypatch, {"10.0.0.1": _FakeSwitch("FDO_AAA")})

    config = [{"switch_ids": ["10.0.0.1"]}]
    module = FakeModule(check_mode=True)
    log = ListLogger()

    _resolve_switch_ips_in_config(module, log, config, fabric_name="fab")

    # save/restore bracket the inventory fetch
    assert fake_rest_send.events == ["save", "restore"]
    assert len(fake_rest_send.inventory_clients) == 1


# =============================================================================
# Test: require_pydantic guard wired into main()
# =============================================================================
#
# Reviewer (mikewiebe) asked for a module-wrapper unit test that simulates
# ``HAS_PYDANTIC=False`` to prove the freshly-added ``require_pydantic(module)``
# call in ``main()`` actually fails fast with the standard Ansible
# "missing required lib" message rather than crashing later with a cryptic
# AttributeError from the pydantic_compat shim.
#
# The check is in two parts:
#   1. Smoke assertion that ``nd_manage_policy_group`` imports
#      ``require_pydantic`` from ``common.pydantic_compat`` -- if that import
#      is ever removed, attribute access in the test below would raise
#      ``AttributeError`` and the test would fail loudly.
#   2. Behavioural assertion that, with ``HAS_PYDANTIC`` patched to False,
#      invoking the imported ``require_pydantic`` against a ``FakeModule``
#      causes ``fail_json`` to fire with a message naming ``pydantic``.
# Together these guarantee that, on a Pydantic-less runtime, ``main()`` would
# exit cleanly via the standard Ansible failure path before touching the
# orchestrator / argspec helpers.
#
# Driving the real ``main()`` is intentionally out of scope here -- that
# would require argspec satisfaction, ``AnsibleModule`` construction, and
# the full ``RestSend`` harness, none of which add anything the
# behavioural assertion below does not already prove.


def test_nd_policy_group_module_00500(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    ``nd_manage_policy_group`` imports ``require_pydantic`` from
    ``common.pydantic_compat``, and that imported reference correctly
    short-circuits to ``module.fail_json`` when ``HAS_PYDANTIC`` is False --
    so on a runtime without Pydantic the module fails with the standard
    Ansible missing-required-lib message instead of a cryptic
    ``AttributeError`` later in the orchestrator stack.

    ## Test

    - Patch ``HAS_PYDANTIC`` on ``common.pydantic_compat`` to False.
    - Call ``nd_manage_policy_group.require_pydantic(fake_module)`` via the
      imported reference.
    - Assert ``FailJsonError`` was raised by ``FakeModule.fail_json``.
    - Assert the failure message contains the string ``pydantic`` (the exact
      wording comes from Ansible's ``missing_required_lib`` helper and is
      not pinned here to avoid coupling to upstream wording changes).

    ## Classes and Methods

    - ``plugins.modules.nd_manage_policy_group.require_pydantic`` (imported)
    - ``plugins.module_utils.common.pydantic_compat.require_pydantic``
    """
    # Sanity: the wrapper must have actually imported the symbol. If a
    # future refactor drops the import, this attribute access raises
    # AttributeError and the test fails before we get to the patching.
    assert hasattr(nd_manage_policy_group, "require_pydantic")

    from ansible_collections.cisco.nd.plugins.module_utils.common import (
        pydantic_compat,
    )

    monkeypatch.setattr(pydantic_compat, "HAS_PYDANTIC", False)

    module = FakeModule()
    with pytest.raises(FailJsonError):
        nd_manage_policy_group.require_pydantic(module)

    assert module.fail_json_called is not None
    assert "pydantic" in module.fail_json_called["msg"].lower()


# =============================================================================
# Test: _validate_template_inputs_in_buckets
# =============================================================================
#
# The hook lives in ``nd_manage_policy_group._validate_template_inputs_in_buckets``
# and is called from ``main()`` immediately after bucket partitioning.  It
# removes invalid entries from their execution bucket, returns structured
# failures, and lets ``main()`` process valid entries before returning the final
# failed task result.  These tests cover:
#
# - Kill-switch (``_ENABLE_TEMPLATE_INPUT_VALIDATION = False``) skips
#   everything cleanly.
# - State filtering (``deleted`` / ``gathered`` skip everything cleanly).
# - Per-entry skip when ``template_inputs`` is missing / empty.
# - Per-entry skip when the template name is still ``POLICY-GROUP-*``
#   (defensive guard for any future code path bypassing ``_resolve_config``).
# - Cache hit / miss accounting -- N entries on the same template incur
#   exactly one GET.
# - ``cluster_name`` is forwarded onto the parameters endpoint (via the
#   orchestrator's ``_apply_endpoint_params(..., with_ticket=False)`` shim).
# - SYSTEM_INJECTED keys are stripped before validation (round-trip safety).
# - Failure path aggregates errors across all entries, identifies each
#   violation by ``config[idx]`` / bucket / identifier, and prunes invalid
#   entries from the downstream write buckets.
# - Validation runs across all three buckets (force_create, direct_action,
#   normal).


def _run_validation(
    monkeypatch: pytest.MonkeyPatch,
    *,
    force_create_items: list[dict] | None = None,
    direct_action_items: list[dict] | None = None,
    normal_config: list[dict] | None = None,
    state: str = "merged",
    fetch_responses: list[Any] | None = None,
    kill_switch: bool | None = None,
) -> tuple[FakeModule, ListLogger, FakeValidationOrchestrator]:
    """Compose a Validation harness:  FakeModule + ListLogger +
    FakeValidationOrchestrator pre-queued with ``fetch_responses``, then
    invoke ``_validate_template_inputs_in_buckets`` with the supplied
    buckets.  Returns the three pieces so tests can inspect.

    If ``kill_switch`` is supplied, the module-level
    ``_ENABLE_TEMPLATE_INPUT_VALIDATION`` constant is patched for the
    duration of the call.
    """
    module = FakeModule()
    log = ListLogger()
    orch = FakeValidationOrchestrator(responses=fetch_responses or [])

    if kill_switch is not None:
        monkeypatch.setattr(nd_manage_policy_group, "_ENABLE_TEMPLATE_INPUT_VALIDATION", kill_switch)

    failures = nd_manage_policy_group._validate_template_inputs_in_buckets(
        force_create_items=force_create_items or [],
        direct_action_items=direct_action_items or [],
        normal_config=normal_config or [],
        state=state,
        orchestrator=orch,
        log=log,
    )
    module.validation_failures = failures
    return module, log, orch


def test_nd_policy_group_module_00600(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` is a no-op when the
    kill switch ``_ENABLE_TEMPLATE_INPUT_VALIDATION`` is ``False``.

    ## Test

    - Kill switch off + a config entry that WOULD fail validation
      (unknown key) -> no fetch issued, no fail_json.

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    """
    module, log, orch = _run_validation(
        monkeypatch,
        normal_config=[{"name": "tpl_a", "description": "d1", "template_inputs": {"foo": "bar"}}],
        kill_switch=False,
    )
    assert module.fail_json_called is None
    assert orch.request_calls == []
    assert any("kill switch" in m or "disabled" in m for m in log.debug_msgs)


def test_nd_policy_group_module_00610(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` is a no-op for
    ``state="deleted"`` (the body never carries templateInputs).

    ## Test

    - state=deleted with config entries that have template_inputs ->
      no fetch issued.

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    """
    module, _log, orch = _run_validation(
        monkeypatch,
        normal_config=[{"name": "tpl_a", "description": "d1", "template_inputs": {"foo": "bar"}}],
        state="deleted",
    )
    assert module.fail_json_called is None
    assert orch.request_calls == []


def test_nd_policy_group_module_00620(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` is a no-op for
    ``state="gathered"`` (defence-in-depth -- ``main()`` short-circuits
    before reaching the hook for gathered, but the hook itself must
    refuse to validate read paths).

    ## Test

    - state=gathered -> no fetch issued even with non-empty buckets.

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    """
    module, _log, orch = _run_validation(
        monkeypatch,
        normal_config=[{"name": "tpl_a", "description": "d1", "template_inputs": {"foo": "bar"}}],
        state="gathered",
    )
    assert module.fail_json_called is None
    assert orch.request_calls == []


def test_nd_policy_group_module_00630(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` is a no-op when all
    buckets are empty.

    ## Test

    - All three buckets empty -> no fetch, no fail_json.

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    """
    module, _log, orch = _run_validation(monkeypatch)
    assert module.fail_json_called is None
    assert orch.request_calls == []


def test_nd_policy_group_module_00640(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` skips per-entry
    validation when ``template_inputs`` is missing or empty -- no GET
    is issued for those entries.

    ## Test

    - One entry with ``template_inputs={}`` + one with no
      ``template_inputs`` key + one with ``template_inputs=None`` ->
      zero GETs.

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    """
    module, _log, orch = _run_validation(
        monkeypatch,
        normal_config=[
            {"name": "tpl_a", "description": "d1", "template_inputs": {}},
            {"name": "tpl_b", "description": "d2"},
            {"name": "tpl_c", "description": "d3", "template_inputs": None},
        ],
    )
    assert module.fail_json_called is None
    assert orch.request_calls == []


def test_nd_policy_group_module_00650(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` skips per-entry
    validation when the entry's ``name`` is still a ``POLICY-GROUP-*``
    ID (defensive guard for any code path that bypasses
    ``_resolve_config``).

    ## Test

    - Entry with name=``POLICY-GROUP-1`` + non-empty template_inputs ->
      no GET issued, no fail_json.

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    """
    module, _log, orch = _run_validation(
        monkeypatch,
        direct_action_items=[
            {
                "name": "POLICY-GROUP-1",
                "policy_id": "POLICY-GROUP-1",
                "template_inputs": {"foo": "bar"},
            }
        ],
    )
    assert module.fail_json_called is None
    assert orch.request_calls == []


def test_nd_policy_group_module_00660(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` issues exactly one
    GET per unique template (N entries on the same template share the
    per-task cache).

    ## Test

    - 3 entries on "tpl_a" + 1 entry on "tpl_b" -> exactly 2 requests
      (one per unique template name).

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    """
    schema = [{"name": "key", "parameterType": "string", "optional": True}]
    module, _log, orch = _run_validation(
        monkeypatch,
        normal_config=[
            {"name": "tpl_a", "description": "d1", "template_inputs": {"key": "v1"}},
            {"name": "tpl_a", "description": "d2", "template_inputs": {"key": "v2"}},
            {"name": "tpl_b", "description": "d3", "template_inputs": {"key": "v3"}},
            {"name": "tpl_a", "description": "d4", "template_inputs": {"key": "v4"}},
        ],
        fetch_responses=[
            _make_params_response(schema),
            _make_params_response(schema),
        ],
    )
    assert module.fail_json_called is None
    # Exactly 2 requests issued: one per unique template_name
    assert len(orch.request_calls) == 2
    paths_hit = [c[0] for c in orch.request_calls]
    assert any("/configTemplates/tpl_a/parameters" in p for p in paths_hit)
    assert any("/configTemplates/tpl_b/parameters" in p for p in paths_hit)


def test_nd_policy_group_module_00670(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` forwards
    ``cluster_name`` via the orchestrator's ``_apply_endpoint_params``
    with ``with_ticket=False`` (the parameters endpoint is a read
    endpoint -- it accepts clusterName but NOT ticketId).

    ## Test

    - One entry triggering one fetch -> ``_apply_endpoint_params``
      called exactly once with ``with_ticket=False``.

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    - ``PolicyGroupOrchestrator._apply_endpoint_params`` (stubbed)
    """
    schema = [{"name": "key", "parameterType": "string", "optional": True}]
    module, _log, orch = _run_validation(
        monkeypatch,
        normal_config=[
            {"name": "tpl_a", "description": "d1", "template_inputs": {"key": "v1"}},
        ],
        fetch_responses=[_make_params_response(schema)],
    )
    assert module.fail_json_called is None
    assert len(orch.apply_params_calls) == 1
    assert orch.apply_params_calls[0]["with_ticket"] is False


def test_nd_policy_group_module_00680(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` strips
    ``SYSTEM_INJECTED_TEMPLATE_KEYS`` from ``template_inputs`` before
    validating -- so the ``gathered -> merged`` round-trip succeeds.

    ## Test

    - Entry whose ``template_inputs`` contains a known SYSTEM_INJECTED
      key (``POLICY_ID``) + a real user key matching the schema ->
      no fail_json (the stripped POLICY_ID would otherwise trip the
      unknown-key check).

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    """
    schema = [{"name": "hostname", "parameterType": "string", "optional": True}]
    module, _log, _orch = _run_validation(
        monkeypatch,
        normal_config=[
            {
                "name": "tpl_a",
                "description": "d1",
                "template_inputs": {"hostname": "leaf-01", "POLICY_ID": "POLICY-1"},
            }
        ],
        fetch_responses=[_make_params_response(schema)],
    )
    assert module.fail_json_called is None


def test_nd_policy_group_module_00690(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` aggregates errors
    across multiple entries, preserves valid entries in their bucket, and
    prunes invalid entries before downstream writes.

    ## Test

    - 2 entries on the same template; one passes, one has an unknown
      key.  Result: one structured failure references ``config[1]`` and
      the bad key; only the valid entry remains in ``normal_config``.

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    """
    schema = [{"name": "hostname", "parameterType": "string", "optional": True}]
    log = ListLogger()
    orch = FakeValidationOrchestrator(responses=[_make_params_response(schema)])
    normal_config = [
        {"name": "tpl_a", "description": "ok", "template_inputs": {"hostname": "leaf-01"}},
        {"name": "tpl_a", "description": "bad", "template_inputs": {"unknown_key": "x"}},
    ]

    failures = nd_manage_policy_group._validate_template_inputs_in_buckets(
        force_create_items=[],
        direct_action_items=[],
        normal_config=normal_config,
        state="merged",
        orchestrator=orch,
        log=log,
    )

    assert len(failures) == 1
    assert failures[0]["index"] == 1
    assert failures[0]["bucket"] == "normal"
    assert failures[0]["identifier"] == "bad"
    assert "unknown_key" in "; ".join(failures[0]["errors"])
    assert normal_config == [{"name": "tpl_a", "description": "ok", "template_inputs": {"hostname": "leaf-01"}}]
    # Only one request issued (cache hit on second entry)
    assert len(orch.request_calls) == 1


def test_nd_policy_group_module_00700(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` validates across
    all three buckets (force_create, direct_action, normal) and tags each
    returned failure with the correct bucket name.

    ## Test

    - One failing entry per bucket -> 3 failures, each tagged with its
      bucket name, and all three buckets pruned empty.

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    """
    schema = [{"name": "hostname", "parameterType": "string", "optional": True}]
    log = ListLogger()
    # All three buckets use the same template -> single GET, three validations
    orch = FakeValidationOrchestrator(responses=[_make_params_response(schema)])
    force_create_items = [
        {"name": "tpl_a", "create_additional_policy": True, "template_inputs": {"bad_fc": 1}},
    ]
    direct_action_items = [
        {"name": "tpl_a", "policy_id": "POLICY-GROUP-2", "description": "d2", "template_inputs": {"bad_da": 1}},
    ]
    normal_config = [
        {"name": "tpl_a", "description": "d3", "template_inputs": {"bad_norm": 1}},
    ]

    failures = nd_manage_policy_group._validate_template_inputs_in_buckets(
        force_create_items=force_create_items,
        direct_action_items=direct_action_items,
        normal_config=normal_config,
        state="merged",
        orchestrator=orch,
        log=log,
    )

    assert [failure["bucket"] for failure in failures] == [
        "force_create",
        "direct_action",
        "normal",
    ]
    all_errors = "; ".join(err for failure in failures for err in failure["errors"])
    assert "bad_fc" in all_errors
    assert "bad_da" in all_errors
    assert "bad_norm" in all_errors
    assert force_create_items == []
    assert direct_action_items == []
    assert normal_config == []


def test_nd_policy_group_module_00710(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` degrades gracefully
    when the parameters GET fails (e.g. transient 5xx).  The shared
    helper catches the exception, caches an empty schema for that
    template, and validation becomes a no-op for that entry (the
    controller's own validation is then authoritative).

    ## Test

    - GET raises RuntimeError -> empty schema cached, no fail_json,
      WARNING logged via the shared helper.

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    - ``common.template_validation.fetch_template_params``
    """
    module = FakeModule()
    log = ListLogger()
    orch = FakeValidationOrchestrator(responses=[RuntimeError("simulated 5xx")])

    nd_manage_policy_group._validate_template_inputs_in_buckets(
        force_create_items=[],
        direct_action_items=[],
        normal_config=[
            {"name": "tpl_a", "description": "d1", "template_inputs": {"hostname": "leaf-01"}},
        ],
        state="merged",
        orchestrator=orch,
        log=log,
    )

    assert module.fail_json_called is None
    # WARNING logged via shared helper
    assert any("simulated 5xx" in m for m in log.warning_msgs)


def test_nd_policy_group_module_00720(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` identifies each
    violated entry by ``description`` when present, falling back to
    ``policy_id`` when description is missing (direct-action /
    round-trip case).

    ## Test

    - One entry with description="my_desc" -> returned failure contains
      ``identifier == "my_desc"``.
    - One entry with policy_id but no description -> returned failure
      contains ``identifier == "POLICY-GROUP-X"``.

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    """
    schema = [{"name": "k", "parameterType": "string", "optional": True}]
    log = ListLogger()
    orch = FakeValidationOrchestrator(responses=[_make_params_response(schema)])

    failures = nd_manage_policy_group._validate_template_inputs_in_buckets(
        force_create_items=[],
        direct_action_items=[],
        normal_config=[
            {"name": "tpl_a", "description": "my_desc", "template_inputs": {"unknown": "x"}},
            {"name": "tpl_a", "policy_id": "POLICY-GROUP-X", "template_inputs": {"unknown": "y"}},
        ],
        state="merged",
        orchestrator=orch,
        log=log,
    )

    assert [failure["identifier"] for failure in failures] == [
        "my_desc",
        "POLICY-GROUP-X",
    ]


def test_nd_policy_group_module_00730(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify ``_validate_template_inputs_in_buckets`` happy-path: a
    schema-valid entry passes through without raising and without any
    fail_json side effect.

    ## Test

    - Entry matching the schema -> no fail_json, one GET issued, debug
      log records the pass.

    ## Classes and Methods

    - ``nd_manage_policy_group._validate_template_inputs_in_buckets``
    """
    schema = [
        {"name": "hostname", "parameterType": "string", "optional": True},
        {"name": "vlan", "parameterType": "Integer", "optional": True},
    ]
    module, log, orch = _run_validation(
        monkeypatch,
        normal_config=[
            {"name": "tpl_a", "description": "d1", "template_inputs": {"hostname": "leaf-01", "vlan": "10"}},
        ],
        fetch_responses=[_make_params_response(schema)],
    )
    assert module.fail_json_called is None
    assert len(orch.request_calls) == 1
    assert any("passed for all" in m for m in log.debug_msgs)
