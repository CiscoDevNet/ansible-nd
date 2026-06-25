# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``NDPolicyModule`` instance methods.

This file complements ``test_nd_policy_resources_helpers.py`` (which
covers the pure / static helpers) by exercising the methods that require
a live ``NDPolicyModule`` instance: constructor, sticky call-info stash,
template-input validation against an in-memory cache, the cache-backed
``_build_have_from_cache`` (Cases A/B/C/D), and the
``_parse_mark_delete_response`` 207 classifier.

A small file-private harness (``FakeAnsibleModule`` + ``FakeND`` +
``ListLogger`` + ``_make_module``) avoids needing the real Ansible
module + REST stack. The state machine and execution layer
(``manage_state`` / ``_handle_*_state`` / ``_execute_*``) are NOT
exercised here -- they require the full FakeRestSend harness and are
covered by the integration tests under ``tests/integration/targets/nd_manage_policy``.
"""

# pylint: disable=use-implicit-booleaness-not-comparison
# pylint: disable=protected-access

from __future__ import annotations

from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.nd_policy_resources import (
    NDPolicyModule,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Lightweight test harness (file-private)
# =============================================================================


class ListLogger:
    """Drop-in logger replacement that captures messages into in-memory lists.

    Each call records the formatted message (after %-style interpolation) into
    a per-level list so tests can assert what was logged without depending on
    Python's logging framework configuration.
    """

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


class FakeAnsibleModule:
    """Minimal Ansible-module stand-in providing the attributes
    ``NDPolicyModule.__init__`` reads at construction time."""

    def __init__(
        self,
        params: dict[str, Any] | None = None,
        check_mode: bool = False,
        verbosity: int = 0,
    ) -> None:
        self.params: dict[str, Any] = params or {}
        self.check_mode: bool = check_mode
        self._verbosity: int = verbosity
        self.warnings: list[str] = []

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    @staticmethod
    def fail_json(msg: str, **_kwargs: object) -> None:  # pragma: no cover
        raise AssertionError(f"FakeAnsibleModule.fail_json called: {msg}")

    @staticmethod
    def exit_json(**_kwargs: object) -> None:  # pragma: no cover
        raise AssertionError("FakeAnsibleModule.exit_json called unexpectedly")


class FakeND:
    """Minimal ``NDModule`` stand-in. Wraps the FakeAnsibleModule and
    provides a programmable ``request()`` whose responses are queued
    by the test (one per call, dequeued FIFO)."""

    def __init__(self, module: FakeAnsibleModule) -> None:
        self.module = module
        self._responses: list[object] = []
        self.calls: list[tuple[str, Any, dict | None]] = []

    def queue(self, *responses: object) -> None:
        """Queue zero or more responses for upcoming ``request()`` calls."""
        self._responses.extend(responses)

    def request(self, path: str, verb: Any, payload: dict | None = None) -> object:
        self.calls.append((path, verb, payload))
        if not self._responses:
            raise AssertionError(f"FakeND.request called with no queued response: " f"path={path!r}, verb={verb!r}, payload={payload!r}")
        return self._responses.pop(0)


def _default_params(**overrides: object) -> dict[str, Any]:
    """Return the minimal params dict that ``NDPolicyModule.__init__`` reads."""
    params: dict[str, Any] = {
        "fabric_name": "fab-test",
        "state": "merged",
        "config": [
            {
                "name": "feature_enable",
                "switch": [{"serial_number": "FDO111"}],
            }
        ],
        "use_desc_as_key": False,
        "deploy": True,
        "ticket_id": None,
        "cluster_name": None,
        "output_level": "normal",
    }
    params.update(overrides)
    return params


def _make_module(
    *,
    params: dict[str, Any] | None = None,
    check_mode: bool = False,
) -> tuple[NDPolicyModule, FakeND, ListLogger]:
    """Build an ``NDPolicyModule`` with a FakeND + ListLogger and return all
    three so tests can inspect calls / log lines."""
    ans = FakeAnsibleModule(
        params=params or _default_params(),
        check_mode=check_mode,
    )
    nd = FakeND(ans)
    logger = ListLogger()
    module = NDPolicyModule(nd=nd, results=Results(), logger=logger)  # type: ignore[arg-type]
    return module, nd, logger


class FakeEndpoint:
    """Endpoint stand-in exposing the two attributes ``_record_call`` reads."""

    def __init__(self, path: str | None, verb: object) -> None:
        self.path = path
        self.verb = verb


# =============================================================================
# Test: __init__ invariants
# =============================================================================


def test_nd_policy_resources_module_00010() -> None:
    """
    # Summary

    Verify ``NDPolicyModule.__init__`` wires up the documented module
    parameters from ``ansible_module.params``.

    ## Test

    - ``fabric_name`` / ``state`` / ``use_desc_as_key`` / ``deploy`` /
      ``cluster_name`` / ``ticket_id`` / ``check_mode`` come from
      ``params`` (or ``check_mode``).

    ## Classes and Methods

    - ``NDPolicyModule.__init__``
    """
    module, _nd, _log = _make_module(
        params=_default_params(
            fabric_name="fab-x",
            state="merged",
            use_desc_as_key=True,
            deploy=False,
            cluster_name="cluster-a",
            ticket_id="JIRA-1",
        ),
        check_mode=True,
    )

    assert module.fabric_name == "fab-x"
    assert module.state == "merged"
    assert module.use_desc_as_key is True
    assert module.deploy is False
    assert module.cluster_name == "cluster-a"
    assert module.ticket_id == "JIRA-1"
    assert module.check_mode is True


def test_nd_policy_resources_module_00020() -> None:
    """
    # Summary

    Verify all internal caches and accumulators are initialised to the
    documented empty / ``None`` defaults so downstream consumers can
    rely on them.

    ## Test

    - ``_template_params_cache`` / ``_policies_by_id_cache`` /
      ``_policies_by_switch_cache`` /
      ``_policies_by_switch_template_cache`` start empty.
    - ``_policies_cache`` is ``None`` (sentinel for "no prefetch yet").
    - ``_inventory`` is ``None``.
    - ``_before`` / ``_after`` / ``_proposed`` / ``_gathered`` /
      ``_warnings`` start as empty lists.
    - ``_call_path`` / ``_call_verb`` / ``_call_payload`` start at
      ``None``.

    ## Classes and Methods

    - ``NDPolicyModule.__init__``
    """
    module, _nd, _log = _make_module()

    assert module._template_params_cache == {}
    assert module._policies_cache is None
    assert module._policies_by_id_cache == {}
    assert module._policies_by_switch_cache == {}
    assert module._policies_by_switch_template_cache == {}
    assert module._inventory is None
    assert module._before == []
    assert module._after == []
    assert module._proposed == []
    assert module._gathered == []
    assert module._warnings == []
    assert module._call_path is None
    assert module._call_verb is None
    assert module._call_payload is None


def test_nd_policy_resources_module_00030() -> None:
    """
    # Summary

    Verify the constructor raises ``NDModuleError`` when ``config`` is
    missing AND the state is not ``"gathered"``. This is the early-fail
    that protects the rest of the orchestration code from a ``None``
    config.

    ## Test

    - ``state="merged"`` + ``config=None`` -> raises ``NDModuleError``.

    ## Classes and Methods

    - ``NDPolicyModule.__init__``
    """
    with pytest.raises(NDModuleError):
        _make_module(params=_default_params(state="merged", config=None))


def test_nd_policy_resources_module_00040() -> None:
    """
    # Summary

    Verify the constructor tolerates a missing ``config`` when
    ``state="gathered"``, defaulting ``self.config`` to ``[]`` so
    downstream iteration is safe.

    ## Test

    - ``state="gathered"`` + ``config=None`` does NOT raise.
    - ``module.config`` is the empty list.

    ## Classes and Methods

    - ``NDPolicyModule.__init__``
    """
    with does_not_raise():
        module, _nd, _log = _make_module(params=_default_params(state="gathered", config=None))

    assert module.state == "gathered"
    assert module.config == []


# =============================================================================
# Test: _record_call / _clear_call sticky stash
# =============================================================================


def test_nd_policy_resources_module_00100() -> None:
    """
    # Summary

    Verify ``_record_call`` stashes the endpoint's ``path`` / ``verb``
    and the supplied payload dict for downstream ``_apply_stashed_call``
    consumption.

    ## Test

    - After call, ``_call_path`` / ``_call_verb`` / ``_call_payload``
      reflect the inputs.

    ## Classes and Methods

    - ``NDPolicyModule._record_call``
    """
    module, _nd, _log = _make_module()
    ep = FakeEndpoint(path="/api/v1/policies", verb=HttpVerbEnum.POST)
    payload = {"policies": [{"switchId": "FDO111"}]}

    module._record_call(ep, payload)

    assert module._call_path == "/api/v1/policies"
    assert module._call_verb is HttpVerbEnum.POST
    assert module._call_payload == payload


def test_nd_policy_resources_module_00110() -> None:
    """
    # Summary

    Verify ``_record_call`` tolerates a payload of ``None`` (DELETE-style
    calls) by stashing ``None`` (not coercing to ``{}``).

    ## Test

    - ``payload=None`` -> ``_call_payload is None``.

    ## Classes and Methods

    - ``NDPolicyModule._record_call``
    """
    module, _nd, _log = _make_module()
    ep = FakeEndpoint(path="/api/v1/policies/POLICY-1", verb=HttpVerbEnum.DELETE)

    module._record_call(ep, None)

    assert module._call_path == "/api/v1/policies/POLICY-1"
    assert module._call_verb is HttpVerbEnum.DELETE
    assert module._call_payload is None


def test_nd_policy_resources_module_00120() -> None:
    """
    # Summary

    Verify ``_record_call`` ignores non-dict payloads (e.g. ``"oops"``)
    by stashing ``None`` -- defensive against accidental mistypes.

    ## Test

    - Non-dict payload -> ``_call_payload is None``.

    ## Classes and Methods

    - ``NDPolicyModule._record_call``
    """
    module, _nd, _log = _make_module()
    ep = FakeEndpoint(path="/x", verb=HttpVerbEnum.GET)

    module._record_call(ep, "oops")  # type: ignore[arg-type]

    assert module._call_payload is None


def test_nd_policy_resources_module_00130() -> None:
    """
    # Summary

    Verify ``_record_call`` handles a bad endpoint object (no ``.path``
    or ``.verb`` attributes) by resetting both to ``None`` rather than
    raising.

    ## Test

    - Endpoint missing ``.path`` / ``.verb`` -> stashed values are
      ``None``.

    ## Classes and Methods

    - ``NDPolicyModule._record_call``
    """
    module, _nd, _log = _make_module()

    class _Empty:  # no path or verb attributes
        pass

    with does_not_raise():
        module._record_call(_Empty(), {"k": "v"})

    assert module._call_path is None
    assert module._call_verb is None
    # payload is still stashed
    assert module._call_payload == {"k": "v"}


def test_nd_policy_resources_module_00140() -> None:
    """
    # Summary

    Verify ``_clear_call`` drops the stashed path/verb/payload so a
    subsequent synthetic register site does not inherit stale call
    info.

    ## Test

    - After ``_record_call`` then ``_clear_call``, all three stash
      fields are ``None``.

    ## Classes and Methods

    - ``NDPolicyModule._clear_call``
    """
    module, _nd, _log = _make_module()
    ep = FakeEndpoint(path="/x", verb=HttpVerbEnum.GET)
    module._record_call(ep, {"k": "v"})

    module._clear_call()

    assert module._call_path is None
    assert module._call_verb is None
    assert module._call_payload is None


# =============================================================================
# Test: _build_have_from_cache (Cases A / B / C / D)
# =============================================================================


def _seed_policy_cache(module: NDPolicyModule, policies: list[dict]) -> None:
    """Populate the three policy caches the way ``_prefetch_all_policies``
    would (minus the HTTP). The lookups in ``_build_have_from_cache`` rely
    only on these three indexes."""
    module._policies_cache = list(policies)
    module._policies_by_id_cache = {p["policyId"]: p for p in policies if "policyId" in p}
    by_switch: dict[str, list[dict]] = {}
    by_switch_tpl: dict[tuple[str, str], list[dict]] = {}
    for p in policies:
        sid = p.get("switchId")
        tpl = p.get("templateName")
        if sid is not None:
            by_switch.setdefault(sid, []).append(p)
            if tpl is not None:
                by_switch_tpl.setdefault((sid, tpl), []).append(p)
    module._policies_by_switch_cache = by_switch
    module._policies_by_switch_template_cache = by_switch_tpl


def test_nd_policy_resources_module_00200() -> None:
    """
    # Summary

    Verify Case A: when ``want`` carries ``policyId``, the lookup is an
    O(1) hit on the id index. Returns the single matching policy.

    ## Test

    - Matched policy returned as a single-item list.
    - ``error_msg`` is ``None``.

    ## Classes and Methods

    - ``NDPolicyModule._build_have_from_cache``
    """
    module, _nd, _log = _make_module()
    pol = {"policyId": "POLICY-1", "switchId": "FDO111", "templateName": "t"}
    _seed_policy_cache(module, [pol])

    have, err = module._build_have_from_cache({"policyId": "POLICY-1"})

    assert have == [pol]
    assert err is None


def test_nd_policy_resources_module_00210() -> None:
    """
    # Summary

    Verify Case A miss: ``policyId`` not in the index returns an empty
    list (NOT an error -- the diff classifier decides whether that is a
    Case 7 fail).

    ## Test

    - Unknown policy ID -> ``([], None)``.

    ## Classes and Methods

    - ``NDPolicyModule._build_have_from_cache``
    """
    module, _nd, _log = _make_module()
    _seed_policy_cache(module, [])

    have, err = module._build_have_from_cache({"policyId": "POLICY-999"})

    assert have == []
    assert err is None


def test_nd_policy_resources_module_00220() -> None:
    """
    # Summary

    Verify Case B: ``use_desc_as_key=False`` with both ``switchId`` and
    ``templateName`` uses the O(1) composite index.

    ## Test

    - All policies under the (switch, template) pair are returned.

    ## Classes and Methods

    - ``NDPolicyModule._build_have_from_cache``
    """
    module, _nd, _log = _make_module()
    p1 = {"policyId": "P1", "switchId": "FDO111", "templateName": "tpl_a"}
    p2 = {"policyId": "P2", "switchId": "FDO111", "templateName": "tpl_a"}
    other = {"policyId": "P3", "switchId": "FDO111", "templateName": "tpl_b"}
    _seed_policy_cache(module, [p1, p2, other])

    have, err = module._build_have_from_cache({"switchId": "FDO111", "templateName": "tpl_a"})

    assert have == [p1, p2]
    assert err is None


def test_nd_policy_resources_module_00230() -> None:
    """
    # Summary

    Verify Case B with an additional ``description`` post-filter: only
    policies whose description matches exactly are kept.

    ## Test

    - Two policies share (switch, template), but only one matches the
      requested description.

    ## Classes and Methods

    - ``NDPolicyModule._build_have_from_cache``
    """
    module, _nd, _log = _make_module()
    p1 = {
        "policyId": "P1",
        "switchId": "FDO111",
        "templateName": "tpl_a",
        "description": "desc-1",
    }
    p2 = {
        "policyId": "P2",
        "switchId": "FDO111",
        "templateName": "tpl_a",
        "description": "desc-2",
    }
    _seed_policy_cache(module, [p1, p2])

    have, err = module._build_have_from_cache({"switchId": "FDO111", "templateName": "tpl_a", "description": "desc-1"})

    assert have == [p1]
    assert err is None


def test_nd_policy_resources_module_00240() -> None:
    """
    # Summary

    Verify Case C: with ``use_desc_as_key=True``, the lookup matches by
    EXACT description across the entire switch (any template). This is
    what allows Case 15 (description matches existing policy under a
    different template -> delete+create).

    ## Test

    - Two policies share a switch but use different templates and
      different descriptions; only the description-match is returned.

    ## Classes and Methods

    - ``NDPolicyModule._build_have_from_cache``
    """
    module, _nd, _log = _make_module(params=_default_params(use_desc_as_key=True))
    p1 = {
        "policyId": "P1",
        "switchId": "FDO111",
        "templateName": "tpl_a",
        "description": "hit",
    }
    p2 = {
        "policyId": "P2",
        "switchId": "FDO111",
        "templateName": "tpl_b",
        "description": "miss",
    }
    _seed_policy_cache(module, [p1, p2])

    have, err = module._build_have_from_cache({"switchId": "FDO111", "templateName": "tpl_b", "description": "hit"})

    # Match by description across ALL templates on the switch, not just
    # the requested template.
    assert have == [p1]
    assert err is None


def test_nd_policy_resources_module_00250() -> None:
    """
    # Summary

    Verify Case C error path: ``use_desc_as_key=True`` requires a
    description -- supplying ``templateName`` without one is reported as
    an error rather than silently matching the empty string.

    ## Test

    - Want with ``templateName`` and no ``description`` ->
      ``([], "description is required ...")``.

    ## Classes and Methods

    - ``NDPolicyModule._build_have_from_cache``
    """
    module, _nd, _log = _make_module(params=_default_params(use_desc_as_key=True))
    _seed_policy_cache(module, [])

    have, err = module._build_have_from_cache({"switchId": "FDO111", "templateName": "tpl_a"})

    assert have == []
    assert err is not None
    assert "description is required" in err


def test_nd_policy_resources_module_00260() -> None:
    """
    # Summary

    Verify Case D: with neither ``policyId`` nor ``templateName``, the
    lookup returns ALL policies on the switch (no further filtering).

    ## Test

    - All switch policies returned.
    - Returned list is a copy (not the cached object) so callers can
      mutate freely.

    ## Classes and Methods

    - ``NDPolicyModule._build_have_from_cache``
    """
    module, _nd, _log = _make_module()
    p1 = {"policyId": "P1", "switchId": "FDO111", "templateName": "tpl_a"}
    p2 = {"policyId": "P2", "switchId": "FDO111", "templateName": "tpl_b"}
    other = {"policyId": "P3", "switchId": "FDO222", "templateName": "tpl_a"}
    _seed_policy_cache(module, [p1, p2, other])

    have, err = module._build_have_from_cache({"switchId": "FDO111"})

    assert have == [p1, p2]
    assert err is None
    # Defensive: returned list must not BE the cached list
    assert have is not module._policies_by_switch_cache["FDO111"]


def test_nd_policy_resources_module_00270() -> None:
    """
    # Summary

    Verify Case D miss: unknown ``switchId`` returns an empty list.

    ## Test

    - Unknown switch -> ``([], None)``.

    ## Classes and Methods

    - ``NDPolicyModule._build_have_from_cache``
    """
    module, _nd, _log = _make_module()
    _seed_policy_cache(module, [])

    have, err = module._build_have_from_cache({"switchId": "FDO999"})

    assert have == []
    assert err is None


# =============================================================================
# Test: _validate_template_inputs (via pre-seeded _template_params_cache)
# =============================================================================


def _seed_template_params(
    module: NDPolicyModule,
    template_name: str,
    params: list[dict],
) -> None:
    """Pre-populate ``_template_params_cache`` so ``_validate_template_inputs``
    skips the HTTP fetch."""
    module._template_params_cache[template_name] = params


def test_nd_policy_resources_module_00300() -> None:
    """
    # Summary

    Verify ``_validate_template_inputs`` returns ``[]`` (no errors) when
    the template has no parameter definitions (so validation is a no-op
    -- the controller's own validation is authoritative).

    ## Test

    - Empty params cache for the template -> empty error list.

    ## Classes and Methods

    - ``NDPolicyModule._validate_template_inputs``
    """
    module, _nd, _log = _make_module()
    _seed_template_params(module, "tpl_a", [])

    errors = module._validate_template_inputs("tpl_a", {"anything": "goes"})

    assert errors == []


def test_nd_policy_resources_module_00310() -> None:
    """
    # Summary

    Verify ``_validate_template_inputs`` flags keys that are not in the
    template parameter definition (Check 1: unknown keys).

    ## Test

    - Unknown ``foo`` key produces an error message containing ``foo``
      and the template name.
    - Known ``hostname`` does NOT produce an error.

    ## Classes and Methods

    - ``NDPolicyModule._validate_template_inputs``
    """
    module, _nd, _log = _make_module()
    _seed_template_params(
        module,
        "tpl_a",
        [{"name": "hostname", "parameterType": "string", "optional": True}],
    )

    errors = module._validate_template_inputs("tpl_a", {"hostname": "leaf-01", "foo": "bar"})

    assert len(errors) == 1
    assert "foo" in errors[0]
    assert "tpl_a" in errors[0]


def test_nd_policy_resources_module_00320() -> None:
    """
    # Summary

    Verify ``_validate_template_inputs`` allows controller-internal
    parameters (``annotations.IsInternal == "true"``) as valid keys
    without exposing them in the "valid keys" error message.

    ## Test

    - ``FABRIC_NAME`` (internal) is silently accepted, NOT flagged.

    ## Classes and Methods

    - ``NDPolicyModule._validate_template_inputs``
    """
    module, _nd, _log = _make_module()
    _seed_template_params(
        module,
        "tpl_a",
        [
            {"name": "hostname", "parameterType": "string", "optional": True},
            {
                "name": "FABRIC_NAME",
                "parameterType": "string",
                "annotations": {"IsInternal": "true"},
            },
        ],
    )

    errors = module._validate_template_inputs("tpl_a", {"hostname": "leaf-01", "FABRIC_NAME": "fab1"})

    assert errors == []


def test_nd_policy_resources_module_00330() -> None:
    """
    # Summary

    Verify ``_validate_template_inputs`` flags missing required
    parameters: ``optional=False`` AND ``defaultValue`` is empty.

    ## Test

    - Missing required ``vlan_id`` -> 1 error message.
    - Optional ``hostname`` (not supplied) -> no error.

    ## Classes and Methods

    - ``NDPolicyModule._validate_template_inputs``
    """
    module, _nd, _log = _make_module()
    _seed_template_params(
        module,
        "tpl_a",
        [
            {
                "name": "vlan_id",
                "parameterType": "Integer",
                "optional": False,
                "defaultValue": "",
            },
            {
                "name": "hostname",
                "parameterType": "string",
                "optional": True,
            },
        ],
    )

    errors = module._validate_template_inputs("tpl_a", {})

    assert len(errors) == 1
    assert "vlan_id" in errors[0]


def test_nd_policy_resources_module_00340() -> None:
    """
    # Summary

    Verify ``_validate_template_inputs`` accepts a required parameter
    that has a non-empty ``defaultValue`` even if the user did not
    supply it (since the controller will use the default).

    ## Test

    - Required ``vlan_id`` with ``defaultValue=10`` and no user input
      -> no error.

    ## Classes and Methods

    - ``NDPolicyModule._validate_template_inputs``
    """
    module, _nd, _log = _make_module()
    _seed_template_params(
        module,
        "tpl_a",
        [
            {
                "name": "vlan_id",
                "parameterType": "Integer",
                "optional": False,
                "defaultValue": "10",
            }
        ],
    )

    errors = module._validate_template_inputs("tpl_a", {})

    assert errors == []


def test_nd_policy_resources_module_00350() -> None:
    """
    # Summary

    Verify ``_validate_template_inputs`` accepts ``"true"`` / ``"false"``
    for ``parameterType=boolean`` (case-insensitive) and rejects
    everything else.

    ## Test

    - ``"true"`` / ``"false"`` / ``"True"`` / ``"FALSE"`` -> no error.
    - ``"yes"`` -> 1 error.

    ## Classes and Methods

    - ``NDPolicyModule._validate_template_inputs``
    """
    module, _nd, _log = _make_module()
    _seed_template_params(
        module,
        "tpl_a",
        [{"name": "flag", "parameterType": "boolean", "optional": True}],
    )

    for good in ("true", "false", "True", "FALSE"):
        assert module._validate_template_inputs("tpl_a", {"flag": good}) == []

    bad_errors = module._validate_template_inputs("tpl_a", {"flag": "yes"})
    assert len(bad_errors) == 1
    assert "boolean" in bad_errors[0]


def test_nd_policy_resources_module_00360() -> None:
    """
    # Summary

    Verify ``_validate_template_inputs`` rejects non-numeric values for
    ``parameterType=Integer`` (case-insensitively matched against
    ``"integer"``).

    ## Test

    - ``"abc"`` -> 1 error mentioning ``integer``.
    - ``"100"`` -> no error.

    ## Classes and Methods

    - ``NDPolicyModule._validate_template_inputs``
    """
    module, _nd, _log = _make_module()
    _seed_template_params(
        module,
        "tpl_a",
        [{"name": "n", "parameterType": "Integer", "optional": True}],
    )

    bad = module._validate_template_inputs("tpl_a", {"n": "abc"})
    good = module._validate_template_inputs("tpl_a", {"n": "100"})

    assert len(bad) == 1
    assert "integer" in bad[0].lower()
    assert good == []


def test_nd_policy_resources_module_00370() -> None:
    """
    # Summary

    Verify ``_validate_template_inputs`` rejects shape-invalid IPv4
    values for ``parameterType=ipV4Address``. The internal regex
    (``_IPV4_RE``) is intentionally shape-only (``^\\d{1,3}\\.\\d{1,3}
    \\.\\d{1,3}\\.\\d{1,3}$``); per-octet 0-255 enforcement is left to
    the controller, so this layer catches typos like missing octets or
    non-numeric input only.

    ## Test

    - ``"not.an.ip"`` -> 1 error mentioning IPv4.
    - ``"10.0.0"`` (3 octets) -> 1 error mentioning IPv4.
    - ``"10.0.0.1"`` -> no error.

    ## Classes and Methods

    - ``NDPolicyModule._validate_template_inputs``
    """
    module, _nd, _log = _make_module()
    _seed_template_params(
        module,
        "tpl_a",
        [{"name": "ip", "parameterType": "ipV4Address", "optional": True}],
    )

    bad_nonnumeric = module._validate_template_inputs("tpl_a", {"ip": "not.an.ip"})
    bad_short = module._validate_template_inputs("tpl_a", {"ip": "10.0.0"})
    good = module._validate_template_inputs("tpl_a", {"ip": "10.0.0.1"})

    assert len(bad_nonnumeric) == 1
    assert "ipv4" in bad_nonnumeric[0].lower()
    assert len(bad_short) == 1
    assert "ipv4" in bad_short[0].lower()
    assert good == []


def test_nd_policy_resources_module_00380() -> None:
    """
    # Summary

    Verify ``_validate_template_inputs`` enforces the ``validValues``
    enum list when supplied via ``metaProperties.validValues``.

    ## Test

    - Value in list -> no error.
    - Value NOT in list -> 1 error.

    ## Classes and Methods

    - ``NDPolicyModule._validate_template_inputs``
    """
    module, _nd, _log = _make_module()
    _seed_template_params(
        module,
        "tpl_a",
        [
            {
                "name": "mode",
                "parameterType": "enum",
                "optional": True,
                "metaProperties": {"validValues": "active,passive,off"},
            }
        ],
    )

    good = module._validate_template_inputs("tpl_a", {"mode": "active"})
    bad = module._validate_template_inputs("tpl_a", {"mode": "auto"})

    assert good == []
    assert len(bad) == 1
    assert "auto" in bad[0]


def test_nd_policy_resources_module_00390() -> None:
    """
    # Summary

    Verify ``_validate_template_inputs`` treats empty / whitespace
    values as "not set" and skips type validation for them. This
    matters for the gathered -> merged round-trip where the controller
    returns ``""`` for unset optional parameters.

    ## Test

    - Empty Integer / boolean / ipv4 values produce no errors.

    ## Classes and Methods

    - ``NDPolicyModule._validate_template_inputs``
    """
    module, _nd, _log = _make_module()
    _seed_template_params(
        module,
        "tpl_a",
        [
            {"name": "vlan", "parameterType": "Integer", "optional": True},
            {"name": "flag", "parameterType": "boolean", "optional": True},
            {"name": "ip", "parameterType": "ipV4Address", "optional": True},
        ],
    )

    errors = module._validate_template_inputs("tpl_a", {"vlan": "", "flag": "  ", "ip": ""})

    assert errors == []


# =============================================================================
# Test: _parse_mark_delete_response (deferred from helpers item)
# =============================================================================


def test_nd_policy_resources_module_00400() -> None:
    """
    # Summary

    Verify ``_parse_mark_delete_response`` treats a non-dict response as
    "all succeeded" (matches ND's known behaviour of occasionally
    returning a non-dict body on success). Also logs a warning.

    ## Test

    - Non-dict input -> ``(requested_ids, [], [])``.
    - A warning is logged.

    ## Classes and Methods

    - ``NDPolicyModule._parse_mark_delete_response``
    """
    module, _nd, log = _make_module()
    requested = ["POLICY-1", "POLICY-2"]

    succeeded, py_fail, other_fail = module._parse_mark_delete_response(
        None,
        requested,
        context_label="markDelete",
    )

    assert succeeded == requested
    assert py_fail == []
    assert other_fail == []
    assert any("non-dict" in m for m in log.warning_msgs)


def test_nd_policy_resources_module_00410() -> None:
    """
    # Summary

    Verify ``_parse_mark_delete_response`` treats an empty ``policies``
    list as "all succeeded" (ambiguous-response fallback) and logs a
    warning.

    ## Test

    - ``{"policies": []}`` with non-empty requested IDs ->
      ``(requested_ids, [], [])``.
    - A warning mentioning "ambiguous" / "empty" is logged.

    ## Classes and Methods

    - ``NDPolicyModule._parse_mark_delete_response``
    """
    module, _nd, log = _make_module()
    requested = ["POLICY-1", "POLICY-2"]

    succeeded, py_fail, other_fail = module._parse_mark_delete_response(
        {"policies": []},
        requested,
        context_label="markDelete",
    )

    assert succeeded == requested
    assert py_fail == []
    assert other_fail == []
    assert any("empty" in m for m in log.warning_msgs)


def test_nd_policy_resources_module_00420() -> None:
    """
    # Summary

    Verify ``_parse_mark_delete_response`` classifies a normal
    success/failure 207 body:

    - ``status=success`` -> ``mark_succeeded``.
    - ``status=failed`` with PYTHON message -> ``mark_failed_python``.
    - ``status=failed`` otherwise -> ``mark_failed_other``.

    ## Test

    - 4 IDs requested, 1 success / 1 PYTHON-fail / 1 generic-fail / 1
      missing-from-response -> the missing one is reported as succeeded
      (its ID is not in the failed set).

    ## Classes and Methods

    - ``NDPolicyModule._parse_mark_delete_response``
    """
    module, _nd, _log = _make_module()
    requested = ["P-S", "P-PY", "P-OTHER", "P-MISSING"]
    response = {
        "policies": [
            {"policyId": "P-S", "status": "success"},
            {
                "policyId": "P-PY",
                "status": "failed",
                "message": "Cannot delete content type PYTHON via markDelete",
            },
            {
                "policyId": "P-OTHER",
                "status": "failed",
                "message": "Generic backend error",
            },
            # P-MISSING is intentionally absent from the response
        ]
    }

    succeeded, py_fail, other_fail = module._parse_mark_delete_response(
        response,
        requested,
        context_label="markDelete",
    )

    # Order-preserved against requested
    assert succeeded == ["P-S", "P-MISSING"]
    assert py_fail == ["P-PY"]
    assert other_fail == ["P-OTHER"]


def test_nd_policy_resources_module_00430() -> None:
    """
    # Summary

    Verify ``_parse_mark_delete_response`` treats ``status=warning`` as
    a soft success: the policy does NOT go into either failure bucket
    AND a warning is appended to both ``self.log`` and
    ``self._warnings`` so the operator can audit ND-side state.

    ## Test

    - The warning ID is in ``mark_succeeded``.
    - ``self._warnings`` contains a message tagged with the
      ``context_label``.

    ## Classes and Methods

    - ``NDPolicyModule._parse_mark_delete_response``
    """
    module, _nd, log = _make_module()
    requested = ["P-WARN"]
    response = {
        "policies": [
            {
                "policyId": "P-WARN",
                "status": "warning",
                "message": "already in markDeleted state",
            }
        ]
    }

    succeeded, py_fail, other_fail = module._parse_mark_delete_response(
        response,
        requested,
        context_label="markDelete (delete_and_create)",
    )

    assert succeeded == ["P-WARN"]
    assert py_fail == []
    assert other_fail == []
    # Warning was surfaced both to log and to _warnings accumulator
    assert any("P-WARN" in m for m in log.warning_msgs)
    assert any("markDelete (delete_and_create)" in m for m in module._warnings)
    assert any("P-WARN" in m for m in module._warnings)


def test_nd_policy_resources_module_00440() -> None:
    """
    # Summary

    Verify ``_parse_mark_delete_response`` treats an empty
    ``requested_ids`` + empty ``policies`` list correctly:

    - ``requested_ids == []`` AND ``policies == []`` -> all three
      buckets empty (no ambiguous-response fallback because there is
      nothing to claim as succeeded).

    ## Test

    - Empty requested + empty response -> ``([], [], [])``.

    ## Classes and Methods

    - ``NDPolicyModule._parse_mark_delete_response``
    """
    module, _nd, _log = _make_module()

    succeeded, py_fail, other_fail = module._parse_mark_delete_response(
        {"policies": []},
        [],
        context_label="markDelete",
    )

    assert succeeded == []
    assert py_fail == []
    assert other_fail == []


def test_nd_policy_resources_module_00450() -> None:
    """
    # Summary

    Verify ``_parse_mark_delete_response`` case-insensitively matches
    ``"WARNING"`` and ``"SUCCESS"`` status values (the per-item status
    is normalised via ``.lower()``).

    ## Test

    - Mixed-case status values are classified identically to lowercase.

    ## Classes and Methods

    - ``NDPolicyModule._parse_mark_delete_response``
    """
    module, _nd, _log = _make_module()
    requested = ["P-S", "P-W"]
    response = {
        "policies": [
            {"policyId": "P-S", "status": "SUCCESS"},
            {"policyId": "P-W", "status": "Warning", "message": "soft"},
        ]
    }

    succeeded, py_fail, other_fail = module._parse_mark_delete_response(
        response,
        requested,
        context_label="markDelete",
    )

    # Both are non-failures
    assert succeeded == ["P-S", "P-W"]
    assert py_fail == []
    assert other_fail == []


def test_nd_policy_resources_module_00460() -> None:
    """
    # Summary

    Verify an active-cache skip under ``state=deleted`` + ``deploy=true`` is
    handled as a blind switch deploy.  No extra GET by policy ID/source is
    issued to prove that a pending ``markDeleted`` record exists.

    ## Classes and Methods

    - ``NDPolicyModule._execute_deleted``
    """
    module, nd, _log = _make_module(params=_default_params(state="deleted", deploy=True))
    nd.queue({"status": "Configuration deployment completed"})

    module._execute_deleted(
        [
            {
                "action": "skip",
                "want": {
                    "policyId": "POLICY-ORIG",
                    "description": "cleanup me",
                    "switchId": "SN1",
                },
                "policies": [],
                "policy_ids": [],
                "match_count": 0,
                "warning": None,
                "error_msg": None,
                "query_path": "/api/v1/manage/fabrics/fab-test/policies/POLICY-ORIG",
                "query_verb": HttpVerbEnum.GET,
            }
        ]
    )

    assert len(nd.calls) == 1
    assert "switchActions/deploy" in nd.calls[0][0]
    assert nd.calls[0][2] == {"switchIds": ["SN1"]}
    task = module.results._tasks[0]
    assert task.metadata["action"] == "policy_pending_delete_deploy"
    assert task.diff["validation"] == "skipped_active_cache_miss"
    assert task.diff["switch_ids"] == ["SN1"]
    assert task.result["found"] is False


def test_nd_policy_resources_module_00470() -> None:
    """
    # Summary

    Verify active markDelete switch targets and blind pending-delete switch
    targets are deployed in one consolidated switchActions/deploy call.

    ## Classes and Methods

    - ``NDPolicyModule._delete_policies_with_fallback``
    """
    module, nd, _log = _make_module(params=_default_params(state="deleted", deploy=True))
    nd.queue(
        {"policies": [{"policyId": "P-ACTIVE", "status": "success"}]},
        {"status": "Configuration deployment completed"},
    )

    module._delete_policies_with_fallback(
        ["P-ACTIVE"],
        policy_switch_map={"P-ACTIVE": "SN1"},
        context_label="markDelete",
        register_results=True,
        extra_deploy_switch_ids={"SN2"},
        extra_deploy_wants=[{"policyId": "P-PENDING", "switchId": "SN2"}],
    )

    assert len(nd.calls) == 2
    assert "markDelete" in nd.calls[0][0]
    assert "switchActions/deploy" in nd.calls[1][0]
    assert nd.calls[1][2] == {"switchIds": ["SN1", "SN2"]}
    deploy_task = [
        task for task in module.results._tasks if task.metadata["action"] == "policy_switch_deploy"
    ][0]
    assert deploy_task.diff["policy_ids"] == ["P-ACTIVE"]
    assert deploy_task.diff["blind_pending_delete_switch_ids"] == ["SN2"]


def test_nd_policy_resources_module_00480() -> None:
    """
    # Summary

    Verify markDelete successes, direct-DELETE fallbacks, and blind pending
    cleanup targets share one deploy call after the direct DELETE fallback has
    completed.

    ## Classes and Methods

    - ``NDPolicyModule._delete_policies_with_fallback``
    """
    module, nd, _log = _make_module(params=_default_params(state="deleted", deploy=True))
    nd.queue(
        {
            "policies": [
                {"policyId": "P-MARK", "status": "success"},
                {
                    "policyId": "P-PY",
                    "status": "failed",
                    "message": "Cannot delete content type PYTHON via markDelete",
                },
            ]
        },
        {},
        {"status": "Configuration deployment completed"},
    )

    module._delete_policies_with_fallback(
        ["P-MARK", "P-PY"],
        policy_switch_map={"P-MARK": "SN1", "P-PY": "SN2"},
        policy_template_map={"P-PY": "switch_freeform"},
        context_label="markDelete",
        register_results=True,
        extra_deploy_switch_ids={"SN3"},
    )

    assert len(nd.calls) == 3
    assert "markDelete" in nd.calls[0][0]
    assert nd.calls[1][1] == HttpVerbEnum.DELETE
    assert "switchActions/deploy" in nd.calls[2][0]
    assert nd.calls[2][2] == {"switchIds": ["SN1", "SN2", "SN3"]}
