# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for stateless / pure helpers in ``nd_policy_resources.py``.

This file covers everything that does NOT need a live ``NDPolicyModule``
instance (no ``self.log``, no ``self._warnings``, no API calls). The full
instance-method surface (state machine, caches, request wiring,
``_parse_mark_delete_response``) is exercised in
``test_nd_policy_resources_module.py`` with the FakeND harness.

Covered helpers:

- ``_looks_like_ipv4`` (module-level free function)
- ``NDPolicyModule._is_policy_id`` (staticmethod)
- ``NDPolicyModule._strip_internal`` (classmethod) + ``_INTERNAL_WANT_KEYS``
- ``NDPolicyModule._escape_lucene_value`` (classmethod)
- ``NDPolicyModule._build_lucene_filter`` (classmethod)
- ``NDPolicyModule._policies_differ`` (staticmethod)
- ``NDPolicyModule._inspect_207_policies`` (staticmethod)
- ``NDPolicyModule.translate_config`` (staticmethod)
"""

# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.nd_policy_resources import (
    NDPolicyModule,
    _looks_like_ipv4,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModuleError
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: _looks_like_ipv4 (module-level function)
# =============================================================================


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.1",
        "192.168.1.254",
        "1.1.1.1",
        "255.255.255.255",
        "0.0.0.0",
        "  10.0.0.1  ",  # leading/trailing whitespace tolerated by .strip()
    ],
)
def test_nd_policy_resources_helpers_00010(value) -> None:
    """
    # Summary

    Verify ``_looks_like_ipv4`` returns ``True`` for valid dotted-quad
    IPv4 strings (with each octet in the 0-255 range).

    ## Test

    - Returns ``True`` for canonical IPv4 strings.
    - Leading/trailing whitespace is tolerated (via ``.strip()``).

    ## Classes and Methods

    - ``_looks_like_ipv4``
    """
    assert _looks_like_ipv4(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        0,
        False,
        "FDO25031SY4",  # serial number, not an IP
        "10.0.0",  # only 3 octets
        "10.0.0.1.2",  # 5 octets
        "10.0.0.256",  # octet > 255
        "10.0.0.-1",  # negative
        "a.b.c.d",  # non-numeric
        "10..0.1",  # empty octet
    ],
)
def test_nd_policy_resources_helpers_00020(value) -> None:
    """
    # Summary

    Verify ``_looks_like_ipv4`` returns ``False`` for non-IPv4 inputs:
    empty / falsy values, serial numbers, malformed dotted strings, and
    out-of-range octets.

    ## Test

    - Returns ``False`` for empty, ``None``, falsy, malformed, or
      out-of-range inputs.

    ## Classes and Methods

    - ``_looks_like_ipv4``
    """
    assert _looks_like_ipv4(value) is False


# =============================================================================
# Test: NDPolicyModule._is_policy_id (staticmethod)
# =============================================================================


@pytest.mark.parametrize(
    "name",
    [
        "POLICY-28440",
        "POLICY-1",
        "policy-28440",  # lower-case prefix
        "Policy-28440",  # mixed case
        "POLICY-",  # bare prefix (still matches)
    ],
)
def test_nd_policy_resources_helpers_00100(name) -> None:
    """
    # Summary

    Verify ``_is_policy_id`` detects the ``POLICY-`` prefix
    case-insensitively. The check ``name.upper().startswith("POLICY-")``
    is what allows users to feed gathered output back through merged
    state for in-place updates.

    ## Test

    - Returns ``True`` for any case variation of the ``POLICY-`` prefix.

    ## Classes and Methods

    - ``NDPolicyModule._is_policy_id``
    """
    assert NDPolicyModule._is_policy_id(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "feature_enable",
        "switch_freeform",
        "policy_28440",  # underscore, not hyphen
        "POLICYwithout-hyphen",  # contains "POLICY" but not "POLICY-"
        " POLICY-1",  # leading whitespace breaks startswith
    ],
)
def test_nd_policy_resources_helpers_00110(name) -> None:
    """
    # Summary

    Verify ``_is_policy_id`` rejects template names and other
    near-matches that do NOT start with ``POLICY-`` (so they fall
    through to the template-name code path).

    ## Test

    - Returns ``False`` for template-name strings and near-matches.

    ## Classes and Methods

    - ``NDPolicyModule._is_policy_id``
    """
    assert NDPolicyModule._is_policy_id(name) is False


# =============================================================================
# Test: NDPolicyModule._strip_internal (classmethod) + _INTERNAL_WANT_KEYS
# =============================================================================


def test_nd_policy_resources_helpers_00200() -> None:
    """
    # Summary

    Verify ``_INTERNAL_WANT_KEYS`` ClassVar is a frozenset containing the
    documented control flags that must not leak into user-facing output.

    ## Test

    - ``_INTERNAL_WANT_KEYS`` includes ``create_additional_policy``.
    - Is a frozenset (immutable).

    ## Classes and Methods

    - ``NDPolicyModule._INTERNAL_WANT_KEYS``
    """
    assert isinstance(NDPolicyModule._INTERNAL_WANT_KEYS, frozenset)
    assert "create_additional_policy" in NDPolicyModule._INTERNAL_WANT_KEYS


def test_nd_policy_resources_helpers_00210() -> None:
    """
    # Summary

    Verify ``_strip_internal(None)`` returns an empty dict (caller-safe
    "nothing-here" sentinel).

    ## Test

    - ``_strip_internal(None) == {}``.

    ## Classes and Methods

    - ``NDPolicyModule._strip_internal``
    """
    assert NDPolicyModule._strip_internal(None) == {}


def test_nd_policy_resources_helpers_00220() -> None:
    """
    # Summary

    Verify ``_strip_internal({})`` returns a fresh empty dict (not the
    same object) -- guards against accidental aliasing.

    ## Test

    - ``_strip_internal({}) == {}``.
    - Returned dict is not the same object as the input.

    ## Classes and Methods

    - ``NDPolicyModule._strip_internal``
    """
    src: dict = {}
    out = NDPolicyModule._strip_internal(src)
    assert out == {}
    assert out is not src


def test_nd_policy_resources_helpers_00230() -> None:
    """
    # Summary

    Verify ``_strip_internal`` removes internal control keys while
    preserving all other fields verbatim.

    ## Test

    - ``create_additional_policy`` is removed.
    - All other keys / values are preserved.
    - Input dict is not mutated.

    ## Classes and Methods

    - ``NDPolicyModule._strip_internal``
    """
    src = {
        "name": "feature_enable",
        "description": "Enable LACP",
        "priority": 100,
        "template_inputs": {"featureName": "lacp"},
        "create_additional_policy": True,  # internal -- must be stripped
    }

    out = NDPolicyModule._strip_internal(src)

    assert out == {
        "name": "feature_enable",
        "description": "Enable LACP",
        "priority": 100,
        "template_inputs": {"featureName": "lacp"},
    }
    # Original dict unmodified
    assert "create_additional_policy" in src


def test_nd_policy_resources_helpers_00240() -> None:
    """
    # Summary

    Verify ``_strip_internal`` on a dict containing none of the
    ``_INTERNAL_WANT_KEYS`` returns a shallow copy with identical
    contents.

    ## Test

    - Output equals input.
    - Output is a different object (shallow copy).

    ## Classes and Methods

    - ``NDPolicyModule._strip_internal``
    """
    src = {"name": "feature_enable", "priority": 500}

    out = NDPolicyModule._strip_internal(src)

    assert out == src
    assert out is not src


# =============================================================================
# Test: NDPolicyModule._escape_lucene_value (classmethod)
# =============================================================================


@pytest.mark.parametrize(
    "value",
    [
        "FDO25031SY4",
        "feature_enable",
        "simple description",  # spaces left unescaped (tokenizer match)
        "alphanumeric123",
    ],
)
def test_nd_policy_resources_helpers_00300(value) -> None:
    """
    # Summary

    Verify ``_escape_lucene_value`` returns plain strings unchanged when
    they contain no Lucene special characters. Spaces are intentionally
    NOT escaped (ND tokenizer matches word-by-word).

    ## Test

    - Plain alphanumeric input is returned identical.

    ## Classes and Methods

    - ``NDPolicyModule._escape_lucene_value``
    """
    assert NDPolicyModule._escape_lucene_value(value) == value


def test_nd_policy_resources_helpers_00310() -> None:
    """
    # Summary

    Verify ``_escape_lucene_value`` escapes each documented Lucene
    special character with a single backslash.

    ## Test

    - For ``"+-!(){}[]^\"~*?:\\/"``, each char becomes ``\\<char>``.

    ## Classes and Methods

    - ``NDPolicyModule._escape_lucene_value``
    """
    raw = r'+-!(){}[]^"~*?:\/'

    out = NDPolicyModule._escape_lucene_value(raw)

    # Each special char must be prefixed with a single backslash
    expected = "".join(f"\\{c}" for c in raw)
    assert out == expected


def test_nd_policy_resources_helpers_00320() -> None:
    """
    # Summary

    Verify ``_escape_lucene_value`` correctly handles mixed input
    (special chars + plain text + spaces), preserving spaces and
    escaping only the special chars.

    ## Test

    - ``description: "policy: enable (v2)"`` is escaped to
      ``"policy\\: enable \\(v2\\)"`` (colon and parens escaped, space
      preserved).

    ## Classes and Methods

    - ``NDPolicyModule._escape_lucene_value``
    """
    out = NDPolicyModule._escape_lucene_value("policy: enable (v2)")
    assert out == r"policy\: enable \(v2\)"


def test_nd_policy_resources_helpers_00330() -> None:
    """
    # Summary

    Verify ``_escape_lucene_value`` returns the empty string when given
    the empty string (no special handling needed).

    ## Test

    - ``""`` -> ``""``.

    ## Classes and Methods

    - ``NDPolicyModule._escape_lucene_value``
    """
    assert NDPolicyModule._escape_lucene_value("") == ""


def test_nd_policy_resources_helpers_00340() -> None:
    """
    # Summary

    Verify ``_escape_lucene_value`` coerces non-string input via
    ``str()`` (so callers may pass ints / bools transparently).

    ## Test

    - ``12345`` -> ``"12345"``.

    ## Classes and Methods

    - ``NDPolicyModule._escape_lucene_value``
    """
    assert NDPolicyModule._escape_lucene_value(12345) == "12345"


# =============================================================================
# Test: NDPolicyModule._build_lucene_filter (classmethod)
# =============================================================================


def test_nd_policy_resources_helpers_00400() -> None:
    """
    # Summary

    Verify ``_build_lucene_filter`` joins ``key:value`` terms with
    ``" AND "`` in the supplied keyword order.

    ## Test

    - Two kwargs -> ``"k1:v1 AND k2:v2"``.

    ## Classes and Methods

    - ``NDPolicyModule._build_lucene_filter``
    """
    out = NDPolicyModule._build_lucene_filter(
        switchId="FDO123",
        templateName="feature_enable",
    )
    assert out == "switchId:FDO123 AND templateName:feature_enable"


def test_nd_policy_resources_helpers_00410() -> None:
    """
    # Summary

    Verify ``_build_lucene_filter`` skips ``None`` values (so callers can
    pass optional filters without conditional logic at the call site).

    ## Test

    - A ``None`` value is omitted from the output.

    ## Classes and Methods

    - ``NDPolicyModule._build_lucene_filter``
    """
    out = NDPolicyModule._build_lucene_filter(
        switchId="FDO123",
        templateName=None,  # must be skipped
        source="",  # empty string is NOT None and IS emitted
    )
    assert "templateName" not in out
    assert out == "switchId:FDO123 AND source:"


def test_nd_policy_resources_helpers_00420() -> None:
    """
    # Summary

    Verify ``_build_lucene_filter`` returns the empty string when all
    values are ``None`` (or no kwargs are supplied).

    ## Test

    - ``_build_lucene_filter()`` -> ``""``.
    - ``_build_lucene_filter(switchId=None)`` -> ``""``.

    ## Classes and Methods

    - ``NDPolicyModule._build_lucene_filter``
    """
    assert NDPolicyModule._build_lucene_filter() == ""
    assert NDPolicyModule._build_lucene_filter(switchId=None) == ""


def test_nd_policy_resources_helpers_00430() -> None:
    """
    # Summary

    Verify ``_build_lucene_filter`` escapes value-side special characters
    via ``_escape_lucene_value`` (keys are not escaped -- they are always
    ND schema fields).

    ## Test

    - A value containing ``"(v2)"`` is escaped to ``"\\(v2\\)"`` in the
      output.

    ## Classes and Methods

    - ``NDPolicyModule._build_lucene_filter``
    """
    out = NDPolicyModule._build_lucene_filter(description="policy (v2)")
    assert out == r"description:policy \(v2\)"


def test_nd_policy_resources_helpers_00440() -> None:
    """
    # Summary

    Verify ``_build_lucene_filter`` coerces non-string values via
    ``str()`` so numeric kwargs (e.g. priority) serialise cleanly.

    ## Test

    - Integer value is rendered as its decimal string.

    ## Classes and Methods

    - ``NDPolicyModule._build_lucene_filter``
    """
    out = NDPolicyModule._build_lucene_filter(priority=100)
    assert out == "priority:100"


# =============================================================================
# Test: NDPolicyModule._policies_differ (staticmethod)
# =============================================================================


def test_nd_policy_resources_helpers_00500() -> None:
    """
    # Summary

    Verify ``_policies_differ`` returns the empty dict when want and have
    are identical on all compared fields.

    ## Test

    - Identical inputs -> ``{}`` (no diff).

    ## Classes and Methods

    - ``NDPolicyModule._policies_differ``
    """
    want = {
        "description": "Enable LACP",
        "priority": 100,
        "templateInputs": {"featureName": "lacp"},
    }
    have = dict(want)

    assert NDPolicyModule._policies_differ(want, have) == {}


def test_nd_policy_resources_helpers_00510() -> None:
    """
    # Summary

    Verify ``_policies_differ`` flags a description change in the
    expected ``{"want": ..., "have": ...}`` shape.

    ## Test

    - Differing descriptions surface under the ``description`` key.

    ## Classes and Methods

    - ``NDPolicyModule._policies_differ``
    """
    want = {"description": "new", "priority": 500}
    have = {"description": "old", "priority": 500}

    out = NDPolicyModule._policies_differ(want, have)

    assert out == {"description": {"want": "new", "have": "old"}}


def test_nd_policy_resources_helpers_00520() -> None:
    """
    # Summary

    Verify ``_policies_differ`` flags a priority change.

    ## Test

    - Different priorities surface under the ``priority`` key.

    ## Classes and Methods

    - ``NDPolicyModule._policies_differ``
    """
    want = {"priority": 100}
    have = {"priority": 500}

    out = NDPolicyModule._policies_differ(want, have)

    assert out == {"priority": {"want": 100, "have": 500}}


def test_nd_policy_resources_helpers_00530() -> None:
    """
    # Summary

    Verify ``_policies_differ`` flags only ``templateInputs`` keys the
    user supplied; controller-injected keys (e.g. ``FABRIC_NAME``) on
    ``have`` are ignored to avoid false positives.

    ## Test

    - User-specified key with different value surfaces.
    - Controller-only key on ``have`` is ignored.

    ## Classes and Methods

    - ``NDPolicyModule._policies_differ``
    """
    want = {"templateInputs": {"featureName": "lacp"}}
    have = {"templateInputs": {"featureName": "vpc", "FABRIC_NAME": "fab1"}}

    out = NDPolicyModule._policies_differ(want, have)

    assert "templateInputs" in out
    assert out["templateInputs"] == {
        "featureName": {"want": "lacp", "have": "vpc"},
    }


def test_nd_policy_resources_helpers_00540() -> None:
    """
    # Summary

    Verify ``_policies_differ`` normalizes ``templateInputs`` comparison
    via ``str(...).strip()`` so that:

    - Python ``int`` 100 matches ND string ``"100"``.
    - Python ``True`` matches ND string ``"True"``.
    - Trailing whitespace is tolerated.

    ## Test

    - Mixed-type / whitespace-padded inputs do NOT trigger a diff.

    ## Classes and Methods

    - ``NDPolicyModule._policies_differ``
    """
    want = {
        "templateInputs": {
            "intVal": 100,
            "boolVal": True,
            "strVal": "hello",
        }
    }
    have = {
        "templateInputs": {
            "intVal": "100",
            "boolVal": "True",
            "strVal": "hello\n",  # trailing newline stripped
        }
    }

    assert NDPolicyModule._policies_differ(want, have) == {}


def test_nd_policy_resources_helpers_00550() -> None:
    """
    # Summary

    Verify ``_policies_differ`` preserves case when comparing
    ``templateInputs`` (NX-OS commands and descriptions are
    case-sensitive -- a lower-case fold would hide genuine drift).

    ## Test

    - Different-case strings are reported as different.

    ## Classes and Methods

    - ``NDPolicyModule._policies_differ``
    """
    want = {"templateInputs": {"hostname": "leaf-01"}}
    have = {"templateInputs": {"hostname": "LEAF-01"}}

    out = NDPolicyModule._policies_differ(want, have)

    assert "templateInputs" in out
    assert out["templateInputs"]["hostname"] == {
        "want": "leaf-01",
        "have": "LEAF-01",
    }


def test_nd_policy_resources_helpers_00560() -> None:
    """
    # Summary

    Verify ``_policies_differ`` treats missing ``description`` /
    ``priority`` as their documented defaults (``""`` / ``500``) so
    callers may omit them on either side.

    ## Test

    - Missing description compared against empty string -> no diff.
    - Missing priority compared against 500 -> no diff.

    ## Classes and Methods

    - ``NDPolicyModule._policies_differ``
    """
    want: dict = {}
    have = {"description": "", "priority": 500}

    assert NDPolicyModule._policies_differ(want, have) == {}


# =============================================================================
# Test: NDPolicyModule._inspect_207_policies (staticmethod)
# =============================================================================


def test_nd_policy_resources_helpers_00600() -> None:
    """
    # Summary

    Verify ``_inspect_207_policies`` returns three empty lists when the
    response body is not a dict (e.g. ``None``, list, string).

    ## Test

    - ``None`` -> ``([], [], [])``.
    - ``[]`` -> ``([], [], [])``.

    ## Classes and Methods

    - ``NDPolicyModule._inspect_207_policies``
    """
    assert NDPolicyModule._inspect_207_policies(None) == ([], [], [])
    assert NDPolicyModule._inspect_207_policies([]) == ([], [], [])


def test_nd_policy_resources_helpers_00610() -> None:
    """
    # Summary

    Verify ``_inspect_207_policies`` returns three empty lists when the
    expected top-level key is missing or non-list.

    ## Test

    - ``{}`` -> ``([], [], [])``.
    - ``{"policies": "oops"}`` -> ``([], [], [])``.

    ## Classes and Methods

    - ``NDPolicyModule._inspect_207_policies``
    """
    assert NDPolicyModule._inspect_207_policies({}) == ([], [], [])
    assert NDPolicyModule._inspect_207_policies({"policies": "oops"}) == ([], [], [])


def test_nd_policy_resources_helpers_00620() -> None:
    """
    # Summary

    Verify ``_inspect_207_policies`` correctly buckets a mixed-status
    response into (success, warning, failure) lists, preserving order
    within each bucket.

    ## Test

    - Items with ``status="success"`` go to succeeded.
    - Items with ``status="warning"`` go to warnings.
    - Items with ``status="failed"`` (or unknown) go to failed.

    ## Classes and Methods

    - ``NDPolicyModule._inspect_207_policies``
    """
    data = {
        "policies": [
            {"policyId": "P1", "status": "success"},
            {"policyId": "P2", "status": "warning", "message": "already deleted"},
            {"policyId": "P3", "status": "failed", "message": "bad request"},
            {"policyId": "P4", "status": "success"},
        ]
    }

    succeeded, warnings, failed = NDPolicyModule._inspect_207_policies(data)

    assert [p["policyId"] for p in succeeded] == ["P1", "P4"]
    assert [p["policyId"] for p in warnings] == ["P2"]
    assert [p["policyId"] for p in failed] == ["P3"]


def test_nd_policy_resources_helpers_00630() -> None:
    """
    # Summary

    Verify ``_inspect_207_policies`` comparison is case-insensitive on
    the status field (``"SUCCESS"`` / ``"Warning"`` are accepted).

    ## Test

    - Mixed-case status values are bucketed identically to lowercase.

    ## Classes and Methods

    - ``NDPolicyModule._inspect_207_policies``
    """
    data = {
        "policies": [
            {"policyId": "P1", "status": "SUCCESS"},
            {"policyId": "P2", "status": "Warning"},
            {"policyId": "P3", "status": "FAILED"},
        ]
    }

    succeeded, warnings, failed = NDPolicyModule._inspect_207_policies(data)

    assert [p["policyId"] for p in succeeded] == ["P1"]
    assert [p["policyId"] for p in warnings] == ["P2"]
    assert [p["policyId"] for p in failed] == ["P3"]


def test_nd_policy_resources_helpers_00640() -> None:
    """
    # Summary

    Verify ``_inspect_207_policies`` is defensive: missing-status and
    unknown-status entries go to the failed bucket (rather than silently
    passing).

    ## Test

    - Entry with no ``status`` key -> failed.
    - Entry with ``status="weird"`` -> failed.

    ## Classes and Methods

    - ``NDPolicyModule._inspect_207_policies``
    """
    data = {
        "policies": [
            {"policyId": "P1"},  # no status
            {"policyId": "P2", "status": "weird"},  # unknown status
        ]
    }

    succeeded, warnings, failed = NDPolicyModule._inspect_207_policies(data)

    assert succeeded == []
    assert warnings == []
    assert [p["policyId"] for p in failed] == ["P1", "P2"]


def test_nd_policy_resources_helpers_00650() -> None:
    """
    # Summary

    Verify ``_inspect_207_policies`` accepts an alternate top-level
    ``key`` argument (so callers can reuse the helper for other 207
    response shapes).

    ## Test

    - ``key="items"`` reads from the ``items`` list instead of
      ``policies``.

    ## Classes and Methods

    - ``NDPolicyModule._inspect_207_policies``
    """
    data = {"items": [{"id": "X", "status": "success"}]}

    succeeded, warnings, failed = NDPolicyModule._inspect_207_policies(data, key="items")

    assert [p["id"] for p in succeeded] == ["X"]
    assert warnings == []
    assert failed == []


# =============================================================================
# Test: NDPolicyModule.translate_config (staticmethod)
# =============================================================================


def test_nd_policy_resources_helpers_00700() -> None:
    """
    # Summary

    Verify ``translate_config`` returns an empty list for an empty /
    falsy config (no work to do).

    ## Test

    - ``[]`` -> ``[]``.
    - ``None`` -> ``[]``.

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    assert NDPolicyModule.translate_config([], use_desc_as_key=False) == []
    assert NDPolicyModule.translate_config(None, use_desc_as_key=False) == []


def test_nd_policy_resources_helpers_00710() -> None:
    """
    # Summary

    Verify the legacy two-level shape: globals + a ``switch`` entry are
    crossed into per-(global, switch) entries. Each emitted dict has
    ``switch`` set to the serial-number string.

    ## Test

    - 2 globals x 2 switches -> 4 flat entries (interleaved per switch).

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    config = [
        {"name": "g1", "description": "Global 1", "priority": 100},
        {"name": "g2", "description": "Global 2", "priority": 200},
        {"switch": [{"serial_number": "S1"}, {"serial_number": "S2"}]},
    ]

    out = NDPolicyModule.translate_config(config, use_desc_as_key=False)

    assert out == [
        {"name": "g1", "description": "Global 1", "priority": 100, "switch": "S1"},
        {"name": "g2", "description": "Global 2", "priority": 200, "switch": "S1"},
        {"name": "g1", "description": "Global 1", "priority": 100, "switch": "S2"},
        {"name": "g2", "description": "Global 2", "priority": 200, "switch": "S2"},
    ]


def test_nd_policy_resources_helpers_00720() -> None:
    """
    # Summary

    Verify legacy shape with NO globals and NO per-switch overrides:
    bare ``{"switch": sn}`` entries are emitted (one per switch). This
    is the deleted-state pattern "remove all on these switches".

    ## Test

    - Only the switch entry, no globals -> bare per-switch dicts.

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    config = [{"switch": [{"serial_number": "S1"}, {"serial_number": "S2"}]}]

    out = NDPolicyModule.translate_config(config, use_desc_as_key=False)

    assert out == [{"switch": "S1"}, {"switch": "S2"}]


def test_nd_policy_resources_helpers_00730() -> None:
    """
    # Summary

    Verify a per-switch override with the SAME name as a global
    REPLACES the global on that switch (when
    ``use_desc_as_key=False``). Other switches still get the global.

    ## Test

    - On S1, override wins (global skipped).
    - On S2, global is emitted normally.

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    config = [
        {"name": "g1", "priority": 100},
        {
            "switch": [
                {
                    "serial_number": "S1",
                    "policies": [{"name": "g1", "priority": 999}],  # override
                },
                {"serial_number": "S2"},
            ]
        },
    ]

    out = NDPolicyModule.translate_config(config, use_desc_as_key=False)

    assert out == [
        # S1: override wins (priority 999), global skipped
        {"name": "g1", "priority": 999, "switch": "S1"},
        # S2: gets the global as-is
        {"name": "g1", "priority": 100, "switch": "S2"},
    ]


def test_nd_policy_resources_helpers_00740() -> None:
    """
    # Summary

    Verify with ``use_desc_as_key=True``, BOTH the global AND the same-
    name per-switch override are emitted (no replacement). This is the
    "create_additional_policy" model where descriptions are the dedup
    key, not template names.

    ## Test

    - On S1, both global and override are present (in that order).

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    config = [
        {"name": "g1", "description": "first", "priority": 100},
        {
            "switch": [
                {
                    "serial_number": "S1",
                    "policies": [
                        {"name": "g1", "description": "second", "priority": 999},
                    ],
                }
            ]
        },
    ]

    out = NDPolicyModule.translate_config(config, use_desc_as_key=True)

    assert out == [
        {"name": "g1", "description": "first", "priority": 100, "switch": "S1"},
        {"name": "g1", "description": "second", "priority": 999, "switch": "S1"},
    ]


def test_nd_policy_resources_helpers_00750() -> None:
    """
    # Summary

    Verify a per-switch override whose template name does NOT appear in
    any global is always emitted as an "extra" (regardless of the
    ``use_desc_as_key`` flag).

    ## Test

    - Override with name not in globals -> emitted on that switch only.

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    config = [
        {"name": "g1", "priority": 100},
        {
            "switch": [
                {
                    "serial_number": "S1",
                    "policies": [{"name": "extra_only", "priority": 999}],
                },
                {"serial_number": "S2"},
            ]
        },
    ]

    out = NDPolicyModule.translate_config(config, use_desc_as_key=False)

    assert out == [
        {"name": "g1", "priority": 100, "switch": "S1"},
        {"name": "extra_only", "priority": 999, "switch": "S1"},
        {"name": "g1", "priority": 100, "switch": "S2"},
    ]


def test_nd_policy_resources_helpers_00760() -> None:
    """
    # Summary

    Verify ``translate_config`` does NOT mutate its input list (callers
    must be free to log / re-use the raw playbook config after).

    ## Test

    - Deep snapshot of input equals input after the call.

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    import copy

    config = [
        {"name": "g1", "priority": 100},
        {"switch": [{"serial_number": "S1"}]},
    ]
    snapshot = copy.deepcopy(config)

    NDPolicyModule.translate_config(config, use_desc_as_key=False)

    assert config == snapshot


def test_nd_policy_resources_helpers_00770() -> None:
    """
    # Summary

    Verify the self-contained / gathered-roundtrip shape: every named
    entry already carries its own ``switch: [...]`` list. The helper
    flattens this into per-entry dicts with ``switch`` as a string.

    ## Test

    - Self-contained entries are flattened without needing a separate
      global switch entry.
    - The first switch's ``serial_number`` becomes the ``switch`` value.

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    config = [
        {
            "name": "feature_enable",
            "priority": 100,
            "switch": [{"serial_number": "S1"}],
        },
        {
            "name": "switch_freeform",
            "priority": 200,
            "switch": [{"serial_number": "S2"}],
        },
    ]

    out = NDPolicyModule.translate_config(config, use_desc_as_key=False)

    assert out == [
        {"name": "feature_enable", "priority": 100, "switch": "S1"},
        {"name": "switch_freeform", "priority": 200, "switch": "S2"},
    ]


def test_nd_policy_resources_helpers_00780() -> None:
    """
    # Summary

    Verify gathered-roundtrip with ``policy_id``: the gathered helper's
    output carries ``policy_id`` (e.g. ``"POLICY-28440"``). When
    re-submitted, ``translate_config`` promotes that to ``name`` so
    merged state updates the existing policy by ID (instead of creating
    a duplicate).

    ## Test

    - ``policy_id`` is consumed off the entry.
    - The resulting ``name`` is the policy ID.

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    config = [
        {
            "name": "feature_enable",
            "policy_id": "POLICY-28440",
            "priority": 100,
            "switch": [{"serial_number": "S1"}],
        }
    ]

    out = NDPolicyModule.translate_config(config, use_desc_as_key=False)

    assert len(out) == 1
    entry = out[0]
    assert entry["name"] == "POLICY-28440"
    assert entry["switch"] == "S1"
    assert "policy_id" not in entry


def test_nd_policy_resources_helpers_00790() -> None:
    """
    # Summary

    Verify the "mixed shape" guard: combining legacy two-level entries
    (named entries WITHOUT embedded ``switch:``) with self-contained
    entries (named entries WITH embedded ``switch:``) in the same
    config raises ``NDModuleError`` -- silently misinterpreting the
    self-contained entry as the global switch entry would drop its
    policy fields on the floor.

    ## Test

    - Mixed shape raises ``NDModuleError`` mentioning the offending
      legacy entry name.

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    config = [
        # Legacy named entry (no embedded switch)
        {"name": "legacy_global", "priority": 100},
        # Self-contained named entry (has embedded switch)
        {
            "name": "feature_enable",
            "priority": 200,
            "switch": [{"serial_number": "S1"}],
        },
    ]

    with pytest.raises(NDModuleError):
        NDPolicyModule.translate_config(config, use_desc_as_key=False)


def test_nd_policy_resources_helpers_00800() -> None:
    """
    # Summary

    Verify ``translate_config`` accepts the ``ip`` alias for
    ``serial_number`` in switch entries (since the playbook arg-spec
    exposes both names). The IP value is carried forward verbatim as
    ``switch``; later, ``resolve_switch_identifiers`` translates IPs to
    serial numbers via the fabric inventory.

    ## Test

    - When a switch entry has only ``ip``, that value becomes the
      ``switch`` value on the emitted dict.

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    config = [
        {"name": "g1", "priority": 100},
        {"switch": [{"ip": "10.1.2.3"}]},
    ]

    out = NDPolicyModule.translate_config(config, use_desc_as_key=False)

    assert out == [{"name": "g1", "priority": 100, "switch": "10.1.2.3"}]


def test_nd_policy_resources_helpers_00810() -> None:
    """
    # Summary

    Verify smoke test: ``translate_config`` does not raise on a typical
    gathered-output dict shape (no globals, one self-contained entry
    with both ``serial_number`` and ``policy_id``).

    ## Test

    - Smoke: does not raise; returns one entry with promoted ``name``
      and string ``switch``.

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    config = [
        {
            "name": "feature_enable",
            "policy_id": "POLICY-99",
            "description": "Enable LACP",
            "priority": 100,
            "template_inputs": {"featureName": "lacp"},
            "create_additional_policy": False,
            "switch": [{"serial_number": "FDO123"}],
        }
    ]

    with does_not_raise():
        out = NDPolicyModule.translate_config(config, use_desc_as_key=False)

    assert len(out) == 1
    assert out[0]["name"] == "POLICY-99"
    assert out[0]["switch"] == "FDO123"
    assert out[0]["template_inputs"] == {"featureName": "lacp"}


def test_nd_policy_resources_helpers_00820() -> None:
    """
    # Summary

    Verify policy entries paired with an empty ``switch:`` list raise
    ``NDModuleError`` instead of silently returning ``[]``. This guards
    against a Jinja expression rendering the switch list to ``[]`` at
    runtime, which would otherwise drop the request on the floor.

    ## Test

    - Policy entry(ies) + empty switch list -> raises ``NDModuleError``
      whose message names the offending entries.

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    config = [
        {"name": "POLICY-12345"},
        {"switch": []},
    ]

    with pytest.raises(NDModuleError) as exc:
        NDPolicyModule.translate_config(config, use_desc_as_key=False)

    assert "POLICY-12345" in str(exc.value)
    assert "switch" in str(exc.value).lower()


def test_nd_policy_resources_helpers_00830() -> None:
    """
    # Summary

    Verify the genuine no-op case is preserved: a config with ONLY an
    empty ``switch:`` entry (no policy entries at all) still returns
    ``[]`` quietly. Only the policy-entries-plus-empty-switch case is
    treated as a user error.

    ## Test

    - ``[{"switch": []}]`` -> ``[]`` (no error).

    ## Classes and Methods

    - ``NDPolicyModule.translate_config``
    """
    config = [{"switch": []}]

    with does_not_raise():
        out = NDPolicyModule.translate_config(config, use_desc_as_key=False)

    assert out == []
