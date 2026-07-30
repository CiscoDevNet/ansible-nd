# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for ``plugins/module_utils/common/template_validation.py``.

Covers the three public helpers:

- ``validate_template_inputs``  -- pure schema check, no I/O
- ``fetch_template_params``     -- cached GET with caller-injected request
- ``strip_system_injected_keys`` -- pre-step that removes controller-injected
  control keys (``POLICY_ID``, ``FABRIC_ID``, ...) before validation

The helper is consumed both by ``NDPolicyModule`` (via the instance
wrappers ``_fetch_template_params`` / ``_validate_template_inputs`` /
``_clean_template_inputs`` on ``plugins/module_utils/nd_policy_resources.py``)
and by ``nd_manage_policy_group`` (via the module-level
``_validate_template_inputs_in_buckets`` hook).  These tests pin every
observable behaviour of the helper so both consumers can rely on it.

Notably absent: any orchestrator, Pydantic, NDModule, or Ansible Module
import.  The helper is pure-Python, so the test surface is too.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.common.template_validation import (
    _IPV4_RE,
    _IPV4_SUBNET_RE,
    _MAC_RE,
    fetch_template_params,
    strip_system_injected_keys,
    validate_template_inputs,
)
from ansible_collections.cisco.nd.plugins.module_utils.constants import (
    SYSTEM_INJECTED_TEMPLATE_KEYS,
)

# =============================================================================
# Test fixtures
# =============================================================================


class ListLogger:
    """Minimal ``logging.Logger`` stand-in that captures messages by level.

    Mirrors the ``ListLogger`` used in ``test_nd_policy_resources_module.py``
    so assertions can read ``log.debug_msgs`` / ``log.info_msgs`` /
    ``log.warning_msgs`` / ``log.error_msgs`` directly.
    """

    def __init__(self) -> None:
        self.debug_msgs: list[str] = []
        self.info_msgs: list[str] = []
        self.warning_msgs: list[str] = []
        self.error_msgs: list[str] = []

    # Methods named to match logging.Logger -- the helper only ever calls
    # these four levels so we do not need the full Logger surface.
    def debug(self, msg: str, *args: Any) -> None:  # noqa: D401
        self.debug_msgs.append(msg % args if args else msg)

    def info(self, msg: str, *args: Any) -> None:
        self.info_msgs.append(msg % args if args else msg)

    def warning(self, msg: str, *args: Any) -> None:
        self.warning_msgs.append(msg % args if args else msg)

    def error(self, msg: str, *args: Any) -> None:
        self.error_msgs.append(msg % args if args else msg)


class FakeEndpoint:
    """Endpoint stand-in exposing ``template_name``, ``path``, ``verb`` and
    ``endpoint_params``.

    Matches the shape that ``fetch_template_params`` requires of any
    endpoint instance produced by an ``endpoint_factory``.
    """

    def __init__(self) -> None:
        self.template_name: str | None = None
        # Endpoint_params is a small struct so callers can set cluster_name
        # / ticket_id via attribute assignment, mirroring the real
        # ``EpManageConfigTemplateParametersGet`` model.
        self.endpoint_params = type("EP", (), {"cluster_name": None, "ticket_id": None})()

    @property
    def path(self) -> str:
        return f"/api/v1/manage/configTemplates/{self.template_name}/parameters"

    @property
    def verb(self) -> str:
        return "GET"


def _make_factory():
    """Return a fresh ``FakeEndpoint`` factory and the produced-endpoint
    sink so tests can assert against the most recent endpoint instance."""
    produced: list[FakeEndpoint] = []

    def factory() -> FakeEndpoint:
        ep = FakeEndpoint()
        produced.append(ep)
        return ep

    return factory, produced


# =============================================================================
# Module-level regex sanity (compiled at import time)
# =============================================================================


def test_template_validation_00010() -> None:
    """
    # Summary

    Verify the three module-level regex constants are valid
    ``re.Pattern`` objects with the expected source strings.  These
    were moved verbatim from ``plugins/module_utils/nd_policy_resources.py``
    so any drift is caught at import time.

    ## Test

    - ``_IPV4_RE`` matches ``"10.0.0.1"`` but not ``"10.0.0"``.
    - ``_IPV4_SUBNET_RE`` matches ``"10.0.0.1/24"`` but not ``"10.0.0.1"``.
    - ``_MAC_RE`` matches both ``XXXX.XXXX.XXXX`` and
      ``XX:XX:XX:XX:XX:XX`` shapes.

    ## Classes and Methods

    - module-level regex constants
    """
    assert _IPV4_RE.match("10.0.0.1")
    assert _IPV4_RE.match("255.255.255.255")
    assert not _IPV4_RE.match("10.0.0")
    assert not _IPV4_RE.match("not.an.ip")

    assert _IPV4_SUBNET_RE.match("10.0.0.1/24")
    assert _IPV4_SUBNET_RE.match("0.0.0.0/0")
    assert not _IPV4_SUBNET_RE.match("10.0.0.1")
    assert not _IPV4_SUBNET_RE.match("10.0.0.1/")

    assert _MAC_RE.match("aabb.ccdd.eeff")
    assert _MAC_RE.match("AA:BB:CC:DD:EE:FF")
    assert _MAC_RE.match("00:11:22:33:44:55")
    assert not _MAC_RE.match("aabb.ccdd")
    assert not _MAC_RE.match("AA-BB-CC-DD-EE-FF")
    assert not _MAC_RE.match("not.a.mac")


# =============================================================================
# Test: validate_template_inputs -- empty / no-params behaviour
# =============================================================================


def test_template_validation_00100() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` returns ``[]`` (no errors) when
    the params list is empty -- validation is a no-op and the
    controller's own checks are authoritative.

    ## Test

    - Empty params + any inputs -> ``[]``.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    errors = validate_template_inputs("tpl_a", {"anything": "goes"}, [])
    assert errors == []


def test_template_validation_00110() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` accepts an empty inputs dict
    when no parameters are required.

    ## Test

    - All-optional params + empty inputs -> ``[]``.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [
        {"name": "hostname", "parameterType": "string", "optional": True},
        {"name": "mtu", "parameterType": "Integer", "optional": True},
    ]
    errors = validate_template_inputs("tpl_a", {}, params)
    assert errors == []


def test_template_validation_00120() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` silently skips parameter
    definitions that lack a ``name`` key (defensive against a
    malformed schema response).

    ## Test

    - Two-entry params list where the second has no ``name`` -> only
      the first is considered, no error for the second.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [
        {"name": "hostname", "parameterType": "string", "optional": True},
        {"parameterType": "string", "optional": True},  # no name
    ]
    errors = validate_template_inputs("tpl_a", {"hostname": "leaf-01"}, params)
    assert errors == []


# =============================================================================
# Test: validate_template_inputs -- Check 1 (unknown keys)
# =============================================================================


def test_template_validation_00200() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` flags keys that are not in the
    template parameter definition (Check 1: unknown keys).

    ## Test

    - Unknown ``foo`` key produces an error message containing ``foo``
      and the template name.
    - Known ``hostname`` does NOT produce an error.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [{"name": "hostname", "parameterType": "string", "optional": True}]
    errors = validate_template_inputs("tpl_a", {"hostname": "leaf-01", "foo": "bar"}, params)
    assert len(errors) == 1
    assert "foo" in errors[0]
    assert "tpl_a" in errors[0]


def test_template_validation_00210() -> None:
    """
    # Summary

    Verify the unknown-key error advertises ONLY user-facing valid
    keys (NOT internal-annotation parameters) in its "Valid keys: [...]"
    suggestion list, even though internal-annotation parameters are
    silently accepted as valid input keys.

    ## Test

    - Internal ``FABRIC_NAME`` is NOT listed in the error message for
      an unknown ``foo`` key.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [
        {"name": "hostname", "parameterType": "string", "optional": True},
        {
            "name": "FABRIC_NAME",
            "parameterType": "string",
            "annotations": {"IsInternal": "true"},
        },
    ]
    errors = validate_template_inputs("tpl_a", {"foo": "bar"}, params)
    assert len(errors) == 1
    assert "foo" in errors[0]
    # User-facing key listed, internal NOT
    assert "hostname" in errors[0]
    assert "FABRIC_NAME" not in errors[0]


def test_template_validation_00220() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` allows controller-internal
    parameters (``annotations.IsInternal == "true"``) as valid keys
    without flagging them as unknown.

    ## Test

    - ``FABRIC_NAME`` (internal) is silently accepted, NOT flagged.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [
        {"name": "hostname", "parameterType": "string", "optional": True},
        {
            "name": "FABRIC_NAME",
            "parameterType": "string",
            "annotations": {"IsInternal": "true"},
        },
    ]
    errors = validate_template_inputs("tpl_a", {"hostname": "leaf-01", "FABRIC_NAME": "fab1"}, params)
    assert errors == []


def test_template_validation_00230() -> None:
    """
    # Summary

    Verify the ``IsInternal`` annotation check is case-insensitive
    (``"True"`` / ``"TRUE"`` / ``"true"`` all flag the parameter as
    internal).  Mirrors the ``str(...).lower() == "true"`` check in
    the source.

    ## Test

    - ``"True"`` flags the parameter as internal -> no unknown-key error.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    for raw in ("true", "True", "TRUE"):
        params = [
            {
                "name": "POLICY_ID",
                "parameterType": "string",
                "annotations": {"IsInternal": raw},
            },
        ]
        errors = validate_template_inputs("tpl_a", {"POLICY_ID": "abc"}, params)
        assert errors == [], f"IsInternal=={raw!r} should flag as internal"


# =============================================================================
# Test: validate_template_inputs -- Check 2 (missing required)
# =============================================================================


def test_template_validation_00300() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` flags missing required
    parameters: ``optional=False`` AND ``defaultValue`` is empty.

    ## Test

    - Missing required ``vlan_id`` -> 1 error message.
    - Optional ``hostname`` (not supplied) -> no error.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [
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
    ]
    errors = validate_template_inputs("tpl_a", {}, params)
    assert len(errors) == 1
    assert "vlan_id" in errors[0]


def test_template_validation_00310() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` accepts a required parameter
    that has a non-empty ``defaultValue`` even if the user did not
    supply it (since the controller will use the default).

    ## Test

    - Required ``vlan_id`` with ``defaultValue=10`` and no user input
      -> no error.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [
        {
            "name": "vlan_id",
            "parameterType": "Integer",
            "optional": False,
            "defaultValue": "10",
        }
    ]
    errors = validate_template_inputs("tpl_a", {}, params)
    assert errors == []


def test_template_validation_00320() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` treats a ``defaultValue`` of
    ``None`` or whitespace-only the same as missing -- a required
    parameter with such a default still raises the missing error.

    ## Test

    - ``defaultValue=None`` + ``optional=False`` -> required.
    - ``defaultValue="   "`` + ``optional=False`` -> required.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    for default in (None, "   ", "\t\n"):
        params = [
            {
                "name": "vlan_id",
                "parameterType": "Integer",
                "optional": False,
                "defaultValue": default,
            }
        ]
        errors = validate_template_inputs("tpl_a", {}, params)
        assert len(errors) == 1, f"defaultValue={default!r} should be 'missing'"
        assert "vlan_id" in errors[0]


def test_template_validation_00330() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` treats ``optional`` defaulting
    to ``True`` (i.e. missing ``optional`` key) -- the parameter is
    considered optional and not flagged as missing.

    ## Test

    - Params without ``optional`` key -> treated as optional -> no
      missing-required error.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [{"name": "hostname", "parameterType": "string"}]
    errors = validate_template_inputs("tpl_a", {}, params)
    assert errors == []


# =============================================================================
# Test: validate_template_inputs -- Check 3 (per-type validation)
# =============================================================================


def test_template_validation_00400() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` accepts ``"true"`` / ``"false"``
    for ``parameterType=boolean`` (case-insensitive) and rejects
    everything else.

    ## Test

    - ``"true"`` / ``"false"`` / ``"True"`` / ``"FALSE"`` -> no error.
    - ``"yes"`` -> 1 error mentioning ``boolean``.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [{"name": "flag", "parameterType": "boolean", "optional": True}]

    for good in ("true", "false", "True", "FALSE"):
        assert validate_template_inputs("tpl_a", {"flag": good}, params) == []

    bad_errors = validate_template_inputs("tpl_a", {"flag": "yes"}, params)
    assert len(bad_errors) == 1
    assert "boolean" in bad_errors[0]


def test_template_validation_00410() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` rejects non-numeric values for
    ``parameterType=Integer`` (case-insensitively matched against
    ``"integer"``).

    ## Test

    - ``"abc"`` -> 1 error mentioning ``integer``.
    - ``"100"`` -> no error.
    - ``"-42"`` -> no error.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [{"name": "n", "parameterType": "Integer", "optional": True}]

    bad = validate_template_inputs("tpl_a", {"n": "abc"}, params)
    good_pos = validate_template_inputs("tpl_a", {"n": "100"}, params)
    good_neg = validate_template_inputs("tpl_a", {"n": "-42"}, params)

    assert len(bad) == 1
    assert "integer" in bad[0].lower()
    assert good_pos == []
    assert good_neg == []


def test_template_validation_00420() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` rejects non-numeric values for
    ``parameterType=long`` and mentions "long integer" in the error.

    ## Test

    - ``"abc"`` -> 1 error mentioning ``long``.
    - ``"1000000000000"`` -> no error.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [{"name": "big", "parameterType": "long", "optional": True}]
    bad = validate_template_inputs("tpl_a", {"big": "abc"}, params)
    good = validate_template_inputs("tpl_a", {"big": "1000000000000"}, params)
    assert len(bad) == 1
    assert "long" in bad[0].lower()
    assert good == []


def test_template_validation_00430() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` rejects non-numeric values for
    ``parameterType=float`` and mentions "float" in the error.

    ## Test

    - ``"abc"`` -> 1 error mentioning ``float``.
    - ``"3.14"`` -> no error.
    - ``"100"`` -> no error (int parses as float).

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [{"name": "x", "parameterType": "float", "optional": True}]
    bad = validate_template_inputs("tpl_a", {"x": "abc"}, params)
    good_frac = validate_template_inputs("tpl_a", {"x": "3.14"}, params)
    good_int = validate_template_inputs("tpl_a", {"x": "100"}, params)
    assert len(bad) == 1
    assert "float" in bad[0].lower()
    assert good_frac == []
    assert good_int == []


def test_template_validation_00440() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` rejects shape-invalid IPv4
    values for ``parameterType=ipV4Address``.  The internal regex
    (``_IPV4_RE``) is intentionally shape-only; per-octet 0-255
    enforcement is left to the controller.

    ## Test

    - ``"not.an.ip"`` -> 1 error mentioning IPv4.
    - ``"10.0.0"`` (3 octets) -> 1 error mentioning IPv4.
    - ``"10.0.0.1"`` -> no error.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [{"name": "ip", "parameterType": "ipV4Address", "optional": True}]

    bad_nonnumeric = validate_template_inputs("tpl_a", {"ip": "not.an.ip"}, params)
    bad_short = validate_template_inputs("tpl_a", {"ip": "10.0.0"}, params)
    good = validate_template_inputs("tpl_a", {"ip": "10.0.0.1"}, params)

    assert len(bad_nonnumeric) == 1
    assert "ipv4" in bad_nonnumeric[0].lower()
    assert len(bad_short) == 1
    assert "ipv4" in bad_short[0].lower()
    assert good == []


def test_template_validation_00450() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` treats ``parameterType=ipAddress``
    identically to ``ipV4Address`` (both route through the same regex
    branch in the source).

    ## Test

    - Same value validates / fails identically under both type aliases.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    p_v4 = [{"name": "ip", "parameterType": "ipV4Address", "optional": True}]
    p_alias = [{"name": "ip", "parameterType": "ipAddress", "optional": True}]

    assert validate_template_inputs("tpl_a", {"ip": "10.0.0.1"}, p_v4) == []
    assert validate_template_inputs("tpl_a", {"ip": "10.0.0.1"}, p_alias) == []

    e_v4 = validate_template_inputs("tpl_a", {"ip": "not.an.ip"}, p_v4)
    e_alias = validate_template_inputs("tpl_a", {"ip": "not.an.ip"}, p_alias)
    assert len(e_v4) == 1 and len(e_alias) == 1


def test_template_validation_00460() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` rejects shape-invalid CIDR
    values for ``parameterType=ipV4AddressWithSubnet``.

    ## Test

    - ``"10.0.0.1"`` (no prefix) -> 1 error mentioning subnet.
    - ``"10.0.0.1/24"`` -> no error.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [{"name": "cidr", "parameterType": "ipV4AddressWithSubnet", "optional": True}]
    bad = validate_template_inputs("tpl_a", {"cidr": "10.0.0.1"}, params)
    good = validate_template_inputs("tpl_a", {"cidr": "10.0.0.1/24"}, params)
    assert len(bad) == 1
    assert "subnet" in bad[0].lower()
    assert good == []


def test_template_validation_00470() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` accepts both dotted-quad
    (``XXXX.XXXX.XXXX``) and colon-separated (``XX:XX:XX:XX:XX:XX``)
    MAC formats for ``parameterType=macAddress``, and rejects everything
    else.

    ## Test

    - ``"aabb.ccdd.eeff"`` -> no error.
    - ``"AA:BB:CC:DD:EE:FF"`` -> no error.
    - ``"aa-bb-cc-dd-ee-ff"`` -> 1 error mentioning MAC.
    - ``"not.a.mac"`` -> 1 error mentioning MAC.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [{"name": "mac", "parameterType": "macAddress", "optional": True}]
    assert validate_template_inputs("tpl_a", {"mac": "aabb.ccdd.eeff"}, params) == []
    assert validate_template_inputs("tpl_a", {"mac": "AA:BB:CC:DD:EE:FF"}, params) == []
    assert validate_template_inputs("tpl_a", {"mac": "00:11:22:33:44:55"}, params) == []

    bad_dash = validate_template_inputs("tpl_a", {"mac": "aa-bb-cc-dd-ee-ff"}, params)
    bad_text = validate_template_inputs("tpl_a", {"mac": "not.a.mac"}, params)
    assert len(bad_dash) == 1 and "mac" in bad_dash[0].lower()
    assert len(bad_text) == 1 and "mac" in bad_text[0].lower()


def test_template_validation_00480() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` enforces the ``validValues``
    enum list when supplied via ``metaProperties.validValues``.

    ## Test

    - Value in list -> no error.
    - Value NOT in list -> 1 error.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [
        {
            "name": "mode",
            "parameterType": "enum",
            "optional": True,
            "metaProperties": {"validValues": "active,passive,off"},
        }
    ]
    good = validate_template_inputs("tpl_a", {"mode": "active"}, params)
    bad = validate_template_inputs("tpl_a", {"mode": "auto"}, params)
    assert good == []
    assert len(bad) == 1
    assert "auto" in bad[0]


def test_template_validation_00490() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` strips whitespace from each entry
    of ``metaProperties.validValues`` when splitting on commas (so
    ``"a , b , c"`` matches ``"a"`` / ``"b"`` / ``"c"``).

    ## Test

    - Padded ``validValues`` accepts unpadded user value.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [
        {
            "name": "mode",
            "parameterType": "enum",
            "optional": True,
            "metaProperties": {"validValues": "  active , passive , off "},
        }
    ]
    assert validate_template_inputs("tpl_a", {"mode": "active"}, params) == []
    assert validate_template_inputs("tpl_a", {"mode": "off"}, params) == []


def test_template_validation_00495() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` skips enum check entirely when
    ``metaProperties.validValues`` is missing -- any value is accepted
    (since we have no way to know the valid set).

    ## Test

    - Enum param without ``validValues`` -> any value accepted.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [{"name": "mode", "parameterType": "enum", "optional": True}]
    assert validate_template_inputs("tpl_a", {"mode": "anything"}, params) == []


def test_template_validation_00500() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` treats empty / whitespace
    values as "not set" and skips type validation for them.  This is
    critical for the ``gathered -> merged`` roundtrip where the
    controller returns ``""`` for unset optional parameters.

    ## Test

    - Empty / whitespace Integer / boolean / ipv4 values -> no errors.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [
        {"name": "vlan", "parameterType": "Integer", "optional": True},
        {"name": "flag", "parameterType": "boolean", "optional": True},
        {"name": "ip", "parameterType": "ipV4Address", "optional": True},
    ]
    errors = validate_template_inputs("tpl_a", {"vlan": "", "flag": "  ", "ip": ""}, params)
    assert errors == []


def test_template_validation_00510() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` skips type validation for any
    ``parameterType`` it does not recognise (e.g. ``"string"``) -- the
    controller's own validation is authoritative for those.

    ## Test

    - ``parameterType="string"`` with any value -> no error.
    - Missing / None ``parameterType`` -> no error.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [
        {"name": "s1", "parameterType": "string", "optional": True},
        {"name": "s2", "parameterType": None, "optional": True},
        {"name": "s3", "optional": True},
    ]
    errors = validate_template_inputs(
        "tpl_a",
        {"s1": "freeform text", "s2": "more", "s3": "and more"},
        params,
    )
    assert errors == []


def test_template_validation_00520() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` accumulates multiple errors
    across multiple checks rather than short-circuiting on the first.

    ## Test

    - One unknown key + one missing required + one type mismatch
      -> 3 separate error strings.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [
        {
            "name": "vlan_id",
            "parameterType": "Integer",
            "optional": False,
            "defaultValue": "",
        },
        {"name": "flag", "parameterType": "boolean", "optional": True},
    ]
    errors = validate_template_inputs("tpl_a", {"flag": "yes", "foo": "bar"}, params)
    assert len(errors) == 3
    joined = " | ".join(errors)
    assert "foo" in joined
    assert "vlan_id" in joined
    assert "flag" in joined


def test_template_validation_00530() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` matches ``parameterType``
    case-insensitively across all type branches (the implementation
    lower-cases the source string before comparison).

    ## Test

    - ``"BOOLEAN"`` rejects ``"yes"`` exactly like ``"boolean"``.
    - ``"INTEGER"`` rejects ``"abc"`` exactly like ``"integer"``.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    p_bool = [{"name": "flag", "parameterType": "BOOLEAN", "optional": True}]
    p_int = [{"name": "n", "parameterType": "INTEGER", "optional": True}]
    assert len(validate_template_inputs("tpl_a", {"flag": "yes"}, p_bool)) == 1
    assert len(validate_template_inputs("tpl_a", {"n": "abc"}, p_int)) == 1


def test_template_validation_00540() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` does not raise on integer or
    bool user values (only the string form is documented but real
    callers may pass typed values).  Each is stringified before
    pattern / parse checks.

    ## Test

    - ``True`` / ``False`` (Python bools) for boolean -> accepted as
      ``"True"`` / ``"False"``.
    - ``42`` (Python int) for Integer -> accepted.
    - ``"yes"`` (string) for boolean -> rejected as before.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    p_bool = [{"name": "flag", "parameterType": "boolean", "optional": True}]
    p_int = [{"name": "n", "parameterType": "Integer", "optional": True}]
    assert validate_template_inputs("tpl_a", {"flag": True}, p_bool) == []
    assert validate_template_inputs("tpl_a", {"flag": False}, p_bool) == []
    assert validate_template_inputs("tpl_a", {"n": 42}, p_int) == []
    assert len(validate_template_inputs("tpl_a", {"flag": "yes"}, p_bool)) == 1


def test_template_validation_00550() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` emits the expected logger
    lines when a logger is supplied: ENTER on call, DEBUG on no-error
    pass, WARNING on errors, EXIT on return.

    ## Test

    - Pass path -> debug includes ENTER and "validation passed".
    - Fail path -> warning includes the error count.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    params = [{"name": "flag", "parameterType": "boolean", "optional": True}]
    log_pass = ListLogger()
    assert validate_template_inputs("tpl_a", {"flag": "true"}, params, logger=log_pass) == []
    assert any("ENTER: validate_template_inputs" in m for m in log_pass.debug_msgs)
    assert any("validation passed" in m for m in log_pass.debug_msgs)

    log_fail = ListLogger()
    errs = validate_template_inputs("tpl_a", {"flag": "yes"}, params, logger=log_fail)
    assert len(errs) == 1
    assert any("1 errors" in m for m in log_fail.warning_msgs)


def test_template_validation_00560() -> None:
    """
    # Summary

    Verify ``validate_template_inputs`` works with ``logger=None``
    (default) -- no AttributeError, no side effects.

    ## Test

    - All three logger-touching branches (cache-hit-style empty-params,
      pass, fail) run cleanly with ``logger=None``.

    ## Classes and Methods

    - ``validate_template_inputs``
    """
    assert validate_template_inputs("tpl_a", {}, []) == []
    params = [{"name": "flag", "parameterType": "boolean", "optional": True}]
    assert validate_template_inputs("tpl_a", {"flag": "true"}, params) == []
    assert len(validate_template_inputs("tpl_a", {"flag": "yes"}, params)) == 1


# =============================================================================
# Test: fetch_template_params -- cache behaviour
# =============================================================================


def test_template_validation_00700() -> None:
    """
    # Summary

    Verify ``fetch_template_params`` issues the GET on cache miss and
    populates the cache with the returned ``parameters`` list.

    ## Test

    - Empty cache + GET returning ``{"parameters": [{...}]}`` ->
      single request, cache populated, returned list matches.

    ## Classes and Methods

    - ``fetch_template_params``
    """
    cache: dict[str, list[dict]] = {}
    calls: list[tuple[str, Any]] = []

    def request_fn(path: str, verb: Any) -> dict:
        calls.append((path, verb))
        return {"parameters": [{"name": "hostname", "parameterType": "string"}]}

    factory, _produced = _make_factory()
    result = fetch_template_params("tpl_a", request_fn, cache, endpoint_factory=factory)

    assert result == [{"name": "hostname", "parameterType": "string"}]
    assert cache == {"tpl_a": [{"name": "hostname", "parameterType": "string"}]}
    assert len(calls) == 1
    assert calls[0][0] == "/api/v1/manage/configTemplates/tpl_a/parameters"
    assert calls[0][1] == "GET"


def test_template_validation_00710() -> None:
    """
    # Summary

    Verify ``fetch_template_params`` returns the cached list without
    issuing the GET when the cache already has the entry.

    ## Test

    - Pre-seeded cache -> returned by-reference, zero requests issued.

    ## Classes and Methods

    - ``fetch_template_params``
    """
    cached_params = [{"name": "hostname"}]
    cache = {"tpl_a": cached_params}

    def request_fn(path: str, verb: Any) -> dict:  # pragma: no cover
        raise AssertionError("request_fn should not be called on cache hit")

    factory, _produced = _make_factory()
    result = fetch_template_params("tpl_a", request_fn, cache, endpoint_factory=factory)

    assert result is cached_params  # by-reference


def test_template_validation_00720() -> None:
    """
    # Summary

    Verify ``fetch_template_params`` caches ``[]`` on a fetch
    exception and returns ``[]`` to the caller (graceful-degradation
    contract: a transient GET failure must not fail the task).

    ## Test

    - ``request_fn`` raises -> cache populated with ``[]``, returned
      value is ``[]``, WARNING logged.

    ## Classes and Methods

    - ``fetch_template_params``
    """
    cache: dict[str, list[dict]] = {}
    log = ListLogger()

    def request_fn(path: str, verb: Any) -> dict:
        raise RuntimeError("simulated controller outage")

    factory, _produced = _make_factory()
    result = fetch_template_params("tpl_a", request_fn, cache, endpoint_factory=factory, logger=log)

    assert result == []
    assert cache == {"tpl_a": []}
    assert any("simulated controller outage" in m for m in log.warning_msgs)
    assert any("Skipping template input validation" in m for m in log.warning_msgs)


def test_template_validation_00730() -> None:
    """
    # Summary

    Verify ``fetch_template_params`` does NOT re-fetch after caching an
    empty list from a previous failure -- short-circuits to ``[]``.

    ## Test

    - First call raises -> cached ``[]``.
    - Second call returns the cached ``[]`` without invoking
      ``request_fn`` again.

    ## Classes and Methods

    - ``fetch_template_params``
    """
    cache: dict[str, list[dict]] = {}
    call_count = {"n": 0}

    def request_fn(path: str, verb: Any) -> dict:
        call_count["n"] += 1
        raise RuntimeError("once")

    factory, _produced = _make_factory()
    first = fetch_template_params("tpl_a", request_fn, cache, endpoint_factory=factory)
    second = fetch_template_params("tpl_a", request_fn, cache, endpoint_factory=factory)

    assert first == []
    assert second == []
    assert call_count["n"] == 1


# =============================================================================
# Test: fetch_template_params -- response shape handling
# =============================================================================


def test_template_validation_00800() -> None:
    """
    # Summary

    Verify ``fetch_template_params`` returns ``[]`` (and caches ``[]``)
    when the response is a dict with ``parameters: None`` -- a
    documented controller response for templates with no params.

    ## Test

    - Response ``{"parameters": None}`` -> ``[]``.

    ## Classes and Methods

    - ``fetch_template_params``
    """
    cache: dict[str, list[dict]] = {}

    def request_fn(path: str, verb: Any) -> dict:
        return {"parameters": None}

    factory, _produced = _make_factory()
    result = fetch_template_params("tpl_a", request_fn, cache, endpoint_factory=factory)
    assert result == []
    assert cache == {"tpl_a": []}


def test_template_validation_00810() -> None:
    """
    # Summary

    Verify ``fetch_template_params`` returns ``[]`` when the response
    is a dict without a ``parameters`` key at all.

    ## Test

    - Response ``{"other": "data"}`` -> ``[]``.

    ## Classes and Methods

    - ``fetch_template_params``
    """
    cache: dict[str, list[dict]] = {}

    def request_fn(path: str, verb: Any) -> dict:
        return {"other": "data"}

    factory, _produced = _make_factory()
    assert fetch_template_params("tpl_a", request_fn, cache, endpoint_factory=factory) == []


def test_template_validation_00820() -> None:
    """
    # Summary

    Verify ``fetch_template_params`` returns ``[]`` when the response
    is not a dict (e.g. ``None``, list, string).  Mirrors the
    ``isinstance(data, dict)`` guard in the source.

    ## Test

    - Response ``None`` / ``[]`` / ``"err"`` -> ``[]``.

    ## Classes and Methods

    - ``fetch_template_params``
    """
    for resp in (None, [], "err"):
        cache: dict[str, list[dict]] = {}

        def request_fn(path: str, verb: Any, _resp=resp) -> Any:
            return _resp

        factory, _produced = _make_factory()
        assert fetch_template_params("tpl_a", request_fn, cache, endpoint_factory=factory) == []
        assert cache == {"tpl_a": []}


# =============================================================================
# Test: fetch_template_params -- callbacks (endpoint_modifier_fn, record_call_fn)
# =============================================================================


def test_template_validation_00900() -> None:
    """
    # Summary

    Verify ``fetch_template_params`` invokes ``endpoint_modifier_fn``
    AFTER setting ``ep.template_name``, BEFORE ``record_call_fn`` /
    ``request_fn``, so the caller can attach ``cluster_name`` etc.

    ## Test

    - Modifier callback sees the populated ``template_name`` and can
      mutate ``endpoint_params.cluster_name``.

    ## Classes and Methods

    - ``fetch_template_params``
    """
    cache: dict[str, list[dict]] = {}
    seen_template_at_modifier: list[str | None] = []

    def modifier(ep) -> None:
        seen_template_at_modifier.append(ep.template_name)
        ep.endpoint_params.cluster_name = "cluster-a"

    def request_fn(path: str, verb: Any) -> dict:
        return {"parameters": []}

    factory, produced = _make_factory()
    fetch_template_params(
        "tpl_a",
        request_fn,
        cache,
        endpoint_factory=factory,
        endpoint_modifier_fn=modifier,
    )

    assert seen_template_at_modifier == ["tpl_a"]
    assert produced[0].endpoint_params.cluster_name == "cluster-a"


def test_template_validation_00910() -> None:
    """
    # Summary

    Verify ``fetch_template_params`` invokes ``record_call_fn`` with
    the endpoint instance and ``None`` payload (the DELETE-style
    record-call signature) immediately before ``request_fn``.

    ## Test

    - Callback receives ``(ep, None)`` exactly once.

    ## Classes and Methods

    - ``fetch_template_params``
    """
    cache: dict[str, list[dict]] = {}
    captured: list[tuple[Any, Any]] = []

    def record_call(ep: Any, payload: Any) -> None:
        captured.append((ep, payload))

    def request_fn(path: str, verb: Any) -> dict:
        return {"parameters": [{"name": "x"}]}

    factory, produced = _make_factory()
    fetch_template_params(
        "tpl_a",
        request_fn,
        cache,
        endpoint_factory=factory,
        record_call_fn=record_call,
    )

    assert len(captured) == 1
    assert captured[0][0] is produced[0]
    assert captured[0][1] is None


def test_template_validation_00920() -> None:
    """
    # Summary

    Verify ``fetch_template_params`` is callable with
    ``endpoint_modifier_fn=None`` and ``record_call_fn=None`` (the
    minimal-call form, used when the caller does not need to forward
    endpoint parameters or audit the call).

    ## Test

    - Minimal-arg call returns the expected list without raising.

    ## Classes and Methods

    - ``fetch_template_params``
    """
    cache: dict[str, list[dict]] = {}

    def request_fn(path: str, verb: Any) -> dict:
        return {"parameters": [{"name": "x"}]}

    factory, _produced = _make_factory()
    result = fetch_template_params("tpl_a", request_fn, cache, endpoint_factory=factory)
    assert result == [{"name": "x"}]


def test_template_validation_00930() -> None:
    """
    # Summary

    Verify the default ``endpoint_factory`` is
    ``EpManageConfigTemplateParametersGet`` -- invoking the helper
    without an explicit factory uses the production endpoint class.

    ## Test

    - Mock request_fn captures the path; assert it matches the
      production endpoint's path shape.

    ## Classes and Methods

    - ``fetch_template_params``
    """
    cache: dict[str, list[dict]] = {}
    captured: list[str] = []

    def request_fn(path: str, verb: Any) -> dict:
        captured.append(path)
        return {"parameters": []}

    # No endpoint_factory kwarg -> uses default
    fetch_template_params("switch_freeform", request_fn, cache)
    assert len(captured) == 1
    assert captured[0].endswith("/configTemplates/switch_freeform/parameters")


def test_template_validation_00940() -> None:
    """
    # Summary

    Verify ``fetch_template_params`` emits the expected debug / info /
    warning lines when a logger is supplied: ENTER / cache-miss /
    fetch-count / EXIT on success; ENTER / WARNING on failure;
    cache-hit-count debug on subsequent calls.

    ## Test

    - First call (success) logs ENTER, INFO with count, EXIT.
    - Second call (cache hit) logs ENTER and cache-hit-count.

    ## Classes and Methods

    - ``fetch_template_params``
    """
    cache: dict[str, list[dict]] = {}
    log = ListLogger()

    def request_fn(path: str, verb: Any) -> dict:
        return {"parameters": [{"name": "a"}, {"name": "b"}]}

    factory, _produced = _make_factory()
    fetch_template_params("tpl_a", request_fn, cache, endpoint_factory=factory, logger=log)
    fetch_template_params("tpl_a", request_fn, cache, endpoint_factory=factory, logger=log)

    enters = [m for m in log.debug_msgs if "ENTER: fetch_template_params" in m]
    assert len(enters) == 2
    cache_hits = [m for m in log.debug_msgs if "cache hit" in m]
    assert len(cache_hits) == 1
    assert any("Fetched 2 parameter definitions" in m for m in log.info_msgs)


def test_template_validation_00950() -> None:
    """
    # Summary

    Verify ``fetch_template_params`` works with ``logger=None`` (no
    AttributeError on any code path, success or failure).

    ## Test

    - Success path with no logger -> no error.
    - Failure path with no logger -> no error.

    ## Classes and Methods

    - ``fetch_template_params``
    """
    cache_ok: dict[str, list[dict]] = {}

    def good_fn(path: str, verb: Any) -> dict:
        return {"parameters": [{"name": "a"}]}

    factory, _produced = _make_factory()
    assert fetch_template_params("tpl_a", good_fn, cache_ok, endpoint_factory=factory) == [{"name": "a"}]

    cache_err: dict[str, list[dict]] = {}

    def bad_fn(path: str, verb: Any) -> dict:
        raise RuntimeError("boom")

    assert fetch_template_params("tpl_b", bad_fn, cache_err, endpoint_factory=factory) == []


# =============================================================================
# Test: strip_system_injected_keys
# =============================================================================


def test_template_validation_01000() -> None:
    """
    # Summary

    Verify ``strip_system_injected_keys`` removes EVERY key in the
    canonical ``SYSTEM_INJECTED_TEMPLATE_KEYS`` frozenset and leaves
    user keys untouched.

    ## Test

    - All 12 system keys + 2 user keys -> output has only the 2 user
      keys.

    ## Classes and Methods

    - ``strip_system_injected_keys``
    """
    raw = {k: "x" for k in SYSTEM_INJECTED_TEMPLATE_KEYS}
    raw["hostname"] = "leaf-01"
    raw["vlan_id"] = "10"

    result = strip_system_injected_keys("tpl_a", raw, SYSTEM_INJECTED_TEMPLATE_KEYS)

    assert result == {"hostname": "leaf-01", "vlan_id": "10"}


def test_template_validation_01010() -> None:
    """
    # Summary

    Verify ``strip_system_injected_keys`` does NOT mutate the input
    dict -- the function returns a fresh dict and the original is
    preserved.

    ## Test

    - Original dict's contents unchanged after the call.

    ## Classes and Methods

    - ``strip_system_injected_keys``
    """
    raw = {"POLICY_ID": "abc", "hostname": "leaf-01"}
    snapshot = dict(raw)

    strip_system_injected_keys("tpl_a", raw, SYSTEM_INJECTED_TEMPLATE_KEYS)

    assert raw == snapshot


def test_template_validation_01020() -> None:
    """
    # Summary

    Verify ``strip_system_injected_keys`` handles edge cases: empty
    input, all-system input, all-user input.

    ## Test

    - Empty raw -> empty result.
    - All keys are system -> empty result.
    - No keys are system -> raw returned (as a fresh dict, not by
      reference).

    ## Classes and Methods

    - ``strip_system_injected_keys``
    """
    assert strip_system_injected_keys("tpl_a", {}, SYSTEM_INJECTED_TEMPLATE_KEYS) == {}

    only_sys = {"POLICY_ID": "x", "FABRIC_ID": "y"}
    assert strip_system_injected_keys("tpl_a", only_sys, SYSTEM_INJECTED_TEMPLATE_KEYS) == {}

    only_user = {"hostname": "leaf-01", "vlan_id": "10"}
    out = strip_system_injected_keys("tpl_a", only_user, SYSTEM_INJECTED_TEMPLATE_KEYS)
    assert out == only_user
    assert out is not only_user


def test_template_validation_01030() -> None:
    """
    # Summary

    Verify ``strip_system_injected_keys`` accepts any container that
    supports the ``in`` operator (set / frozenset / list / tuple) for
    ``system_keys`` -- not just the canonical frozenset.

    ## Test

    - Custom set / list / tuple all strip the same keys.

    ## Classes and Methods

    - ``strip_system_injected_keys``
    """
    raw = {"A": 1, "B": 2, "C": 3}
    expected = {"C": 3}

    assert strip_system_injected_keys("t", raw, {"A", "B"}) == expected
    assert strip_system_injected_keys("t", raw, frozenset({"A", "B"})) == expected
    assert strip_system_injected_keys("t", raw, ["A", "B"]) == expected
    assert strip_system_injected_keys("t", raw, ("A", "B")) == expected


def test_template_validation_01040() -> None:
    """
    # Summary

    Verify ``strip_system_injected_keys`` emits the expected logger
    lines when a logger is supplied: ENTER on call, DEBUG with
    stripped-key list when at least one key was stripped, EXIT with
    counts on return.

    ## Test

    - Mixed input -> debug log includes ENTER, stripped-keys, EXIT.

    ## Classes and Methods

    - ``strip_system_injected_keys``
    """
    raw = {"POLICY_ID": "x", "hostname": "leaf-01"}
    log = ListLogger()
    strip_system_injected_keys("tpl_a", raw, SYSTEM_INJECTED_TEMPLATE_KEYS, logger=log)

    assert any("ENTER: strip_system_injected_keys" in m for m in log.debug_msgs)
    assert any("Stripped 1 system-injected keys" in m for m in log.debug_msgs)
    assert any("POLICY_ID" in m for m in log.debug_msgs)
    assert any("EXIT: strip_system_injected_keys" in m for m in log.debug_msgs)


def test_template_validation_01050() -> None:
    """
    # Summary

    Verify ``strip_system_injected_keys`` does NOT log the
    "Stripped N system-injected keys" line when nothing was stripped
    (the line is only emitted when at least one key was removed).

    ## Test

    - All-user input + logger -> no "Stripped" debug message.

    ## Classes and Methods

    - ``strip_system_injected_keys``
    """
    log = ListLogger()
    strip_system_injected_keys("tpl_a", {"hostname": "leaf-01"}, SYSTEM_INJECTED_TEMPLATE_KEYS, logger=log)
    assert not any("Stripped" in m for m in log.debug_msgs)


def test_template_validation_01060() -> None:
    """
    # Summary

    Verify ``strip_system_injected_keys`` works with ``logger=None``
    (default) -- no AttributeError, no side effects.

    ## Test

    - Mixed input + no logger -> correct output, no exception.

    ## Classes and Methods

    - ``strip_system_injected_keys``
    """
    raw = {"POLICY_ID": "x", "hostname": "leaf-01"}
    result = strip_system_injected_keys("tpl_a", raw, SYSTEM_INJECTED_TEMPLATE_KEYS)
    assert result == {"hostname": "leaf-01"}


# =============================================================================
# Test: cross-helper integration (round-trip safety)
# =============================================================================


def test_template_validation_01100() -> None:
    """
    # Summary

    Verify the canonical ``gathered -> merged`` round-trip is clean:
    a controller response containing ``SYSTEM_INJECTED_TEMPLATE_KEYS``
    can be stripped and then re-validated against the template's user
    parameter list without producing spurious unknown-key errors.

    ## Test

    - Build a fake gathered ``templateInputs`` containing user keys +
      system keys.
    - Strip system keys via ``strip_system_injected_keys``.
    - Validate via ``validate_template_inputs`` with a schema that
      lists only the user keys -> no errors.

    ## Classes and Methods

    - ``strip_system_injected_keys`` + ``validate_template_inputs``
    """
    gathered = {
        "hostname": "leaf-01",
        "vlan_id": "10",
        # ND-injected on every gathered response:
        "POLICY_ID": "POLICY-1234",
        "FABRIC_ID": "FAB-1",
        "FABRIC_NAME": "fab1",
        "SERIAL_NUMBER": "FDO111",
        "SOURCE": "",
        "PRIORITY": "500",
    }
    schema = [
        {"name": "hostname", "parameterType": "string", "optional": True},
        {
            "name": "vlan_id",
            "parameterType": "Integer",
            "optional": False,
            "defaultValue": "",
        },
    ]

    cleaned = strip_system_injected_keys("tpl_a", gathered, SYSTEM_INJECTED_TEMPLATE_KEYS)
    errors = validate_template_inputs("tpl_a", cleaned, schema)

    assert cleaned == {"hostname": "leaf-01", "vlan_id": "10"}
    assert errors == []


def test_template_validation_01110() -> None:
    """
    # Summary

    Verify ``fetch_template_params`` + ``validate_template_inputs``
    compose correctly: the raw param list returned by the fetch is
    accepted by the validator without any transformation in between.

    ## Test

    - Fetch returns params -> validate uses them directly -> errors
      computed correctly.

    ## Classes and Methods

    - ``fetch_template_params`` + ``validate_template_inputs``
    """
    cache: dict[str, list[dict]] = {}

    def request_fn(path: str, verb: Any) -> dict:
        return {
            "parameters": [
                {"name": "flag", "parameterType": "boolean", "optional": True},
                {
                    "name": "n",
                    "parameterType": "Integer",
                    "optional": False,
                    "defaultValue": "",
                },
            ]
        }

    factory, _produced = _make_factory()
    params = fetch_template_params("tpl_a", request_fn, cache, endpoint_factory=factory)
    errors = validate_template_inputs("tpl_a", {"flag": "yes"}, params)

    # 1 missing-required (n) + 1 type (flag) = 2 errors
    assert len(errors) == 2
    joined = " | ".join(errors)
    assert "n" in joined
    assert "boolean" in joined.lower()
