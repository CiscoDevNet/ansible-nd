# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for nd_argument_specs.py

Tests the shared argument-spec functions: the common connection/authentication spec (nd_argument_spec) and the
config_actions fragment with its include-allowlist selection (config_actions_spec, _select_options).
"""

# pylint: disable=protected-access

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import (
    _select_options,
    config_actions_spec,
    nd_argument_spec,
)


def test_nd_argument_specs_00000() -> None:
    """
    # Summary

    Verify `nd_argument_spec()` returns the complete connection/authentication spec with expected keys, defaults, and `no_log` on `password`.

    ## Test

    - The key set matches the historical spec from nd.py exactly
    - `password` has `no_log=True`
    - `timeout` defaults to 30 and `output_level` defaults to "normal"
    - `host` carries the `hostname` alias

    ## Classes and Methods

    - nd_argument_specs.nd_argument_spec()
    """
    spec = nd_argument_spec()
    assert set(spec.keys()) == {
        "host",
        "port",
        "username",
        "password",
        "output_level",
        "timeout",
        "use_proxy",
        "use_ssl",
        "validate_certs",
        "login_domain",
    }
    assert spec["password"]["no_log"] is True
    assert spec["timeout"]["default"] == 30
    assert spec["output_level"]["default"] == "normal"
    assert spec["output_level"]["choices"] == ["debug", "info", "normal"]
    assert spec["host"]["aliases"] == ["hostname"]


def test_nd_argument_specs_00001() -> None:
    """
    # Summary

    Verify `nd_argument_spec()` returns a fresh dict on every call so callers can mutate their copy safely.

    ## Test

    - Two calls return equal but distinct objects
    - Mutating one result does not affect a subsequent call

    ## Classes and Methods

    - nd_argument_specs.nd_argument_spec()
    """
    first = nd_argument_spec()
    second = nd_argument_spec()
    assert first == second
    assert first is not second
    del first["host"]
    assert "host" in nd_argument_spec()


def test_nd_argument_specs_00100() -> None:
    """
    # Summary

    Verify `config_actions_spec()` with no allowlist returns the full fragment: `save`, `deploy`, and `type` options.

    ## Test

    - Top-level shape is a single `config_actions` dict of type "dict"
    - All three options are present with expected defaults and choices

    ## Classes and Methods

    - nd_argument_specs.config_actions_spec()
    """
    spec = config_actions_spec()
    assert set(spec.keys()) == {"config_actions"}
    assert spec["config_actions"]["type"] == "dict"
    options = spec["config_actions"]["options"]
    assert set(options.keys()) == {"save", "deploy", "type"}
    assert options["save"] == {"type": "bool", "default": True}
    assert options["deploy"] == {"type": "bool", "default": True}
    assert options["type"] == {"type": "str", "default": "switch", "choices": ["switch", "global"]}


def test_nd_argument_specs_00101() -> None:
    """
    # Summary

    Verify `config_actions_spec(include=("deploy",))` reproduces the deploy-only block hand-written in the `nd_interface_*` modules today.

    ## Test

    - The returned fragment equals the exact dict currently duplicated across the interface modules

    ## Classes and Methods

    - nd_argument_specs.config_actions_spec()
    """
    expected = {
        "config_actions": {
            "type": "dict",
            "options": {
                "deploy": {"type": "bool", "default": True},
            },
        },
    }
    assert config_actions_spec(include=("deploy",)) == expected


def test_nd_argument_specs_00102() -> None:
    """
    # Summary

    Verify `config_actions_spec()` raises `ValueError` when `include` names an option that is not part of the fragment.

    ## Test

    - An unknown option name in `include` raises `ValueError` naming the offender and the valid options

    ## Classes and Methods

    - nd_argument_specs.config_actions_spec()
    - nd_argument_specs._select_options()
    """
    match = r"Unknown option name\(s\) in include: bogus\. Valid options: deploy, save, type\."
    with pytest.raises(ValueError, match=match):
        result = config_actions_spec(include=("deploy", "bogus"))  # pylint: disable=unused-variable


def test_nd_argument_specs_00200() -> None:
    """
    # Summary

    Verify `_select_options()` allowlist behavior: `include=None` selects every option as a copy; an allowlist selects exactly those options.

    ## Test

    - `include=None` returns an equal but distinct dict (mutating the copy does not affect the source)
    - An allowlist returns only the named options
    - An empty allowlist returns an empty dict

    ## Classes and Methods

    - nd_argument_specs._select_options()
    """
    options = {"save": {"type": "bool"}, "deploy": {"type": "bool"}}
    everything = _select_options(options, None)
    assert everything == options
    assert everything is not options
    del everything["save"]
    assert "save" in options
    assert _select_options(options, ("save",)) == {"save": {"type": "bool"}}
    assert _select_options(options, ()) == {}
