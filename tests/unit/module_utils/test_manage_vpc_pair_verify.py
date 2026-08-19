# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Verification compatibility contracts for nd_manage_vpc_pair."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.common import get_verify_settings
from ansible_collections.cisco.nd.plugins.modules.nd_manage_vpc_pair import _handle_verify_compatibility


def _module(verify):
    return SimpleNamespace(params={"verify": verify})


def test_vpc_verify_settings_use_canonical_attempts_and_interval() -> None:
    assert get_verify_settings(_module({"enabled": True, "attempts": 4, "interval": 0, "timeout": 12})) == {
        "enabled": True,
        "attempts": 4,
        "interval": 0,
        "timeout": 12,
    }


def test_vpc_verify_settings_map_released_retries_alias() -> None:
    assert get_verify_settings(_module({"retries": 6})) == {
        "enabled": True,
        "attempts": 6,
        "interval": 1,
        "timeout": 10,
    }


def test_vpc_verify_settings_remain_enabled_by_default() -> None:
    assert get_verify_settings(_module(None)) == {
        "enabled": True,
        "attempts": 5,
        "interval": 1,
        "timeout": 10,
    }


class _CompatibilityModule:
    def __init__(self) -> None:
        self.deprecations: list[tuple[str, str, str]] = []

    def deprecate(self, message: str, *, version: str, collection_name: str) -> None:
        self.deprecations.append((message, version, collection_name))

    def fail_json(self, **kwargs) -> None:
        raise RuntimeError(kwargs["msg"])


def test_vpc_verify_compatibility_rejects_attempts_with_retries() -> None:
    module = _CompatibilityModule()

    with pytest.raises(RuntimeError, match="cannot be used together"):
        _handle_verify_compatibility(module, {"verify": {"attempts": 3, "retries": 4}})


def test_vpc_verify_compatibility_warns_for_released_legacy_fields() -> None:
    module = _CompatibilityModule()

    _handle_verify_compatibility(module, {"verify": {"retries": 4, "timeout": 10}})

    assert len(module.deprecations) == 2
    assert all(item[1:] == ("2.0.0", "cisco.nd") for item in module.deprecations)
