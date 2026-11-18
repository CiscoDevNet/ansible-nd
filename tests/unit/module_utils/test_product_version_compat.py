# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Product release access stays independent of the legacy build-version API."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ansible_collections.cisco.nd.plugins.httpapi.nd import HttpApi
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


@pytest.mark.parametrize("first", ["product", "legacy", "build"])
@pytest.mark.parametrize("product", ["4.3(1)", "4.3.1a", None])
def test_httpapi_product_and_build_access_share_one_about_lookup(first, product):
    """Both call orders cache all reported fields, including a missing product."""
    provider = HttpApi(MagicMock())
    provider._send_nd_request = MagicMock(return_value={"body": {"productVersion": product, "buildVersion": "4.3.1.175"}})
    getters = {"product": provider.get_product_version, "legacy": lambda: provider.get_version("nd"), "build": provider.get_build_version}
    assert getters[first]() == (product if first == "product" else "4.3.1.175")
    assert provider.get_product_version() == product
    assert provider.get_build_version() == "4.3.1.175"
    assert provider.get_version("nd") == "4.3.1.175"
    provider._send_nd_request.assert_called_once_with("GET", "/api/v1/infra/about", provider.headers)


def test_httpapi_missing_product_is_not_inferred_from_build():
    provider = HttpApi(MagicMock())
    provider._send_nd_request = MagicMock(return_value={"body": {"buildVersion": "4.3.1.175"}})
    assert provider.get_version("nd") == "4.3.1.175"
    assert provider.get_product_version() is None
    assert provider.get_product_version() is None
    assert provider._send_nd_request.call_count == 1


def test_sender_retains_legacy_build_getter_and_uses_distinct_product_getter():
    legacy = MagicMock(return_value="4.3.1.175")
    product = MagicMock(return_value="4.3.1a")
    sender = Sender()
    sender._connection = SimpleNamespace(get_version=legacy, get_product_version=product)
    assert sender.get_version() == "4.3.1.175"
    assert sender.get_build_version() == "4.3.1.175"
    assert sender.get_product_version() == "4.3.1a"
    assert legacy.call_count == 2
    product.assert_called_once_with("nd")


def test_sender_older_connection_does_not_substitute_legacy_build_for_product():
    legacy = MagicMock(return_value="4.3.1.175")
    sender = Sender()
    sender._connection = SimpleNamespace(get_version=legacy)
    assert sender.get_product_version() is None
    legacy.assert_not_called()
    assert sender.get_version() == "4.3.1.175"


@pytest.mark.parametrize("product", ["4.3(1)", "4.3.1a", None])
def test_runtime_caches_product_independently_and_retains_legacy_build_contract(product):
    legacy = MagicMock(return_value="4.2.1.10")
    product_getter = MagicMock(return_value=product)
    runtime = RestSend({})
    runtime._sender = SimpleNamespace(get_version=legacy, get_product_version=product_getter)
    for _ in range(2):
        assert runtime.controller_product_version == product
        assert runtime.controller_version == "4.2.1.10"
        assert runtime.controller_build_version == "4.2.1.10"
    assert legacy.call_count == product_getter.call_count == 1


def test_runtime_product_failure_is_cached_without_falling_back_to_build():
    legacy = MagicMock(return_value="4.3.1.175")
    product = MagicMock(side_effect=RuntimeError("provider has no product support"))
    runtime = RestSend({})
    runtime._sender = SimpleNamespace(get_version=legacy, get_product_version=product)
    assert runtime.controller_product_version is None
    assert runtime.controller_product_version is None
    product.assert_called_once_with()
    legacy.assert_not_called()
    assert runtime.controller_version == "4.3.1.175"


def test_runtime_explicit_product_none_and_build_alias_do_not_cross_contaminate():
    product = MagicMock(side_effect=AssertionError("Explicit product override must bypass lookup"))
    runtime = RestSend({})
    runtime._sender = SimpleNamespace(get_product_version=product)
    runtime.controller_build_version = "4.3.1.175"
    runtime.controller_product_version = None
    assert runtime.controller_product_version is None
    assert runtime.controller_version == runtime.controller_build_version == "4.3.1.175"
    product.assert_not_called()
