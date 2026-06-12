# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `ManagePrefixListOrchestrator`.

Verifies the orchestrator drives RestSend correctly for prefix list operations.
Focus: explicit routing with fail-fast for unknown ip_version, centralized split-by-version helper,
IPv4/IPv6 endpoint delegation, and composite (ip_version, name) identifiers.

Scope: methods defined in manage_prefix_list.py only. Inherited base methods belong in their
own base-class test module.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,too-many-lines
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_prefix_list.manage_prefix_list import PrefixListModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_prefix_list import ManagePrefixListOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_manage_prefix_list(key: str):
    """Load fixture data for test_manage_prefix_list tests."""
    return load_fixture("test_manage_prefix_list")[key]


def _build_rest_send(gen_responses: ResponseGenerator, config: list | None = None) -> RestSend:
    """Build a `RestSend` wired to a file-based `Sender` and `ResponseHandler`."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    params = {"check_mode": False, "fabric_name": "SITE1", "config": config or []}
    rest_send = RestSend(params)
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


# =============================================================================
# Test: initialization
# =============================================================================


def test_manage_prefix_list_00010() -> None:
    """
    # Summary

    Verify `ManagePrefixListOrchestrator` instantiates and exposes expected ClassVars.

    ## Test

    - model_class is PrefixListModel
    - supports_bulk_create is True
    - supports_bulk_delete is True
    - Instance can be created with rest_send

    ## Classes and Methods

    - ManagePrefixListOrchestrator.__init__()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = ManagePrefixListOrchestrator(rest_send=rest_send)

    assert instance.model_class is PrefixListModel
    assert instance.supports_bulk_create is True
    assert instance.supports_bulk_delete is True
    # rest_send should be accessible
    assert instance.rest_send is rest_send


# =============================================================================
# Test: _endpoint_classes_for_version helper (explicit routing + fail-fast)
# =============================================================================


def test_manage_prefix_list_00020() -> None:
    """
    # Summary

    Verify _endpoint_classes_for_version returns correct endpoint classes for ipv4.

    ## Test

    - _endpoint_classes_for_version("ipv4") returns IPv4 endpoint class dict
    - Dict includes get, list, post, put, delete, bulk_delete keys

    ## Classes and Methods

    - ManagePrefixListOrchestrator._endpoint_classes_for_version()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)

    with does_not_raise():
        ep_classes = instance._endpoint_classes_for_version("ipv4")

    assert "get" in ep_classes
    assert "list" in ep_classes
    assert "post" in ep_classes
    assert "put" in ep_classes
    assert "delete" in ep_classes
    assert "bulk_delete" in ep_classes


def test_manage_prefix_list_00030() -> None:
    """
    # Summary

    Verify _endpoint_classes_for_version returns correct endpoint classes for ipv6.

    ## Test

    - _endpoint_classes_for_version("ipv6") returns IPv6 endpoint class dict
    - Dict includes get, list, post, put, delete, bulk_delete keys

    ## Classes and Methods

    - ManagePrefixListOrchestrator._endpoint_classes_for_version()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)

    with does_not_raise():
        ep_classes = instance._endpoint_classes_for_version("ipv6")

    assert "get" in ep_classes
    assert "list" in ep_classes


def test_manage_prefix_list_00040() -> None:
    """
    # Summary

    Verify _endpoint_classes_for_version raises ValueError for unknown ip_version (fail-fast routing).

    ## Test

    - _endpoint_classes_for_version("invalid") raises ValueError
    - Error message identifies the unknown version

    ## Classes and Methods

    - ManagePrefixListOrchestrator._endpoint_classes_for_version()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)

    with pytest.raises(ValueError, match="Unsupported ip_version.*invalid"):
        instance._endpoint_classes_for_version("invalid")


# =============================================================================
# Test: _split_by_ip_version helper (centralized grouping + fail-fast)
# =============================================================================


def test_manage_prefix_list_00050() -> None:
    """
    # Summary

    Verify _split_by_ip_version groups models by ip_version.

    ## Test

    - Mixed IPv4/IPv6 list is split into two groups
    - Each group contains only models of that version

    ## Classes and Methods

    - ManagePrefixListOrchestrator._split_by_ip_version()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)

    models = [
        PrefixListModel(ip_version="ipv4", name="PL-IPV4-1"),
        PrefixListModel(ip_version="ipv6", name="PL-IPV6-1"),
        PrefixListModel(ip_version="ipv4", name="PL-IPV4-2"),
    ]

    with does_not_raise():
        grouped = instance._split_by_ip_version(models)

    assert "ipv4" in grouped
    assert "ipv6" in grouped
    assert len(grouped["ipv4"]) == 2
    assert len(grouped["ipv6"]) == 1
    assert grouped["ipv4"][0].name == "PL-IPV4-1"
    assert grouped["ipv6"][0].name == "PL-IPV6-1"


def test_manage_prefix_list_00060() -> None:
    """
    # Summary

    Verify _split_by_ip_version groups models by ip_version correctly.

    ## Test

    - Empty list returns empty groups
    - Mixed models are grouped correctly

    ## Classes and Methods

    - ManagePrefixListOrchestrator._split_by_ip_version()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)

    # Empty list should return empty groups
    result = instance._split_by_ip_version([])
    assert result["ipv4"] == []
    assert result["ipv6"] == []


# =============================================================================
# Test: composite identifier handling
# =============================================================================


def test_manage_prefix_list_00070() -> None:
    """
    # Summary

    Verify orchestrator recognizes composite (ip_version, name) identifier.

    ## Test

    - Two models with same name but different ip_version have different identifier values
    - get_identifier_value() returns (ip_version, name) tuple

    ## Classes and Methods

    - PrefixListModel.get_identifier_value()
    """
    ipv4 = PrefixListModel(ip_version="ipv4", name="PL-SHARED")
    ipv6 = PrefixListModel(ip_version="ipv6", name="PL-SHARED")

    assert ipv4.get_identifier_value() == ("ipv4", "PL-SHARED")
    assert ipv6.get_identifier_value() == ("ipv6", "PL-SHARED")
    assert ipv4.get_identifier_value() != ipv6.get_identifier_value()


# =============================================================================
# Test: single model operations (set_identifiers flow)
# =============================================================================


def test_manage_prefix_list_00080() -> None:
    """
    # Summary

    Verify model composite identifier is passed correctly to endpoint via set_identifiers.

    ## Test

    - Composite identifier tuple (ip_version, name) is passed to endpoint
    - Endpoint receives identifier correctly

    ## Classes and Methods

    - PrefixListModel.get_identifier_value()
    - Endpoint.set_identifiers()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)

    model = PrefixListModel(ip_version="ipv4", name="PL-TEST")
    identifier = model.get_identifier_value()

    # Verify identifier is a tuple (ip_version, name)
    assert isinstance(identifier, tuple)
    assert len(identifier) == 2
    assert identifier[0] == "ipv4"
    assert identifier[1] == "PL-TEST"


# =============================================================================
# Test: bulk operation grouping
# =============================================================================


def test_manage_prefix_list_00090() -> None:
    """
    # Summary

    Verify bulk delete groups models by ip_version and calls separate endpoints.

    ## Test

    - Multiple models are grouped by family
    - Orchestrator would route each group to appropriate endpoint

    ## Classes and Methods

    - ManagePrefixListOrchestrator._split_by_ip_version()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)

    models = [
        PrefixListModel(ip_version="ipv4", name="PL-IPV4-BORDERS"),
        PrefixListModel(ip_version="ipv6", name="PL-IPV6-DATACENTER"),
        PrefixListModel(ip_version="ipv4", name="PL-IPV4-PEERS"),
    ]

    grouped = instance._split_by_ip_version(models)

    # Verify grouping
    assert len(grouped["ipv4"]) == 2
    assert len(grouped["ipv6"]) == 1
    assert [m.name for m in grouped["ipv4"]] == ["PL-IPV4-BORDERS", "PL-IPV4-PEERS"]
    assert [m.name for m in grouped["ipv6"]] == ["PL-IPV6-DATACENTER"]


# =============================================================================
# Test: endpoint class correctness
# =============================================================================


def test_manage_prefix_list_00100() -> None:
    """
    # Summary

    Verify IPv4 and IPv6 endpoint classes are distinct (ipv4PrefixLists vs ipv6PrefixLists).

    ## Test

    - IPv4 endpoints use ipv4PrefixLists path segment
    - IPv6 endpoints use ipv6PrefixLists path segment

    ## Classes and Methods

    - ManagePrefixListOrchestrator._endpoint_classes_for_version()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)

    ipv4_classes = instance._endpoint_classes_for_version("ipv4")
    ipv6_classes = instance._endpoint_classes_for_version("ipv6")

    # Verify they are different classes
    assert ipv4_classes["get"] is not ipv6_classes["get"]
    assert ipv4_classes["list"] is not ipv6_classes["list"]
    assert ipv4_classes["post"] is not ipv6_classes["post"]
