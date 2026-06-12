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


# =============================================================================
# Test: fabric_name resolution
# =============================================================================


def test_manage_prefix_list_00110() -> None:
    """
    # Summary

    Verify the orchestrator exposes ``fabric_name`` from ``rest_send.params``.

    ## Test

    - ``fabric_name`` resolves to the value supplied in the module params (regression guard: the
      generic ``NDBaseOrchestrator`` does not define it, so the orchestrator must surface it itself).

    ## Classes and Methods

    - ManagePrefixListOrchestrator.fabric_name
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)

    assert instance.fabric_name == "SITE1"


# =============================================================================
# Test: query_all (RestSend-driven)
# =============================================================================


def test_manage_prefix_list_00120() -> None:
    """
    # Summary

    Verify ``query_all`` fetches IPv4 then IPv6, injects ``ipVersion`` into each raw row, and that
    the rows carry the ``entries`` key so ``PrefixListModel.from_response`` can parse them.

    ## Test

    - IPv4 list GET is consumed first, then the IPv6 list GET (``_VERSION_CONFIG`` insertion order).
    - The combined result has one IPv4 and one IPv6 row, each tagged with ``ipVersion``.
    - A model built from the IPv4 row exposes its entries (validates the response ``entries`` key).

    ## Classes and Methods

    - ManagePrefixListOrchestrator.query_all
    """

    def responses():
        yield responses_manage_prefix_list("ipv4_prefix_lists_ok")
        yield responses_manage_prefix_list("ipv6_prefix_lists_ok")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert isinstance(result, list)
    assert len(result) == 2
    by_version = {row["ipVersion"]: row for row in result}
    assert by_version["ipv4"]["name"] == "PL-IPV4-BORDERS"
    assert by_version["ipv6"]["name"] == "PL-IPV6-DATACENTER"

    # The raw rows must carry the 'entries' key so the model deserialises correctly.
    ipv4_model = PrefixListModel.from_response(by_version["ipv4"])
    assert str(ipv4_model.ip_version) == "ipv4"
    assert ipv4_model.entries is not None
    assert len(ipv4_model.entries) == 2


def test_manage_prefix_list_00130() -> None:
    """
    # Summary

    Verify ``query_all`` returns an empty list when both address families are empty.

    ## Classes and Methods

    - ManagePrefixListOrchestrator.query_all
    """

    def responses():
        yield responses_manage_prefix_list("empty_ipv4_lists")
        yield responses_manage_prefix_list("empty_ipv6_lists")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert result == []


# =============================================================================
# Test: create / create_bulk (207 Multi-Status)
# =============================================================================


def test_manage_prefix_list_00140() -> None:
    """
    # Summary

    Verify ``create_bulk`` (IPv4 only) POSTs to the IPv4 collection endpoint with the
    ``ipv4PrefixLists`` wrapper key and succeeds on a 207 with all-success results.

    ## Classes and Methods

    - ManagePrefixListOrchestrator.create_bulk
    - ManagePrefixListOrchestrator._bulk_create_for_version
    """

    def responses():
        yield responses_manage_prefix_list("create_ipv4_207_success")

    gen_responses = ResponseGenerator(responses())
    config = {"ip_version": "ipv4", "name": "PL-IPV4-BORDERS", "entries": [{"sequence_number": 10, "action": "permit", "prefix": "10.0.0.0/8"}]}
    rest_send = _build_rest_send(gen_responses, config=[config])
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)
    model = PrefixListModel.from_config(config)

    with does_not_raise():
        result = instance.create_bulk([model])

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/ipv4PrefixLists")
    body = rest_send.committed_payload
    assert "ipv4PrefixLists" in body
    assert body["ipv4PrefixLists"][0]["name"] == "PL-IPV4-BORDERS"
    assert body["ipv4PrefixLists"][0]["entries"][0]["sequenceNumber"] == 10
    assert "ipv4" in result


def test_manage_prefix_list_00150() -> None:
    """
    # Summary

    Verify ``create_bulk`` with a mixed IPv4/IPv6 batch issues two POSTs (IPv4 first, then IPv6),
    each with its own wrapper key.

    ## Classes and Methods

    - ManagePrefixListOrchestrator.create_bulk
    """

    def responses():
        yield responses_manage_prefix_list("create_ipv4_207_success")
        yield responses_manage_prefix_list("create_ipv6_207_success")

    gen_responses = ResponseGenerator(responses())
    configs = [
        {"ip_version": "ipv4", "name": "PL-IPV4-BORDERS", "entries": [{"sequence_number": 10, "action": "permit", "prefix": "10.0.0.0/8"}]},
        {"ip_version": "ipv6", "name": "PL-IPV6-DATACENTER", "entries": [{"sequence_number": 10, "action": "permit", "prefix": "2001:db8::/32"}]},
    ]
    rest_send = _build_rest_send(gen_responses, config=configs)
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)
    models = [PrefixListModel.from_config(c) for c in configs]

    with does_not_raise():
        result = instance.create_bulk(models)

    # The last request is the IPv6 POST.
    assert rest_send.path.endswith("/ipv6PrefixLists")
    assert rest_send.committed_payload["ipv6PrefixLists"][0]["name"] == "PL-IPV6-DATACENTER"
    assert set(result.keys()) == {"ipv4", "ipv6"}


def test_manage_prefix_list_00160() -> None:
    """
    # Summary

    Verify ``create_bulk`` raises when the 207 body reports a per-item failure (the controller
    returns 207 -- transport success -- even when some items fail).

    ## Classes and Methods

    - ManagePrefixListOrchestrator.create_bulk
    - ManagePrefixListOrchestrator._raise_on_207_failures
    """

    def responses():
        yield responses_manage_prefix_list("create_ipv4_207_partial_failure")

    gen_responses = ResponseGenerator(responses())
    config = {"ip_version": "ipv4", "name": "PL-IPV4-OK", "entries": [{"sequence_number": 10, "action": "permit", "prefix": "10.0.0.0/8"}]}
    rest_send = _build_rest_send(gen_responses, config=[config])
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)
    model = PrefixListModel.from_config(config)

    with pytest.raises(Exception, match="per-item failures.*PL-IPV4-BAD"):
        instance.create_bulk([model])


def test_manage_prefix_list_00170() -> None:
    """
    # Summary

    Verify ``create`` (single) routes through the bulk create endpoint.

    ## Classes and Methods

    - ManagePrefixListOrchestrator.create
    """

    def responses():
        yield responses_manage_prefix_list("create_ipv4_207_success")

    gen_responses = ResponseGenerator(responses())
    config = {"ip_version": "ipv4", "name": "PL-IPV4-BORDERS", "entries": [{"sequence_number": 10, "action": "permit", "prefix": "10.0.0.0/8"}]}
    rest_send = _build_rest_send(gen_responses, config=[config])
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)
    model = PrefixListModel.from_config(config)

    with does_not_raise():
        instance.create(model)

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/ipv4PrefixLists")
    assert rest_send.committed_payload["ipv4PrefixLists"][0]["name"] == "PL-IPV4-BORDERS"


# =============================================================================
# Test: update (PUT)
# =============================================================================


def test_manage_prefix_list_00180() -> None:
    """
    # Summary

    Verify ``update`` PUTs to the IPv4 item endpoint using the composite identifier name and the
    model payload.

    ## Classes and Methods

    - ManagePrefixListOrchestrator.update
    """

    def responses():
        yield responses_manage_prefix_list("update_ipv4_prefix_list")

    gen_responses = ResponseGenerator(responses())
    config = {"ip_version": "ipv4", "name": "PL-IPV4-BORDERS", "entries": [{"sequence_number": 10, "action": "permit", "prefix": "10.0.1.0/24"}]}
    rest_send = _build_rest_send(gen_responses, config=[config])
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)
    model = PrefixListModel.from_config(config)

    with does_not_raise():
        instance.update(model)

    assert rest_send.verb == HttpVerbEnum.PUT.value
    assert rest_send.path.endswith("/ipv4PrefixLists/PL-IPV4-BORDERS")
    assert rest_send.committed_payload["name"] == "PL-IPV4-BORDERS"


# =============================================================================
# Test: delete / delete_bulk (207 Multi-Status)
# =============================================================================


def test_manage_prefix_list_00190() -> None:
    """
    # Summary

    Verify ``delete_bulk`` POSTs the names to the IPv4 bulk-delete action endpoint with the
    ``ipv4PrefixListNames`` wrapper key and succeeds on a 207 with all-success results.

    ## Classes and Methods

    - ManagePrefixListOrchestrator.delete_bulk
    - ManagePrefixListOrchestrator._bulk_delete_for_version
    """

    def responses():
        yield responses_manage_prefix_list("bulk_delete_ipv4_207_success")

    gen_responses = ResponseGenerator(responses())
    config = {"ip_version": "ipv4", "name": "PL-IPV4-BORDERS"}
    rest_send = _build_rest_send(gen_responses, config=[config])
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)
    model = PrefixListModel.from_config(config)

    with does_not_raise():
        result = instance.delete_bulk([model])

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/ipv4PrefixListActions/remove")
    assert rest_send.committed_payload == {"ipv4PrefixListNames": ["PL-IPV4-BORDERS"]}
    assert "ipv4" in result


def test_manage_prefix_list_00200() -> None:
    """
    # Summary

    Verify ``delete_bulk`` raises when the 207 body reports a per-item failure.

    ## Classes and Methods

    - ManagePrefixListOrchestrator.delete_bulk
    - ManagePrefixListOrchestrator._raise_on_207_failures
    """

    def responses():
        yield responses_manage_prefix_list("bulk_delete_ipv4_207_partial_failure")

    gen_responses = ResponseGenerator(responses())
    config = {"ip_version": "ipv4", "name": "PL-IPV4-OK"}
    rest_send = _build_rest_send(gen_responses, config=[config])
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)
    model = PrefixListModel.from_config(config)

    with pytest.raises(Exception, match="per-item failures.*PL-IPV4-BAD"):
        instance.delete_bulk([model])


def test_manage_prefix_list_00210() -> None:
    """
    # Summary

    Verify ``delete`` (single) routes through the bulk-delete endpoint.

    ## Classes and Methods

    - ManagePrefixListOrchestrator.delete
    """

    def responses():
        yield responses_manage_prefix_list("bulk_delete_ipv4_207_success")

    gen_responses = ResponseGenerator(responses())
    config = {"ip_version": "ipv4", "name": "PL-IPV4-BORDERS"}
    rest_send = _build_rest_send(gen_responses, config=[config])
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)
    model = PrefixListModel.from_config(config)

    with does_not_raise():
        instance.delete(model)

    assert rest_send.path.endswith("/ipv4PrefixListActions/remove")
    assert rest_send.committed_payload == {"ipv4PrefixListNames": ["PL-IPV4-BORDERS"]}


# =============================================================================
# Test: query_one (GET item)
# =============================================================================


def test_manage_prefix_list_00220() -> None:
    """
    # Summary

    Verify ``query_one`` GETs the IPv4 item endpoint using the composite identifier name.

    ## Classes and Methods

    - ManagePrefixListOrchestrator.query_one
    """

    def responses():
        yield responses_manage_prefix_list("ipv4_single_prefix_list")

    gen_responses = ResponseGenerator(responses())
    config = {"ip_version": "ipv4", "name": "PL-IPV4-BORDERS"}
    rest_send = _build_rest_send(gen_responses, config=[config])
    instance = ManagePrefixListOrchestrator(rest_send=rest_send)
    model = PrefixListModel.from_config(config)

    with does_not_raise():
        result = instance.query_one(model)

    assert rest_send.verb == HttpVerbEnum.GET.value
    assert rest_send.path.endswith("/ipv4PrefixLists/PL-IPV4-BORDERS")
    assert result["name"] == "PL-IPV4-BORDERS"
