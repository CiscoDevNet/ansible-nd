# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Slawomir Kaszlikowski (@skaszlik)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `ManageAclOrchestrator`.

Verifies the orchestrator drives RestSend correctly for ACL operations: single
identifier (name) routing, bulk create/delete via the 207 Multi-Status action
endpoints, per-item failure detection, and fabric_name resolution from params.

Scope: methods defined in manage_acl.py only. Inherited base methods belong in
their own base-class test module.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,too-many-lines
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.acl.acl import AclModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_acl import ManageAclOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_manage_acl(key: str):
    """Load fixture data for test_manage_acl tests."""
    return load_fixture("test_manage_acl")[key]


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


SAMPLE_CONFIG = {
    "type": "ipv4",
    "name": "ACL-IPV4-WEB",
    "entries": [{"sequence_number": 10, "action": "permit", "protocol": "ip", "src": "any", "dst": "any"}],
}


# =============================================================================
# Test: initialization
# =============================================================================


def test_manage_acl_00010() -> None:
    """
    # Summary

    Verify `ManageAclOrchestrator` instantiates and exposes expected ClassVars.

    ## Test

    - model_class is AclModel
    - supports_bulk_create is True
    - supports_bulk_delete is True
    - rest_send is accessible

    ## Classes and Methods

    - ManageAclOrchestrator.__init__()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = ManageAclOrchestrator(rest_send=rest_send)

    assert instance.model_class is AclModel
    assert instance.supports_bulk_create is True
    assert instance.supports_bulk_delete is True
    assert instance.rest_send is rest_send


# =============================================================================
# Test: fabric_name resolution
# =============================================================================


def test_manage_acl_00020() -> None:
    """
    # Summary

    Verify the orchestrator exposes ``fabric_name`` from ``rest_send.params``.

    ## Test

    - ``fabric_name`` resolves to the value supplied in the module params
      (regression guard: ``NDBaseOrchestrator`` does not define it).

    ## Classes and Methods

    - ManageAclOrchestrator.fabric_name
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManageAclOrchestrator(rest_send=rest_send)

    assert instance.fabric_name == "SITE1"


# =============================================================================
# Test: query_all / query_one (RestSend-driven)
# =============================================================================


def test_manage_acl_00030() -> None:
    """
    # Summary

    Verify ``query_all`` GETs the collection endpoint and unwraps the
    ``accessControlLists`` list.

    ## Test

    - The list GET is consumed and returns the inner list of raw ACL rows.
    - A model built from the first row exposes its entries.

    ## Classes and Methods

    - ManageAclOrchestrator.query_all
    """

    def responses():
        yield responses_manage_acl("acls_ok")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManageAclOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert rest_send.verb == HttpVerbEnum.GET.value
    assert "/accessControlLists" in rest_send.path
    assert "max=100" in rest_send.path
    assert "offset=0" in rest_send.path
    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0]["name"] == "ACL-IPV4-WEB"

    model = AclModel.from_response(result[0])
    assert str(model.type) == "ipv4"
    assert model.entries is not None
    assert len(model.entries) == 2


def test_manage_acl_00040() -> None:
    """
    # Summary

    Verify ``query_all`` returns an empty list when the fabric has no ACLs.

    ## Classes and Methods

    - ManageAclOrchestrator.query_all
    """

    def responses():
        yield responses_manage_acl("empty_acls")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManageAclOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert result == []


def test_manage_acl_00035(monkeypatch) -> None:
    """
    # Summary

    Verify ``query_all`` follows offset pagination across multiple pages and
    stops on the first short (< page size) page, returning every ACL.

    ## Test

    - With a page size of 2, three GETs are issued (offset 0, 2, 4).
    - Pages 1 and 2 are full (2 rows) so the walk continues; page 3 is short
      (1 row) so it terminates.
    - All 5 ACLs across the three pages are collected, in order.
    - The final request carries ``max``/``offset`` reflecting the last page.

    ## Classes and Methods

    - ManageAclOrchestrator.query_all
    """
    monkeypatch.setattr(ManageAclOrchestrator, "query_all_page_size", 2)

    def responses():
        yield responses_manage_acl("acls_page_1")
        yield responses_manage_acl("acls_page_2")
        yield responses_manage_acl("acls_page_3")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManageAclOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert isinstance(result, list)
    assert [row["name"] for row in result] == [
        "ACL-PAGE-1",
        "ACL-PAGE-2",
        "ACL-PAGE-3",
        "ACL-PAGE-4",
        "ACL-PAGE-5",
    ]
    # Last request was the short page at offset 4.
    assert "max=2" in rest_send.path
    assert "offset=4" in rest_send.path


def test_manage_acl_00036(monkeypatch) -> None:
    """
    # Summary

    Verify ``query_all`` cannot loop forever when the controller ignores
    ``offset`` and keeps returning the same full page.

    ## Test

    - With a page size of 2, page 1 is full; page 2 is also full but its rows
      duplicate page 1 (no new names).
    - The de-duplication guard detects zero new rows and stops after page 2.
    - Only the two unique ACLs are returned (duplicates dropped).

    ## Classes and Methods

    - ManageAclOrchestrator.query_all
    """
    monkeypatch.setattr(ManageAclOrchestrator, "query_all_page_size", 2)

    def responses():
        yield responses_manage_acl("acls_page_1")
        yield responses_manage_acl("acls_dup_page")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = ManageAclOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert [row["name"] for row in result] == ["ACL-PAGE-1", "ACL-PAGE-2"]


def test_manage_acl_00050() -> None:
    """
    # Summary

    Verify ``query_one`` GETs the item endpoint using the single (name) identifier.

    ## Classes and Methods

    - ManageAclOrchestrator.query_one
    """

    def responses():
        yield responses_manage_acl("single_acl")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, config=[SAMPLE_CONFIG])
    instance = ManageAclOrchestrator(rest_send=rest_send)
    model = AclModel.from_config(SAMPLE_CONFIG)

    with does_not_raise():
        result = instance.query_one(model)

    assert rest_send.verb == HttpVerbEnum.GET.value
    assert rest_send.path.endswith("/accessControlLists/ACL-IPV4-WEB")
    assert result["name"] == "ACL-IPV4-WEB"


# =============================================================================
# Test: create / create_bulk (207 Multi-Status)
# =============================================================================


def test_manage_acl_00060() -> None:
    """
    # Summary

    Verify ``create_bulk`` POSTs to the collection endpoint with the
    ``accessControlLists`` wrapper key and succeeds on a 207 with all-success
    results.

    ## Classes and Methods

    - ManageAclOrchestrator.create_bulk
    """

    def responses():
        yield responses_manage_acl("create_207_success")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, config=[SAMPLE_CONFIG])
    instance = ManageAclOrchestrator(rest_send=rest_send)
    model = AclModel.from_config(SAMPLE_CONFIG)

    with does_not_raise():
        result = instance.create_bulk([model])

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/accessControlLists")
    body = rest_send.committed_payload
    assert "accessControlLists" in body
    assert body["accessControlLists"][0]["name"] == "ACL-IPV4-WEB"
    assert body["accessControlLists"][0]["type"] == "ipv4"
    assert body["accessControlLists"][0]["entries"][0]["sequenceNumber"] == 10
    assert "results" in result


def test_manage_acl_00070() -> None:
    """
    # Summary

    Verify ``create_bulk`` raises when the 207 body reports a per-item failure
    (the controller returns 207 -- transport success -- even when some items
    fail).

    ## Classes and Methods

    - ManageAclOrchestrator.create_bulk
    - NdV1Strategy.is_success
    """

    def responses():
        yield responses_manage_acl("create_207_partial_failure")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, config=[SAMPLE_CONFIG])
    instance = ManageAclOrchestrator(rest_send=rest_send)
    model = AclModel.from_config(SAMPLE_CONFIG)

    with pytest.raises(Exception, match="Bulk create failed.*ACL-BAD"):
        instance.create_bulk([model])


def test_manage_acl_00080() -> None:
    """
    # Summary

    Verify ``create`` (single) routes through the bulk create endpoint.

    ## Classes and Methods

    - ManageAclOrchestrator.create
    """

    def responses():
        yield responses_manage_acl("create_207_success")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, config=[SAMPLE_CONFIG])
    instance = ManageAclOrchestrator(rest_send=rest_send)
    model = AclModel.from_config(SAMPLE_CONFIG)

    with does_not_raise():
        instance.create(model)

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/accessControlLists")
    assert rest_send.committed_payload["accessControlLists"][0]["name"] == "ACL-IPV4-WEB"


# =============================================================================
# Test: update (PUT)
# =============================================================================


def test_manage_acl_00090() -> None:
    """
    # Summary

    Verify ``update`` PUTs to the item endpoint using the name identifier and
    the model payload.

    ## Classes and Methods

    - ManageAclOrchestrator.update
    """

    def responses():
        yield responses_manage_acl("update_acl")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses, config=[SAMPLE_CONFIG])
    instance = ManageAclOrchestrator(rest_send=rest_send)
    model = AclModel.from_config(SAMPLE_CONFIG)

    with does_not_raise():
        instance.update(model)

    assert rest_send.verb == HttpVerbEnum.PUT.value
    assert rest_send.path.endswith("/accessControlLists/ACL-IPV4-WEB")
    assert rest_send.committed_payload["name"] == "ACL-IPV4-WEB"


# =============================================================================
# Test: delete / delete_bulk (207 Multi-Status)
# =============================================================================


def test_manage_acl_00100() -> None:
    """
    # Summary

    Verify ``delete_bulk`` POSTs the names to the bulk-delete action endpoint
    with the ``accessControlListNames`` wrapper key and succeeds on a 207 with
    all-success results.

    ## Classes and Methods

    - ManageAclOrchestrator.delete_bulk
    """

    def responses():
        yield responses_manage_acl("bulk_delete_207_success")

    gen_responses = ResponseGenerator(responses())
    config = {"name": "ACL-IPV4-WEB"}
    rest_send = _build_rest_send(gen_responses, config=[config])
    instance = ManageAclOrchestrator(rest_send=rest_send)
    model = AclModel.from_config(config)

    with does_not_raise():
        result = instance.delete_bulk([model])

    assert rest_send.verb == HttpVerbEnum.POST.value
    assert rest_send.path.endswith("/accessControlListActions/remove")
    assert rest_send.committed_payload == {"accessControlListNames": ["ACL-IPV4-WEB"]}
    assert "results" in result


def test_manage_acl_00110() -> None:
    """
    # Summary

    Verify ``delete_bulk`` raises when the 207 body reports a per-item failure.

    ## Classes and Methods

    - ManageAclOrchestrator.delete_bulk
    - NdV1Strategy.is_success
    """

    def responses():
        yield responses_manage_acl("bulk_delete_207_partial_failure")

    gen_responses = ResponseGenerator(responses())
    config = {"name": "ACL-OK"}
    rest_send = _build_rest_send(gen_responses, config=[config])
    instance = ManageAclOrchestrator(rest_send=rest_send)
    model = AclModel.from_config(config)

    with pytest.raises(Exception, match="Bulk delete failed.*ACL-BAD"):
        instance.delete_bulk([model])


def test_manage_acl_00120() -> None:
    """
    # Summary

    Verify ``delete`` (single) routes through the bulk-delete endpoint.

    ## Classes and Methods

    - ManageAclOrchestrator.delete
    """

    def responses():
        yield responses_manage_acl("bulk_delete_207_success")

    gen_responses = ResponseGenerator(responses())
    config = {"name": "ACL-IPV4-WEB"}
    rest_send = _build_rest_send(gen_responses, config=[config])
    instance = ManageAclOrchestrator(rest_send=rest_send)
    model = AclModel.from_config(config)

    with does_not_raise():
        instance.delete(model)

    assert rest_send.path.endswith("/accessControlListActions/remove")
    assert rest_send.committed_payload == {"accessControlListNames": ["ACL-IPV4-WEB"]}
