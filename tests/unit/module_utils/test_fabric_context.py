# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for fabric_context.py.

Verifies that `FabricContext` drives `RestSend` correctly for the fabric summary
and switches list endpoints, surfaces 404s as "fabric not found", parses the
`fabricManagementIp` -> `switchId` mapping, and raises `RuntimeError` from
`validate_for_mutation` when the fabric is missing.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,too-many-lines

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_fabric_context(key: str):
    """Load fixture data for fabric_context tests."""
    return load_fixture("test_fabric_context")[key]


def _build_rest_send(gen_responses: ResponseGenerator) -> RestSend:
    """Build a RestSend instance wired to a file-based Sender and ResponseHandler."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    rest_send = RestSend({"check_mode": False})
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


# =============================================================================
# Test: FabricContext initialization
# =============================================================================


def test_fabric_context_00010() -> None:
    """
    # Summary

    Verify `FabricContext` initializes with `rest_send` and `fabric_name` without fetching.

    ## Test

    - `fabric_name` returns the value passed at construction
    - No HTTP calls are made during `__init__`

    ## Classes and Methods

    - FabricContext.__init__()
    - FabricContext.fabric_name
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")

    assert instance.fabric_name == "fabric_1"
    # Internal sentinels indicate data has not been fetched yet.
    assert instance._switch_map is None  # pylint: disable=protected-access


# =============================================================================
# Test: fabric_summary / fabric_exists
# =============================================================================


def test_fabric_context_00100() -> None:
    """
    # Summary

    Verify `fabric_summary` fetches and caches the fabric detail dict.

    ## Test

    - GET to `/api/v1/manage/fabrics/{fabric_name}/summary` returns 200 with DATA
    - `fabric_summary` returns the DATA dict
    - `fabric_exists` returns True
    - Second access does not re-fetch (cache hit)

    ## Classes and Methods

    - FabricContext.fabric_summary
    - FabricContext.fabric_exists
    - FabricContext._query_get
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_fabric_context(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
        summary = instance.fabric_summary
        exists = instance.fabric_exists()
        # Cache hit: should not consume another response.
        cached = instance.fabric_summary

    assert summary == {"name": "fabric_1", "ownerCluster": "cluster_a"}
    assert exists is True
    assert cached is summary


def test_fabric_context_00110() -> None:
    """
    # Summary

    Verify `fabric_summary` returns None on 404 and `fabric_exists` returns False.

    ## Test

    - GET returns 404 -> `_query_get` returns `{}`
    - `fabric_summary` stores `None` and returns `None`
    - `fabric_exists` returns False

    ## Classes and Methods

    - FabricContext.fabric_summary
    - FabricContext.fabric_exists
    - FabricContext._query_get
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_fabric_context(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricContext(rest_send=rest_send, fabric_name="missing_fabric")
        summary = instance.fabric_summary
        exists = instance.fabric_exists()

    assert summary is None
    assert exists is False


# =============================================================================
# Test: switch_map / get_switch_id
# =============================================================================


def test_fabric_context_00200() -> None:
    """
    # Summary

    Verify `switch_map` builds a `fabricManagementIp -> switchId` dict from the switches list.

    ## Test

    - GET to `/api/v1/manage/fabrics/{fabric_name}/switches` returns two switches
    - `switch_map` contains both IPs mapped to their switchIds
    - `get_switch_id` resolves known IPs
    - `get_switch_id` raises `RuntimeError` for unknown IP

    ## Classes and Methods

    - FabricContext.switch_map
    - FabricContext.get_switch_id
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_fabric_context(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
        switch_map = instance.switch_map

    assert switch_map == {
        "192.168.12.151": "FDO12345ABC",
        "192.168.12.152": "FDO12345ABD",
    }
    assert instance.get_switch_id("192.168.12.151") == "FDO12345ABC"
    assert instance.get_switch_id("192.168.12.152") == "FDO12345ABD"

    match = r"No switch found with fabricManagementIp '10\.0\.0\.1' in fabric 'fabric_1'"
    with pytest.raises(RuntimeError, match=match):
        instance.get_switch_id("10.0.0.1")


def test_fabric_context_00210() -> None:
    """
    # Summary

    Verify `switch_map_by_id` builds a `switchId -> fabricManagementIp` dict and `get_switch_ip` resolves switch IDs.

    ## Test

    - GET to `/api/v1/manage/fabrics/{fabric_name}/switches` returns two switches
    - `switch_map_by_id` contains both switchIds mapped to their IPs
    - `get_switch_ip` resolves known switchIds
    - `get_switch_ip` raises `RuntimeError` for unknown switchId

    ## Classes and Methods

    - FabricContext.switch_map_by_id
    - FabricContext.get_switch_ip
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_fabric_context(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
        switch_map_by_id = instance.switch_map_by_id

    assert switch_map_by_id == {
        "FDO12345ABC": "192.168.12.151",
        "FDO12345ABD": "192.168.12.152",
    }
    assert instance.get_switch_ip("FDO12345ABC") == "192.168.12.151"
    assert instance.get_switch_ip("FDO12345ABD") == "192.168.12.152"

    match = r"No switch found with switchId 'FDO99999XYZ' in fabric 'fabric_1'"
    with pytest.raises(RuntimeError, match=match):
        instance.get_switch_ip("FDO99999XYZ")


# =============================================================================
# Test: validate_for_mutation
# =============================================================================


def test_fabric_context_00300() -> None:
    """
    # Summary

    Verify `validate_for_mutation` is a no-op when the fabric exists.

    ## Test

    - GET summary returns 200 -> `fabric_exists` is True
    - `validate_for_mutation` does not raise

    Note: `fabric_is_local` and `fabric_is_read_only` are stubs and are intentionally not invoked by `validate_for_mutation`.

    ## Classes and Methods

    - FabricContext.validate_for_mutation
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_fabric_context(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
        instance.validate_for_mutation()


def test_fabric_context_00310() -> None:
    """
    # Summary

    Verify `validate_for_mutation` raises `RuntimeError` when the fabric does not exist.

    ## Test

    - GET summary returns 404
    - `validate_for_mutation` raises with a message referencing the fabric name

    ## Classes and Methods

    - FabricContext.validate_for_mutation
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_fabric_context(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    instance = FabricContext(rest_send=rest_send, fabric_name="missing_fabric")
    match = r"Fabric 'missing_fabric' not found"
    with pytest.raises(RuntimeError, match=match):
        instance.validate_for_mutation()
