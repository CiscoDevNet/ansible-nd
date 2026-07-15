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
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, PlatformTypeEnum
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


def test_fabric_context_00170() -> None:
    """
    # Summary

    Verify `fabric_summary` fails closed when a 200 response body carries an embedded `code` error key (issue #400).

    ## Test

    - GET (summary) returns 200 with DATA `{"code": 404, "message": "..."}`
    - `fabric_summary` raises `RuntimeError` rather than accepting the payload as a valid summary

    ## Classes and Methods

    - FabricContext.fabric_summary
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_context(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
    match = r"returned an embedded error instead of a fabric summary"
    with pytest.raises(RuntimeError, match=match):
        result = instance.fabric_summary  # pylint: disable=unused-variable


# =============================================================================
# Test: fabric_is_deployment_frozen
# =============================================================================


def test_fabric_context_00120() -> None:
    """
    # Summary

    Verify `fabric_is_deployment_frozen` returns True when `fabricStatus` in the summary is "frozen".

    ## Test

    - GET (summary) returns 200 with `fabricStatus: "frozen"`
    - `fabric_is_deployment_frozen()` returns True
    - No additional API call is made (state is read from the cached summary)

    ## Classes and Methods

    - FabricContext.fabric_is_deployment_frozen
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_context(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
        result = instance.fabric_is_deployment_frozen()

    assert result is True


def test_fabric_context_00130() -> None:
    """
    # Summary

    Verify `fabric_is_deployment_frozen` returns False when `fabricStatus` is "default" and the summary cache prevents
    a second fetch on subsequent calls.

    ## Test

    - GET (summary) returns 200 with `fabricStatus: "default"`
    - `fabric_is_deployment_frozen()` returns False
    - A second call returns False without consuming another response (summary cache hit)

    ## Classes and Methods

    - FabricContext.fabric_is_deployment_frozen
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_context(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
        first = instance.fabric_is_deployment_frozen()
        cached = instance.fabric_is_deployment_frozen()

    assert first is False
    assert cached is False


# =============================================================================
# Test: fabric_is_local
# =============================================================================


def test_fabric_context_00140() -> None:
    """
    # Summary

    Verify `fabric_is_local` returns True when the summary reports `local: true`.

    ## Test

    - GET (summary) returns 200 with `local: true`
    - `fabric_is_local()` returns True

    ## Classes and Methods

    - FabricContext.fabric_is_local
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_context(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
        result = instance.fabric_is_local()

    assert result is True


def test_fabric_context_00150() -> None:
    """
    # Summary

    Verify `fabric_is_local` returns False when the summary reports `local: false` (fabric owned by a different controller in the cluster).

    ## Test

    - GET (summary) returns 200 with `local: false`
    - `fabric_is_local()` returns False

    ## Classes and Methods

    - FabricContext.fabric_is_local
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_context(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
        result = instance.fabric_is_local()

    assert result is False


def test_fabric_context_00160() -> None:
    """
    # Summary

    Verify `fabric_is_local` defaults to True when the `local` field is absent from the summary (older API / single-controller setup).

    ## Test

    - GET (summary) returns 200 without a `local` field
    - `fabric_is_local()` returns True

    ## Classes and Methods

    - FabricContext.fabric_is_local
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_context(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
        result = instance.fabric_is_local()

    assert result is True


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


def test_fabric_context_00220() -> None:
    """
    # Summary

    Verify `invalidate` drops cached state so the next switch_map access re-fetches from the API.

    ## Test

    - First `switch_map` access fetches the one-switch response and caches it
    - `invalidate()` is called
    - Second `switch_map` access fetches the two-switch response and reflects the new state
    - Both IP- and ID-keyed maps are refreshed

    ## Classes and Methods

    - FabricContext.invalidate
    - FabricContext.switch_map
    - FabricContext.switch_map_by_id
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_context(f"{method_name}a")
        yield responses_fabric_context(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
    with does_not_raise():
        first_map = instance.switch_map
        instance.invalidate()
        second_map = instance.switch_map
        second_map_by_id = instance.switch_map_by_id

    assert first_map == {"192.168.12.151": "FDO12345ABC"}
    assert second_map == {
        "192.168.12.151": "FDO12345ABC",
        "192.168.12.152": "FDO12345ABD",
    }
    assert second_map_by_id == {
        "FDO12345ABC": "192.168.12.151",
        "FDO12345ABD": "192.168.12.152",
    }


def test_fabric_context_00230() -> None:
    """
    # Summary

    Verify `switches` retains the raw switch records and `get_platform_type` resolves each switch's `platformType`
    (nested under `additionalData`) to a `PlatformTypeEnum`.

    ## Test

    - GET (switches) returns three switches: nx-os, ios-xe, and one with no `additionalData`
    - `switches` returns the raw three-record list
    - `get_platform_type` returns `PlatformTypeEnum.NX_OS` / `PlatformTypeEnum.IOS_XE` for the first two
    - `get_platform_type` returns `None` for the switch that reports no `platformType`
    - `get_platform_type` raises `RuntimeError` for an IP not in the fabric

    ## Classes and Methods

    - FabricContext.switches
    - FabricContext.get_platform_type
    - FabricContext._load_switch_maps
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_fabric_context(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
        switches = instance.switches

    assert len(switches) == 3
    assert switches[0]["switchId"] == "FDO12345ABC"
    assert instance.get_platform_type("192.168.12.151") == PlatformTypeEnum.NX_OS
    assert instance.get_platform_type("192.168.12.152") == PlatformTypeEnum.IOS_XE
    # Switch exists but reports no platformType -> None (not a raise).
    assert instance.get_platform_type("192.168.12.153") is None

    match = r"No switch found with fabricManagementIp '10\.0\.0\.1' in fabric 'fabric_1'"
    with pytest.raises(RuntimeError, match=match):
        instance.get_platform_type("10.0.0.1")


def test_fabric_context_00250() -> None:
    """
    # Summary

    Verify a switches-endpoint 404 for a nonexistent fabric raises "fabric not found" rather than a misleading
    "switch not found" (issue #399). The 404 is confirmed against `fabric_summary` before raising.

    ## Test

    - GET (switches) returns 404
    - `_load_switch_maps` consults `fabric_summary` (also 404) and raises the fabric-level error
    - The message matches `validate_for_mutation`'s "fabric not found" wording

    ## Classes and Methods

    - FabricContext.switch_map
    - FabricContext._load_switch_maps
    - FabricContext.fabric_exists
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_context(f"{method_name}a")  # switches 404
        yield responses_fabric_context(f"{method_name}b")  # summary 404 (fabric_exists confirmation)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    instance = FabricContext(rest_send=rest_send, fabric_name="missing_fabric")
    match = r"Fabric 'missing_fabric' not found"
    with pytest.raises(RuntimeError, match=match):
        result = instance.switch_map  # pylint: disable=unused-variable


# =============================================================================
# Test: validate_for_mutation
# =============================================================================


def test_fabric_context_00300() -> None:
    """
    # Summary

    Verify `validate_for_mutation` is a no-op when the fabric exists, is local, and is not in deployment freeze mode.

    ## Test

    - GET (summary) returns 200 with `local: true` and `fabricStatus: "default"`
    - `validate_for_mutation` does not raise

    ## Classes and Methods

    - FabricContext.validate_for_mutation
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_context(f"{method_name}a")

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


def test_fabric_context_00320() -> None:
    """
    # Summary

    Verify `validate_for_mutation` raises `RuntimeError` when the fabric is in deployment freeze mode.

    ## Test

    - GET (summary) returns 200 with `fabricStatus: "frozen"`
    - `validate_for_mutation` raises with a message that mentions deployment freeze and the fabric name

    ## Classes and Methods

    - FabricContext.validate_for_mutation
    - FabricContext.fabric_is_deployment_frozen
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_context(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
    match = r"Fabric 'fabric_1' is in deployment freeze mode"
    with pytest.raises(RuntimeError, match=match):
        instance.validate_for_mutation()


def test_fabric_context_00330() -> None:
    """
    # Summary

    Verify `validate_for_mutation` raises `RuntimeError` when the fabric is owned by a different controller in the cluster.

    ## Test

    - GET (summary) returns 200 with `local: false`
    - `validate_for_mutation` raises with a message that mentions a different controller and the fabric name

    ## Classes and Methods

    - FabricContext.validate_for_mutation
    - FabricContext.fabric_is_local
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_fabric_context(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    instance = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
    match = r"Fabric 'fabric_1' is owned by a different controller"
    with pytest.raises(RuntimeError, match=match):
        instance.validate_for_mutation()
