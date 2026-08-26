# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for fabric_details_cache.py."""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.fabric_details_cache import FabricDetailsCache


class _FakeRestSend:
    """Minimal RestSend stand-in for FabricDetailsCache tests."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.path = None
        self.verb = None
        self.return_code = 200
        self.success = True
        self.error_summary = ""
        self.response_current = {"DATA": {}}

    def commit(self):
        self.calls.append((self.path, self.verb))
        response = self.responses.pop(0)
        self.return_code = response.get("RETURN_CODE", 200)
        self.success = response.get("success", True)
        self.error_summary = response.get("error_summary", "")
        self.response_current = {"DATA": response.get("DATA", {})}


def test_fabric_details_cache_get_fabric_type_uses_management_type_and_caches():
    rest_send = _FakeRestSend(
        [
            {
                "DATA": {
                    "fabricType": "ignored",
                    "management": {"type": "vxlanCampus", "greenfieldDebugFlag": "enable"},
                }
            }
        ]
    )
    context = FabricDetailsCache(rest_send=rest_send, fabric_name="Campus_AK")

    assert context.get_fabric_type() == "vxlanCampus"
    assert context.is_greenfield_debug_enabled() is True
    assert context.get_fabric_type() == "vxlanCampus"
    assert rest_send.calls == [("/api/v1/manage/fabrics/Campus_AK", HttpVerbEnum.GET)]


def test_fabric_details_cache_404_returns_none_and_get_details_raises():
    rest_send = _FakeRestSend([{"RETURN_CODE": 404, "success": False, "DATA": {"error": "not found"}}])
    context = FabricDetailsCache(rest_send=rest_send, fabric_name="missing")

    assert context.fabric_details is None
    with pytest.raises(ValueError, match="fabric was not found"):
        context.get_fabric_details()


def test_fabric_details_cache_controller_failure_raises_runtime_error():
    rest_send = _FakeRestSend([{"RETURN_CODE": 500, "success": False, "error_summary": "controller unavailable"}])
    context = FabricDetailsCache(rest_send=rest_send, fabric_name="fab1")

    with pytest.raises(RuntimeError, match="GET /api/v1/manage/fabrics/fab1 failed controller unavailable"):
        context.get_fabric_details()


@pytest.mark.parametrize(
    "data",
    [
        [],
        {},
        {"management": []},
        {"management": {}},
        {"management": {"type": None}},
        {"management": {"type": "  "}},
        {"fabricType": "vxlanCampus"},
    ],
)
def test_fabric_details_cache_rejects_malformed_fabric_type(data):
    rest_send = _FakeRestSend([{"DATA": data}])
    context = FabricDetailsCache(rest_send=rest_send, fabric_name="fab1")

    with pytest.raises(ValueError, match="Unable to determine fabric type|expected dictionary DATA"):
        context.get_fabric_type()
