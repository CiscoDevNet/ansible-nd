# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the legacy NDModule request helper."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule


def test_request_returns_http_207_response_body():
    """HTTP 207 Multi-Status is a successful response with a usable body."""
    response_body = {
        "configurationDiffs": [
            {
                "interfaceName": "Ethernet1/1",
                "status": "success",
                "switchId": "SN1",
            }
        ]
    }
    connection = MagicMock()
    connection.send_request.return_value = {
        "body": response_body,
        "msg": "Multi-Status",
        "status": 207,
        "url": "https://nd.example/api/v1/manage/fabrics/fab/interfaceActions/preview",
    }
    connection.pop_messages.return_value = []

    instance = NDModule.__new__(NDModule)
    instance.connection = connection
    instance.has_modified = False
    instance.httpapi_logs = []
    instance.method = None
    instance.module = SimpleNamespace(_socket_path="/tmp/ansible-connection")
    instance.path = None
    instance.result = {}
    instance.response = None
    instance.status = None
    instance.url = None

    result = instance.request(
        "/api/v1/manage/fabrics/fab/interfaceActions/preview",
        method="POST",
        data={"interfaces": []},
    )

    assert result == response_body
    assert instance.status == 207
