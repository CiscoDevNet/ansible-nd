# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from unittest.mock import MagicMock

import pytest

from ansible_collections.cisco.nd.plugins.httpapi.nd import HttpApi


@pytest.mark.parametrize("connected", [False, True])
def test_send_request_preserves_persistent_command_timeout(connected):
    connection = MagicMock()
    connection._connected = connected
    options = {
        "host": "https://nd.example",
        "persistent_command_timeout": 1000,
        "session_key": None,
        "remote_user": "admin",
    }
    connection.get_option.side_effect = options.get
    connection.set_option.side_effect = options.__setitem__
    connection.send.return_value = (None, '{"ok": true}')
    httpapi = HttpApi(connection)
    httpapi.get_option = MagicMock(return_value="DefaultAuth")
    httpapi.params = {"timeout": 30}

    httpapi.send_request("GET", "/api/v1/test")

    assert connection._connected is connected
    assert options["persistent_command_timeout"] == 1000
    assert not any(call.args and call.args[0] == "persistent_command_timeout" for call in connection.set_option.call_args_list)


@pytest.mark.parametrize(
    ("response", "build_version", "product_version"),
    (
        ({"body": {"buildVersion": "4.3.1.175", "productVersion": "4.3.1a"}}, "4.3.1.175", "4.3.1a"),
        ({"body": {}}, None, None),
    ),
)
def test_nd_versions_are_cached_from_one_about_request(response, build_version, product_version):
    httpapi = HttpApi(MagicMock())
    httpapi._send_nd_request = MagicMock(return_value=response)

    assert httpapi.get_version("nd") == build_version
    assert httpapi.get_build_version("nd") == build_version
    assert httpapi.get_product_version("nd") == product_version
    assert httpapi.get_version("nd") == build_version
    assert httpapi.get_product_version("nd") == product_version
    httpapi._send_nd_request.assert_called_once_with("GET", "/api/v1/infra/about", httpapi.headers)
