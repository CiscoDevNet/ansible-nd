# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the legacy NDModule request helper."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule


@pytest.mark.parametrize("status", [200, 207])
@pytest.mark.parametrize("accept_multistatus", [None, False, True])
def test_request_returns_http_207_body_only_when_explicitly_accepted(monkeypatch, status, accept_multistatus):
    """Opting into 207 returns its complete body; ordinary 200 stays compatible."""
    response_body = {
        "configurationDiffs": [
            {
                "interfaceName": "Ethernet1/1",
                "status": "success",
                "switchId": "SN1",
            },
            {
                "interfaceName": "Ethernet1/2",
                "status": "failed",
                "switchId": "SN2",
            },
        ]
    }
    connection = MagicMock()
    connection.send_request.return_value = {
        "body": response_body,
        "msg": "Multi-Status" if status == 207 else "OK",
        "status": status,
        "url": "https://nd.example/api/v1/manage/fabrics/fab/interfaceActions/preview",
    }
    connection.pop_messages.return_value = []
    monkeypatch.setattr("ansible_collections.cisco.nd.plugins.module_utils.nd.Connection", lambda socket_path: connection)
    module = SimpleNamespace(_socket_path="/tmp/ansible-connection", _debug=False, params={})
    if accept_multistatus is None:
        instance = NDModule(module)
    else:
        instance = NDModule(module, accept_multistatus=accept_multistatus)

    result = instance.request(
        "/api/v1/manage/fabrics/fab/interfaceActions/preview",
        method="POST",
        data={"interfaces": []},
    )

    if status == 200 or accept_multistatus is True:
        # The transport helper returns every item without interpreting status.
        assert result == response_body
    else:
        # Preserve the legacy fallthrough for a status that is not accepted.
        assert result is None
    assert instance.status == status
