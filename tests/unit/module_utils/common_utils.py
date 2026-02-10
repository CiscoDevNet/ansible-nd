# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Common utilities used by unit tests.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name


from contextlib import contextmanager

import pytest
from ansible_collections.ansible.netcommon.tests.unit.modules.utils import \
    AnsibleFailJson
# from ansible_collections.cisco.dcnm.plugins.module_utils.common.controller_version import \
#     ControllerVersion
from ansible_collections.cisco.nd.plugins.module_utils.log import Log
from ansible_collections.cisco.nd.plugins.module_utils.sender_file import \
    Sender as SenderFile

from ansible_collections.cisco.nd.tests.unit.module_utils.fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator

params = {
    "state": "merged",
    "config": {"switches": [{"ip_address": "172.22.150.105"}]},
    "check_mode": False,
}


class MockAnsibleModule:
    """
    Mock the AnsibleModule class
    """

    check_mode = False

    params = {"config": {"switches": [{"ip_address": "172.22.150.105"}]}}
    argument_spec = {
        "config": {"required": True, "type": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted", "query"]},
        "check_mode": False,
    }
    supports_check_mode = True

    @staticmethod
    def fail_json(msg, **kwargs) -> AnsibleFailJson:
        """
        mock the fail_json method
        """
        raise AnsibleFailJson(msg)

    def public_method_for_pylint(self):
        """
        Add one public method to appease pylint
        """


# See the following for explanation of why fixtures are explicitely named
# https://pylint.pycqa.org/en/latest/user_guide/messages/warning/redefined-outer-name.html


# @pytest.fixture(name="controller_version")
# def controller_version_fixture():
#     """
#     return ControllerVersion instance.
#     """
#     return ControllerVersion()


@pytest.fixture(name="sender_file")
def sender_file_fixture():
    """
    return Send() imported from sender_file.py
    """

    def responses():
        yield {}

    instance = SenderFile()
    instance.gen = ResponseGenerator(responses())
    return instance


@pytest.fixture(name="log")
def log_fixture():
    """
    return Log with mocked AnsibleModule
    """
    return Log()


@contextmanager
def does_not_raise():
    """
    A context manager that does not raise an exception.
    """
    yield


def responses_sender_file(key: str) -> dict[str, str]:
    """
    Return data in responses_SenderFile.json
    """
    response_file = "responses_SenderFile"
    response = load_fixture(response_file).get(key)
    print(f"responses_sender_file: {key} : {response}")
    return response
