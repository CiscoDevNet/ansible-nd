# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Mock AnsibleModule for unit testing.

This module provides a mock implementation of Ansible's AnsibleModule
to avoid circular import issues between sender_file.py and common_utils.py.
"""

from __future__ import absolute_import, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

# Define base exception class
class AnsibleFailJson(Exception):
    """
    Exception raised by MockAnsibleModule.fail_json()
    """

# Try to import AnsibleFailJson from ansible.netcommon if available
# This allows compatibility with tests that expect the netcommon version
try:
    from ansible_collections.ansible.netcommon.tests.unit.modules.utils import (
        AnsibleFailJson as _NetcommonFailJson,
    )

    # Use the netcommon version if available
    AnsibleFailJson = _NetcommonFailJson  # type: ignore[misc]
except ImportError:
    # Use the local version defined above
    pass


class MockAnsibleModule:
    """
    # Summary

    Mock the AnsibleModule class for unit testing.

    ## Attributes

    - check_mode: Whether the module is running in check mode
    - params: Module parameters dictionary
    - argument_spec: Module argument specification
    - supports_check_mode: Whether the module supports check mode

    ## Methods

    - fail_json: Raises AnsibleFailJson exception with the provided message
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
        # Summary

        Mock the fail_json method.

        ## Parameters

        - msg: Error message
        - kwargs: Additional keyword arguments (ignored)

        ## Raises

        - AnsibleFailJson: Always raised with the provided message
        """
        raise AnsibleFailJson(msg)

    def public_method_for_pylint(self):
        """
        # Summary

        Add one public method to appease pylint.

        ## Raises

        None
        """
