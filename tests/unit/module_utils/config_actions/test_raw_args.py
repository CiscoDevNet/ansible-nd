# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Unit tests for config_actions.raw_args.
"""

from __future__ import annotations

import json

from ansible.module_utils import basic as ansible_basic
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.raw_args import get_raw_module_args


class AnsibleArgsPatch:
    """
    # Summary

    Context manager for temporarily replacing Ansible's serialized module arguments.

    ## Raises

    None
    """

    def __init__(self, value: object) -> None:
        self.value = value
        self.previous = getattr(ansible_basic, "_ANSIBLE_ARGS", None)

    def __enter__(self) -> None:
        ansible_basic._ANSIBLE_ARGS = self.value  # pylint: disable=protected-access

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        ansible_basic._ANSIBLE_ARGS = self.previous  # pylint: disable=protected-access


def test_config_actions_raw_args_00000() -> None:
    """
    # Summary

    Verify raw args are decoded from Ansible's bytes payload.

    ## Raises

    None
    """
    payload = json.dumps({"ANSIBLE_MODULE_ARGS": {"config_actions": {"deploy": False}}}).encode("utf-8")
    with AnsibleArgsPatch(payload):
        assert get_raw_module_args() == {"config_actions": {"deploy": False}}


def test_config_actions_raw_args_00010() -> None:
    """
    # Summary

    Verify raw args are decoded from Ansible's string payload.

    ## Raises

    None
    """
    payload = json.dumps({"ANSIBLE_MODULE_ARGS": {"config_actions": {}}})
    with AnsibleArgsPatch(payload):
        assert get_raw_module_args() == {"config_actions": {}}


def test_config_actions_raw_args_00020() -> None:
    """
    # Summary

    Verify malformed or unexpected payloads return an empty dictionary.

    ## Raises

    None
    """
    with AnsibleArgsPatch("{not-json"):
        assert get_raw_module_args() == {}
    with AnsibleArgsPatch(json.dumps({"ANSIBLE_MODULE_ARGS": []})):
        assert get_raw_module_args() == {}
