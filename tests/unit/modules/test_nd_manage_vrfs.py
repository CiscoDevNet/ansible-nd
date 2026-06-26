# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for plugins/modules/nd_manage_vrfs.py.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

from unittest.mock import patch

from ansible_collections.cisco.nd.plugins.modules import nd_manage_vrfs


def test_nd_manage_vrfs_requires_pydantic_immediately_after_module_creation():
    """
    Verify the module wrapper checks for Pydantic before fabric resolution or
    orchestrator construction.
    """
    events = []

    class FakeAnsibleModule:
        def __init__(self, **kwargs):
            self.params = {
                "fabric_name": "fab1",
                "state": "gathered",
                "config": [],
            }
            self.kwargs = kwargs
            events.append(("AnsibleModule", self))

        def exit_json(self, **kwargs):
            events.append(("exit_json", kwargs))

        def fail_json(self, **kwargs):
            raise AssertionError(f"fail_json called unexpectedly: {kwargs}")

    class FakeNDModule:
        def __init__(self, module):
            events.append(("NDModule", module))

    class FakeResolver:
        def __init__(self, nd_module, fabric_name):
            events.append(("VrfFabricResolver", nd_module, fabric_name))

        def resolve(self):
            events.append(("resolve",))
            return object()

    class FakeCoordinator:
        def __init__(self, module, strategy):
            events.append(("VrfWorkflowCoordinator", module, strategy))

        def run(self):
            events.append(("run",))
            return {"changed": False}

    def fake_require_pydantic(module):
        events.append(("require_pydantic", module))

    with patch.object(nd_manage_vrfs, "AnsibleModule", FakeAnsibleModule), patch.object(
        nd_manage_vrfs, "require_pydantic", fake_require_pydantic
    ), patch.object(nd_manage_vrfs, "NDModule", FakeNDModule), patch.object(nd_manage_vrfs, "VrfFabricResolver", FakeResolver), patch.object(
        nd_manage_vrfs, "VrfWorkflowCoordinator", FakeCoordinator
    ):
        nd_manage_vrfs.main()

    assert [event[0] for event in events] == [
        "AnsibleModule",
        "require_pydantic",
        "NDModule",
        "VrfFabricResolver",
        "resolve",
        "VrfWorkflowCoordinator",
        "run",
        "exit_json",
    ]
    assert events[1][1] is events[2][1]
    assert events[0][1].kwargs["supports_check_mode"] is True
