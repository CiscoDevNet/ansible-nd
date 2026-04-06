# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Action plugin stub for cisco.nd.nd_links.

Ansible picks this up instead of forking a module subprocess. All real work
lives in ``NDActionBase``.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.cisco.nd.plugins.action.nd_action_base import NDActionBase


class ActionModule(NDActionBase):
    MODULE_NAME = "nd_links"
