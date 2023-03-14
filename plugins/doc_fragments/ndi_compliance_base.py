# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Standard files documentation fragment
    DOCUMENTATION = r"""
options:
  insights_group:
    description:
    - The name of the insights group.
    type: str
    required: yes
    aliases: [ fab_name, ig_name ]
  name:
    description:
    - The name of the compliance requirement.
    type: str
  description:
    description:
    - The description of the compliance requirement.
    type: str
    aliases: [ descr ]
  enabled:
    description:
    - Enable the compliance requirement.
    type: bool
  sites:
    description:
    - The names of the sites.
    type: list
    elements: str
  state:
    description:
    - Use C(query) for retrieving the version object.
    type: str
    choices: [ query, absent, present ]
    default: query
"""
