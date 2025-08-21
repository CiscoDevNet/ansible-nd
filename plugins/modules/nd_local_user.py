#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_local_user
version_added: "1.4.0"
short_description: Manage local users on Cisco Nexus Dashboard
description:
- Manage local users on Cisco Nexus Dashboard (ND).
- It supports creating, updating, querying, and deleting local users.
author:
- Gaspard Micol (@gmicol)
options:
  email:
    description:
    - The email address of the local user.
    type: str
  login_id:
    description:
    - The login ID of the local user.
    - The O(login_id) must be defined when creating, updating or deleting a local user.
    type: str
  first_name:
    description:
    - The first name of the local user.
    type: str
  last_name:
    description:
    - The last name of the local user.
    type: str
  user_password:
    description:
    - The password of the local user.
    - Password must have a minimum of 8 characters to a maximum of 64 characters.
    - Password must have three of the following; one number, one lower case character, one upper case character, one special character.
    - The O(user_password) must be defined when creating a new local_user.
    type: str
  reuse_limitation:
    description:
    - The number of different passwords a user must use before they can reuse a previous one.
    - It defaults to C(0) when unset during creation.
    type: int
  time_interval_limitation:
    description:
    - The minimum time period that must pass before a previous password can be reused.
    - It defaults to C(0) when unset during creation.
    type: int
  security_domains:
    description:
    - The list of Security Domains and Roles for the local user.
    - At least, one Security Domain must be defined when creating a new local user.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the Security Domain to which the local user is given access.
        type: str
        required: true
        aliases: [ security_domain_name, domain_name ]
      roles:
        description:
        - The Permission Roles of the local user within the Security Domain.
        type: list
        elements: str
        choices: [ fabric_admin, observer, super_admin, support_engineer, approver, designer ]
    aliases: [ domains ]
  remote_id_claim:
    description:
    - The remote ID claim of the local user.
    type: str
  remote_user_authorization:
    description:
    - To enable/disable the Remote User Authorization of the local user.
    - Remote User Authorization is used for signing into Nexus Dashboard when using identity providers that cannot provide authorization claims.
      Once this attribute is enabled, the local user ID cannot be used to directly login to Nexus Dashboard.
    - It defaults to C(false) when unset during creation.
    type: bool
  state:
    description:
    - Use C(present) to create or update a local user.
    - Use C(absent) to delete an existing local user.
    - Use C(query) for listing all the existing local users or a specific local user if O(login_id) is specified.
    type: str
    default: present
    choices: [ present, absent, query ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.1.0 or higher.
- This module is not idempotent when creating or updating a local user object when O(user_password) is used.
"""

EXAMPLES = r"""
- name: Create a new local user
  cisco.nd.nd_local_user:
    email: user@example.com
    login_id: local_user
    first_name: User first name
    last_name: User last name
    user_password: localUserPassword1%
    reuse_limitation: 20
    time_interval_limitation: 10
    security_domains:
      name: all
      roles:
        - observer
        - support_engineer
    remote_id_claim: remote_user
    remote_user_authorization: true
    state: present
  register: result

- name: Create local user with minimal configuration
  cisco.nd.nd_local_user:
    login_id: local_user_min
    user_password: localUserMinuser_password
    security_domain: all
    state: present

- name: Update local user
  cisco.nd.nd_local_user:
    email: udpateduser@example.com
    login_id: local_user
    first_name: Updated user first name
    last_name: Updated user last name
    user_password: updatedLocalUserPassword1%
    reuse_limitation: 25
    time_interval_limitation: 15
    security_domains:
      - name: all
        roles: super_admin
      - name: ansible_domain
        roles: observer
    roles: super_admin
    remote_id_claim: ""
    remote_user_authorization: false
    state: present

- name: Query an existing local user
  cisco.nd.nd_local_user:
    login_id: local_user
    state: query
  register: query_result

- name: Query all local users
  cisco.nd.nd_local_user:
    state: query
  register: query_all

- name: Delete a local user
  cisco.nd.nd_local_user:
    login_id: local_user
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec, sanitize_dict
from ansible_collections.cisco.nd.plugins.module_utils.constants import USER_ROLES_MAPPING


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        email=dict(type="str"),
        login_id=dict(type="str"),
        first_name=dict(type="str"),
        last_name=dict(type="str"),
        user_password=dict(type="str", no_log=True),
        reuse_limitation=dict(type="int"),
        time_interval_limitation=dict(type="int"),
        security_domains=dict(
            type="list",
            elements="dict",
            options=dict(
                name=dict(type="str", required=True, aliases=["security_domain_name", "domain_name"]),
                roles=dict(type="list", elements="str", choices=list(USER_ROLES_MAPPING)),
            ),
            aliases=["domains"],
        ),
        remote_id_claim=dict(type="str"),
        remote_user_authorization=dict(type="bool"),
        state=dict(type="str", default="present", choices=["present", "absent", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["login_id"]],
            ["state", "absent", ["login_id"]],
        ],
    )

    nd = NDModule(module)

    email = nd.params.get("email")
    login_id = nd.params.get("login_id")
    first_name = nd.params.get("first_name")
    last_name = nd.params.get("last_name")
    user_password = nd.params.get("user_password")
    reuse_limitation = nd.params.get("reuse_limitation")
    time_interval_limitation = nd.params.get("time_interval_limitation")
    security_domains = nd.params.get("security_domains")
    remote_id_claim = nd.params.get("remote_id_claim")
    remote_user_authorization = nd.params.get("remote_user_authorization")
    state = nd.params.get("state")

    path = "/api/v1/infra/aaa/localUsers"
    if login_id:
        updated_path = "{0}/{1}".format(path, login_id)
        nd.existing = nd.previous = nd.query_obj(path=updated_path, ignore_not_found_error=True)
    else:
        nd.existing = nd.query_obj(path=path, ignore_not_found_error=True)

    if state == "present":

        payload = {
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "loginID": login_id,
            "password": user_password,
            "remoteIDClaim": remote_id_claim,
            "xLaunch": remote_user_authorization,
        }

        if security_domains:
            payload["rbac"] = {
                "domains": {
                    security_domain.get("name"): {
                        "roles": [USER_ROLES_MAPPING.get(role) for role in security_domain["roles"]] if isinstance(security_domain.get("roles"), list) else [],
                    }
                    for security_domain in security_domains
                },
            }
        if reuse_limitation or time_interval_limitation:
            payload["passwordPolicy"] = sanitize_dict(
                {
                    "reuseLimitation": reuse_limitation,
                    "timeIntervalLimitation": time_interval_limitation,
                }
            )

        nd.sanitize(payload)

        if module.check_mode:
            nd.existing = nd.proposed
        else:
            if not nd.existing:
                nd.existing = nd.request(path=path, method="POST", data=payload)
            elif nd.get_diff(unwanted=[["passwordPolicy", "passwordChangeTime"], ["userID"]]):
                nd.existing = nd.request(path=updated_path, method="PUT", data=payload)

    elif state == "absent":
        if nd.existing:
            if not module.check_mode:
                nd.request(path=updated_path, method="DELETE")
            nd.existing = {}

    nd.exit_json()


if __name__ == "__main__":
    main()
