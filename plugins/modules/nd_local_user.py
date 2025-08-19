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
  config:
    description:
    - The list of the local users to configure.
    type: list
    elements: dict
    suboptions:
      email:
        description:
        - The email address of the local user.
        type: str
      login_id:
        description:
        - The login ID of the local user.
        - The O(config.login_id) must be defined when creating, updating or deleting a local user.
        type: str
        required: true
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
        - The O(config.user_password) must be defined when creating a new local_user.
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
    - The desired state of the network resources on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new resources and updates existing ones as defined in your configuration.
      Resources on ND that are not specified in the configuration will be left unchanged.
    - Use O(state=replaced) to replace the resources specified in the configuration.
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
      The resources on ND will be modified to exactly match the configuration.
      Any resource existing on ND but not present in the configuration will be deleted. Use with extra caution.
    - Use O(state=deleted) to remove the resources specified in the configuration from the Cisco Nexus Dashboard.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.1.0 or higher.
- This module is not idempotent when creating or updating a local user object when O(config.user_password) is used.
"""

EXAMPLES = r"""
- name: Create a new local user
  cisco.nd.nd_local_user:
    config:
      - email: user@example.com
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
    state: merged
  register: result

- name: Create local user with minimal configuration
  cisco.nd.nd_local_user:
    config:
      - login_id: local_user_min
        user_password: localUserMinuser_password
        security_domain: all
    state: merged

- name: Update local user
  cisco.nd.nd_local_user:
    config:
      - email: udpateduser@example.com
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
    state: replaced

- name: Delete a local user
  cisco.nd.nd_local_user:
    config:
      - login_id: local_user
    state: deleted
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec, NDModule
from ansible_collections.cisco.nd.plugins.module_utils.nd_network_resources import NDNetworkResourceModule
from ansible_collections.cisco.nd.plugins.module_utils.constants import USER_ROLES_MAPPING


# Actions overwrite functions
def quey_all_local_users(nd):
    return nd.query_obj(nd.path).get("localusers")


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        config=dict(
            type="list",
            elements="dict",
            options=dict(
                email=dict(type="str"),
                login_id=dict(type="str", required=True),
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
            ),
        ),
        override_exceptions=dict(type="list", elements="str"),
        state=dict(type="str", default="merged", choices=["merged", "replaced", "overridden", "deleted"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    path = "/api/v1/infra/aaa/localUsers"
    identifier_keys = ["loginID"]
    actions_overwrite_map = {"query_all": quey_all_local_users}

    nd = NDNetworkResourceModule(module, path, identifier_keys, actions_overwrite_map=actions_overwrite_map)

    state = nd.params.get("state")
    config = nd.params.get("config")
    override_exceptions = nd.params.get("override_exceptions")
    new_config = []
    for object in config:
        payload = {
            "email": object.get("email"),
            "firstName": object.get("first_name"),
            "lastName": object.get("last_name"),
            "loginID": object.get("login_id"),
            "password": object.get("user_password"),
            "remoteIDClaim": object.get("remote_id_claim"),
            "xLaunch": object.get("remote_user_authorization"),
        }

        if object.get("security_domains"):
            payload["rbac"] = {
                "domains": {
                    security_domain.get("name"): {
                        "roles": (
                            [USER_ROLES_MAPPING.get(role) for role in security_domain["roles"]] if isinstance(security_domain.get("roles"), list) else []
                        )
                    }
                    for security_domain in object["security_domains"]
                },
            }
        if object.get("reuse_limitation") or object.get("time_interval_limitation"):
            payload["passwordPolicy"] = {
                "reuseLimitation": object.get("reuse_limitation"),
                "timeIntervalLimitation": object.get("time_interval_limitation"),
            }
        new_config.append(payload)

    nd.manage_state(state=state, new_configs=new_config, unwanted_keys=[["passwordPolicy", "passwordChangeTime"], ["userID"]], override_exceptions=override_exceptions)

    nd.exit_json()


if __name__ == "__main__":
    main()
