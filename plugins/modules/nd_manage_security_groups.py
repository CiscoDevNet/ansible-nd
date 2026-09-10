#!/usr/bin/python

# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage security groups on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_security_groups
version_added: "2.0.0"
short_description: Manage security groups on Cisco Nexus Dashboard
description:
- Manage Nexus Dashboard security groups in a fabric.
- Security groups classify endpoints or networks through selectors and can be attached to switch intent.
- This module intentionally does not implement CSV import/export or O(state=gathered) in this first release.
author:
- Cisco
options:
  fabric_name:
    description:
    - Name of the standalone fabric or parent fabric group.
    type: str
    required: true
  cluster_name:
    description:
    - Optional Nexus Dashboard cluster name for multi-cluster API calls.
    type: str
  config:
    description:
    - List of security groups.
    type: list
    elements: dict
    required: true
    suboptions:
      name:
        description:
        - Security group name.
        - The characters C(!), C(@), C(#), C($), C(^), C(=), C(+), C({), and C(}) are not supported.
        type: str
        required: true
      tenant_name:
        description:
        - Tenant that owns the security group.
        - Omit this option for non-tenant VXLAN fabrics.
        - Set this only when the tenant is associated with the target fabric.
        type: str
      id:
        description:
        - Security group numeric identifier. Required when creating or replacing a group.
        type: int
      display_name:
        description:
        - Display name shown in Nexus Dashboard.
        type: str
      description:
        description:
        - Description for the security group.
        type: str
      attach:
        description:
        - Whether the security group should be attached after reconciliation.
        - Detaching a group that is still referenced by attached associations can be rejected by Nexus Dashboard.
        type: bool
      vrf_names:
        description:
        - VRFs associated with the security group. Required when creating or replacing a group.
        type: list
        elements: str
      selectors:
        description:
        - Selectors that define security group membership.
        type: list
        elements: dict
        suboptions:
          type:
            description:
            - Selector type.
            type: str
            required: true
            choices: [ connectedEndpoint, externalSubnet, network, networkPort, vm ]
          vrf_name:
            description:
            - VRF for connected endpoint or external subnet selectors.
            type: str
          ip:
            description:
            - IP address or prefix for connected endpoint or external subnet selectors.
            type: str
          network_name:
            description:
            - Network name for network or network port selectors.
            type: str
          switch_id:
            description:
            - Switch serial number for network port selectors.
            type: str
          interface_name:
            description:
            - Interface name for network port selectors.
            type: str
          vm_data:
            description:
            - VM selector data supplied by Nexus Dashboard VM integration.
            type: list
            elements: dict
      aci_data:
        description:
        - Optional ACI integration fields.
        type: dict
        suboptions:
          application_profile_name:
            description:
            - ACI application profile name.
            type: str
  config_actions:
    description:
    - Controls save and deploy behavior after inventory is updated.
    type: dict
    suboptions:
      save:
        description:
        - Save/Recalculate the configuration of the fabric after inventory is updated.
        type: bool
        default: true
      deploy:
        description:
        - Deploy the pending configuration after inventory is updated.
        - When set to C(true), C(save) must also be C(true).
        type: bool
        default: true
      type:
        description:
        - Scope of the deploy operation.
        type: str
        default: switch
        choices: [ switch, global ]
  state:
    description:
    - Desired state of the security groups.
    - O(state=merged) creates missing groups and updates specified fields.
    - O(state=replaced) replaces the listed groups.
    - O(state=overridden) makes the fabric's security group set match O(config). Use with caution.
    - O(state=deleted) removes the listed groups.
    - O(state=gathered) is intentionally deferred to a future release.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Deleting an attached group or a group referenced by associations can be rejected by Nexus Dashboard until dependencies are removed.
"""

EXAMPLES = r"""
- name: Create and attach a security group
  cisco.nd.nd_manage_security_groups:
    fabric_name: SITE1
    config:
      - name: app_web
        id: 101
        vrf_names:
          - vrf1
        attach: true
        selectors:
          - type: network
            network_name: web_net
    config_actions:
      save: true
      deploy: true
      type: switch
    state: merged

- name: Replace a security group selector set
  cisco.nd.nd_manage_security_groups:
    fabric_name: SITE1
    config:
      - name: app_web
        id: 101
        vrf_names:
          - vrf1
        selectors:
          - type: connectedEndpoint
            vrf_name: vrf1
            ip: 10.10.10.10
    state: replaced

- name: Override security groups
  cisco.nd.nd_manage_security_groups:
    fabric_name: SITE1
    config:
      - name: app_web
        id: 101
        vrf_names:
          - vrf1
    state: overridden

- name: Delete a security group
  cisco.nd.nd_manage_security_groups:
    fabric_name: SITE1
    config:
      - name: app_web
    state: deleted
"""

RETURN = r"""
"""

from ansible_collections.cisco.nd.plugins.module_utils.models.security.groups import SecurityGroupModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.security import SecurityGroupOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.security_module import run_security_module


def main():
    """Module entry point."""
    run_security_module(
        model_class=SecurityGroupModel,
        orchestrator_class=SecurityGroupOrchestrator,
        logger_name="nd.nd_manage_security_groups",
    )


if __name__ == "__main__":
    main()
