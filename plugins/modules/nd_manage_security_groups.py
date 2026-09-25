#!/usr/bin/python

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage security groups on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: nd_manage_security_groups
version_added: "2.0.0"
short_description: Manage security groups on Cisco Nexus Dashboard
description:
- Manage security groups through the Nexus Dashboard (ND) Manage Security and Segmentation API.
- ND 4.2.1 and ND 4.3.1 are supported.
- Security groups classify endpoints, subnets, networks, ports, or virtual machines through selectors.
author:
- Mike Wiebe (@mikewiebe)
options:
  fabric_name:
    description:
    - Name of the standalone fabric or parent fabric group that owns the groups.
    type: str
    required: true
  cluster_name:
    description:
    - Name of the ND cluster that manages the fabric in a multi-cluster deployment.
    - When set, the value is sent as the C(clusterName) query parameter on fabric, resource, and action requests.
    type: str
  config:
    description:
    - List of security groups.
    - Required for write states. Omit for O(state=gathered) to return all groups.
    type: list
    elements: dict
    required: false
    suboptions:
      name:
        description:
        - Security group name.
        - The characters C(!), C(@), C(#), C($), C(^), C(=), C(+), C({), and C(}) are not supported.
        - A name without O(config.tenant_name) can contain at most 63 characters.
        - The maximum qualified-name length is 115 characters on ND 4.2.1 and 125 characters on ND 4.3.1.
        type: str
        required: true
      tenant_name:
        description:
        - Tenant that owns the security group.
        - The module sends tenant-scoped names as C(tenant_name~name) and returns gathered names in separate O(config.tenant_name) and O(config.name) fields.
        - Omit this option for non-tenant VXLAN fabrics.
        type: str
      id:
        description:
        - Numeric security group identifier.
        - Use 16 through 65535 for user-created groups; values 0 through 15 are reserved for controller-owned groups.
        - Required when creating on ND 4.2.1.
        - May be omitted when creating on ND 4.3.1 so the controller generates the identifier.
        - On ND 4.3.1 updates, an omitted controller-generated identifier is preserved; an explicitly supplied identifier must match the current value.
        type: int
      display_name:
        description:
        - Display name shown in ND. The maximum length is 64 characters.
        type: str
      description:
        description:
        - Description for the security group. The maximum length is 128 characters.
        - ND 4.3.1 does not accept carriage-return or line-feed characters.
        type: str
      attach:
        description:
        - C(true) attaches the group after reconciliation; C(false) detaches it.
        - New groups default to attached when this option is omitted.
        - With O(state=merged), omission preserves the current attachment state.
        - With O(state=replaced) or O(state=overridden), omission resets the attachment state to C(true).
        - Detaching a group referenced by an attached association can be rejected by ND.
        type: bool
      vrf_names:
        description:
        - Unique VRFs associated with the group. Required for create and update operations.
        - Each name can contain at most 94 characters.
        type: list
        elements: str
      selectors:
        description:
        - Unique selectors that define security group membership.
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
            - VRF for a C(connectedEndpoint) or C(externalSubnet) selector.
            type: str
          ip:
            description:
            - IP address or prefix for a C(connectedEndpoint) or C(externalSubnet) selector.
            type: str
          network_name:
            description:
            - Network for a C(network) or C(networkPort) selector. The maximum length is 128 characters.
            type: str
          switch_id:
            description:
            - Switch serial number for a C(networkPort) selector.
            type: str
          interface_name:
            description:
            - Interface name for a C(networkPort) selector.
            type: str
          vm_data:
            description:
            - Unique vCenter virtual-machine selector data. Required and nonempty for O(config.selectors.type=vm).
            type: list
            elements: dict
            suboptions:
              vm_data_type:
                description:
                - VM data discriminator. Only C(vCenter) is supported.
                type: str
                default: vCenter
                choices: [ vCenter ]
                aliases: [ vmDataType ]
              v_center:
                description:
                - vCenter name known to ND.
                type: str
                required: true
                aliases: [ vCenter ]
              vm_uuid:
                description:
                - Virtual-machine UUID.
                type: str
                required: true
                aliases: [ vmUuid ]
              nic_mac:
                description:
                - Virtual NIC MAC address.
                type: str
                required: true
                aliases: [ nicMac ]
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
    - Controls fabric save and deploy actions after a resource or attach/detach change.
    - Omit this option when O(state=gathered). Read-only runs never save or deploy.
    type: dict
    suboptions:
      save:
        description:
        - Save and recalculate the fabric configuration after a change.
        type: bool
        default: false
      deploy:
        description:
        - Deploy pending fabric configuration after a change.
        - C(true) requires O(config_actions.save=true).
        type: bool
        default: false
      type:
        description:
        - Deployment scope.
        - C(switch) deploys affected out-of-sync switches; C(global) deploys all pending fabric changes.
        type: str
        default: switch
        choices: [ switch, global ]
  state:
    description:
    - Desired state of the security groups.
    - O(state=merged) creates missing groups and updates specified fields.
    - O(state=replaced) replaces the listed groups.
    - O(state=overridden) makes the fabric's group set match O(config). Use with caution.
    - O(state=deleted) removes the listed groups.
    - O(state=gathered) returns replayable configuration without changing, attaching, detaching, saving, or deploying anything.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted, gathered ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Group Based Policy must already be enabled and ready on the target fabric. This module does not enable the feature or reload switches.
- Security resources are supported only on iBGP VXLAN fabrics. PVLAN, change-control, and eBGP-underlay VXLAN fabrics are unsupported.
- O(config.selectors.type=networkPort) requires NX-OS 10.6(1) or later. O(config.selectors.type=vm) requires VMM integration.
- Controller-owned default groups and IDs 0 through 15 are excluded from gathered output and are never modified or deleted by any state.
- Create referenced groups before associations. Delete associations before deleting their groups.
- Attaching an association can implicitly attach its groups. Detaching an association does not detach them.
- Controller-returned VM inventory fields are omitted from gathered output, diffs, and write payloads.
- CSV import and export workflows and ND 4.3 security-group migration APIs are outside this module's scope.
"""

EXAMPLES = r"""
- name: Create and attach a security group on ND 4.2.1
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
    state: merged

- name: Let ND 4.3.1 assign the ID and save without deploying
  cisco.nd.nd_manage_security_groups:
    fabric_name: SITE1
    cluster_name: cluster-1
    config:
      - name: app_generated
        vrf_names:
          - vrf1
        attach: false
    config_actions:
      save: true
      deploy: false
    state: merged

- name: Select one virtual-machine NIC
  cisco.nd.nd_manage_security_groups:
    fabric_name: SITE1
    config:
      - name: app_vm
        id: 102
        vrf_names:
          - vrf1
        attach: false
        selectors:
          - type: vm
            vm_data:
              - vm_data_type: vCenter
                v_center: vc1.example.com
                vm_uuid: 421b12a0-1234-5678-9abc-0123456789ab
                nic_mac: 00:50:56:aa:bb:cc
    state: replaced

- name: Detach a security group
  cisco.nd.nd_manage_security_groups:
    fabric_name: SITE1
    config:
      - name: app_web
        id: 101
        vrf_names:
          - vrf1
        attach: false
    state: merged

- name: Gather groups as replayable module configuration
  cisco.nd.nd_manage_security_groups:
    fabric_name: SITE1
    state: gathered
  register: security_groups

- name: Authoritatively retain only the listed security groups
  cisco.nd.nd_manage_security_groups:
    fabric_name: SITE1
    config:
      - name: app_web
        id: 101
        vrf_names:
          - vrf1
        attach: false
    state: overridden

- name: Delete a security group after its associations have been deleted
  cisco.nd.nd_manage_security_groups:
    fabric_name: SITE1
    config:
      - name: app_web
    state: deleted
"""

RETURN = r"""
changed:
  description: Whether the module changed, or in check mode would change, security groups or their attachment state.
  returned: always
  type: bool
  sample: true
output_level:
  description: Output verbosity selected by O(output_level).
  returned: always
  type: str
  sample: normal
before:
  description: Groups before reconciliation. Empty for O(state=gathered).
  returned: always
  type: list
  elements: dict
after:
  description: Groups after reconciliation. Empty for O(state=gathered).
  returned: always
  type: list
  elements: dict
diff:
  description: Difference between C(before) and C(after).
  returned: for write states
  type: list
  elements: dict
proposed:
  description: Configuration proposed by the task.
  returned: for write states when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
gathered:
  description:
  - Groups read from ND, pruned to fields accepted by O(config).
  - An empty list is returned when no groups exist.
  returned: when O(state=gathered)
  type: list
  elements: dict
security_actions_result:
  description: ND attach and detach action results, keyed by the action that ran.
  returned: when O(config.attach) requests an attachment-state action
  type: dict
  contains:
    attach:
      description: ND attach response, or a planned action containing C(planned=true) and C(securityGroupNames) in check mode.
      returned: when one or more groups are attached or would be attached
      type: dict
    detach:
      description: ND detach response, or a planned action containing C(planned=true) and C(securityGroupNames) in check mode.
      returned: when one or more groups are detached or would be detached
      type: dict
config_actions_result:
  description: Structured save and deploy plan or result, including requested and effective actions, status, reason, targets, and action steps.
  returned: when save or deploy is requested for a changed or planned resource
  type: dict
api_paths:
  description: API paths included in the result at Ansible verbosity level 2 or higher.
  returned: at verbosity level 2 or higher
  type: list
  elements: str
api_verbs:
  description: HTTP verbs included in the result at Ansible verbosity level 2 or higher.
  returned: at verbosity level 2 or higher
  type: list
  elements: str
logs:
  description: Internal diagnostic log messages.
  returned: when O(output_level=debug)
  type: list
  elements: str
msg:
  description: Human-readable error message.
  returned: on failure
  type: str
"""

from ansible_collections.cisco.nd.plugins.module_utils.models.security.groups import (
    SecurityGroupModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.security import (
    SecurityGroupOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.security_module import (
    run_security_module,
)


def main():
    """Module entry point."""
    run_security_module(
        model_class=SecurityGroupModel,
        orchestrator_class=SecurityGroupOrchestrator,
        logger_name="nd.nd_manage_security_groups",
    )


if __name__ == "__main__":
    main()
