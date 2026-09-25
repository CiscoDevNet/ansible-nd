#!/usr/bin/python

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage security associations on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: nd_manage_security_associations
version_added: "2.0.0"
short_description: Manage security associations on Cisco Nexus Dashboard
description:
- Manage security associations through the Nexus Dashboard (ND) Manage Security and Segmentation API.
- ND 4.2.1 and ND 4.3.1 are supported.
- An association links an existing contract with existing source and destination security groups.
author:
- Mike Wiebe (@mikewiebe)
options:
  fabric_name:
    description:
    - Name of the standalone fabric or parent fabric group that owns the associations.
    type: str
    required: true
  cluster_name:
    description:
    - Name of the ND cluster that manages the fabric in a multi-cluster deployment.
    - When set, the value is sent as the C(clusterName) query parameter on fabric, resource, and action requests.
    type: str
  config:
    description:
    - List of security associations.
    - Required for write states. Omit for O(state=gathered) to return all associations.
    type: list
    elements: dict
    required: false
    suboptions:
      name:
        description:
        - Security association name. Both unqualified and tenant-qualified names can contain at most 128 characters.
        type: str
        required: true
      tenant_name:
        description:
        - Tenant that owns the security association.
        - The module sends tenant-scoped names as C(tenant_name~name) and returns gathered names in separate O(config.tenant_name) and O(config.name) fields.
        - Omit this option for non-tenant VXLAN fabrics.
        type: str
      display_name:
        description:
        - Display name shown in ND. The maximum length is 64 characters.
        type: str
      description:
        description:
        - Description for the security association. The maximum length is 128 characters.
        - ND 4.3.1 does not accept carriage-return or line-feed characters.
        type: str
      contract_name:
        description:
        - Existing security contract name. This reference is case insensitive and required when creating an association.
        - Use C(tenant_name~contract_name) for a non-default tenant.
        - This field is immutable after creation; delete and recreate the association to change it.
        type: str
      src_security_group_name:
        description:
        - Existing source security group name. Required when creating an association.
        - This field is immutable after creation; delete and recreate the association to change it.
        type: str
      src_vrf_name:
        description:
        - Source VRF name. When both VRFs are provided, it must match O(config.dst_vrf_name).
        - This field is immutable after creation.
        type: str
      dst_security_group_name:
        description:
        - Existing destination security group name. Required when creating an association.
        - This field is immutable after creation; delete and recreate the association to change it.
        type: str
      dst_vrf_name:
        description:
        - Destination VRF name. When both VRFs are provided, it must match O(config.src_vrf_name).
        - This field is immutable after creation.
        type: str
      attach:
        description:
        - C(true) attaches the association after reconciliation; C(false) detaches it.
        - New associations default to attached when this option is omitted.
        - With O(state=merged), omission preserves the current attachment state.
        - With O(state=replaced) or O(state=overridden), omission resets the attachment state to C(true).
        - Attaching an association can implicitly attach its source and destination groups.
        - Detaching an association does not detach either group.
        type: bool
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
    - Desired state of the security associations.
    - O(state=merged) creates missing associations and updates mutable metadata.
    - O(state=replaced) replaces mutable fields of the listed associations.
    - O(state=overridden) makes the fabric's association set match O(config). Use with caution.
    - O(state=deleted) removes the listed associations.
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
- Create protocol definitions, contracts, and security groups before their associations. Delete associations first during cleanup.
- Contract, source group, destination group, and source/destination VRF references are immutable after creation.
- CSV import and export workflows are outside this module's scope.
"""

EXAMPLES = r"""
- name: Create and attach a security association without saving or deploying
  cisco.nd.nd_manage_security_associations:
    fabric_name: SITE1
    config:
      - name: web_to_app
        contract_name: allow_web
        src_security_group_name: app_web
        src_vrf_name: vrf1
        dst_security_group_name: app_app
        dst_vrf_name: vrf1
        attach: true
    state: merged

- name: Replace mutable association metadata and save and deploy affected switches
  cisco.nd.nd_manage_security_associations:
    fabric_name: SITE1
    cluster_name: cluster-1
    config:
      - name: web_to_app
        contract_name: allow_web
        src_security_group_name: app_web
        src_vrf_name: vrf1
        dst_security_group_name: app_app
        dst_vrf_name: vrf1
        description: Updated description
        attach: false
    config_actions:
      save: true
      deploy: true
      type: switch
    state: replaced

- name: Detach an association while leaving its groups attached
  cisco.nd.nd_manage_security_associations:
    fabric_name: SITE1
    config:
      - name: web_to_app
        contract_name: allow_web
        src_security_group_name: app_web
        dst_security_group_name: app_app
        attach: false
    state: merged

- name: Gather associations as replayable module configuration
  cisco.nd.nd_manage_security_associations:
    fabric_name: SITE1
    state: gathered
  register: security_associations

- name: Authoritatively retain only the listed associations
  cisco.nd.nd_manage_security_associations:
    fabric_name: SITE1
    config:
      - name: web_to_app
        contract_name: allow_web
        src_security_group_name: app_web
        src_vrf_name: vrf1
        dst_security_group_name: app_app
        dst_vrf_name: vrf1
        attach: false
    state: overridden

- name: Delete an association before deleting its groups and contract
  cisco.nd.nd_manage_security_associations:
    fabric_name: SITE1
    config:
      - name: web_to_app
    state: deleted
"""

RETURN = r"""
changed:
  description: Whether the module changed, or in check mode would change, security associations or their attachment state.
  returned: always
  type: bool
  sample: true
output_level:
  description: Output verbosity selected by O(output_level).
  returned: always
  type: str
  sample: normal
before:
  description: Associations before reconciliation. Empty for O(state=gathered).
  returned: always
  type: list
  elements: dict
after:
  description: Associations after reconciliation. Empty for O(state=gathered).
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
  - Associations read from ND, pruned to fields accepted by O(config).
  - An empty list is returned when no associations exist.
  returned: when O(state=gathered)
  type: list
  elements: dict
security_actions_result:
  description: ND attach and detach action results, keyed by the action that ran.
  returned: when O(config.attach) requests an attachment-state action
  type: dict
  contains:
    attach:
      description: ND attach response, or a planned action containing C(planned=true) and C(securityAssociationNames) in check mode.
      returned: when one or more associations are attached or would be attached
      type: dict
    detach:
      description: ND detach response, or a planned action containing C(planned=true) and C(securityAssociationNames) in check mode.
      returned: when one or more associations are detached or would be detached
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

from ansible_collections.cisco.nd.plugins.module_utils.models.security.associations import (
    SecurityAssociationModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.security import (
    SecurityAssociationOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.security_module import (
    run_security_module,
)


def main():
    """Module entry point."""
    run_security_module(
        model_class=SecurityAssociationModel,
        orchestrator_class=SecurityAssociationOrchestrator,
        logger_name="nd.nd_manage_security_associations",
    )


if __name__ == "__main__":
    main()
