#!/usr/bin/python

# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage security associations on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_security_associations
version_added: "2.0.0"
short_description: Manage security associations on Cisco Nexus Dashboard
description:
- Manage Nexus Dashboard security associations in a fabric.
- A security association links a contract, source security group, and destination security group.
- Source group, destination group, and contract changes are treated as immutable updates by this module.
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
    - List of security associations.
    type: list
    elements: dict
    required: true
    suboptions:
      name:
        description:
        - Security association name.
        type: str
        required: true
      tenant_name:
        description:
        - Tenant that owns the security association.
        - Omit this option for non-tenant VXLAN fabrics.
        - Set this only when the tenant is associated with the target fabric.
        type: str
      display_name:
        description:
        - Display name shown in Nexus Dashboard.
        type: str
      description:
        description:
        - Description for the security association.
        type: str
      contract_name:
        description:
        - Existing security contract name. Required when creating an association.
        type: str
      src_security_group_name:
        description:
        - Source security group name. Required when creating an association.
        type: str
      src_vrf_name:
        description:
        - Source VRF name. If both source and destination VRFs are provided, they must match.
        type: str
      dst_security_group_name:
        description:
        - Destination security group name. Required when creating an association.
        type: str
      dst_vrf_name:
        description:
        - Destination VRF name. If both source and destination VRFs are provided, they must match.
        type: str
      attach:
        description:
        - Whether the security association should be attached after reconciliation.
        - Attaching an association can implicitly attach referenced security groups.
        - Detaching an association does not detach referenced security groups.
        type: bool
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
    - Desired state of the security associations.
    - O(state=merged) creates missing associations and updates specified fields.
    - O(state=replaced) replaces the listed associations.
    - O(state=overridden) makes the fabric's security association set match O(config). Use with caution.
    - O(state=deleted) removes the listed associations.
    - O(state=gathered) is intentionally deferred to a future release.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Contract/source/destination changes should be made by creating a new association and deleting the old one.
"""

EXAMPLES = r"""
- name: Create and attach a security association
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
    config_actions:
      save: true
      deploy: true
      type: switch
    state: merged

- name: Replace association metadata
  cisco.nd.nd_manage_security_associations:
    fabric_name: SITE1
    config:
      - name: web_to_app
        contract_name: allow_web
        src_security_group_name: app_web
        src_vrf_name: vrf1
        dst_security_group_name: app_app
        dst_vrf_name: vrf1
        description: Updated description
    state: replaced

- name: Override security associations
  cisco.nd.nd_manage_security_associations:
    fabric_name: SITE1
    config:
      - name: web_to_app
        contract_name: allow_web
        src_security_group_name: app_web
        dst_security_group_name: app_app
    state: overridden

- name: Delete a security association
  cisco.nd.nd_manage_security_associations:
    fabric_name: SITE1
    config:
      - name: web_to_app
    state: deleted
"""

RETURN = r"""
"""

from ansible_collections.cisco.nd.plugins.module_utils.models.security.associations import SecurityAssociationModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.security import SecurityAssociationOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.security_module import run_security_module


def main():
    """Module entry point."""
    run_security_module(
        model_class=SecurityAssociationModel,
        orchestrator_class=SecurityAssociationOrchestrator,
        logger_name="nd.nd_manage_security_associations",
    )


if __name__ == "__main__":
    main()
