#!/usr/bin/python

# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage security contracts on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_security_contracts
version_added: "2.0.0"
short_description: Manage security contracts on Cisco Nexus Dashboard
description:
- Manage Nexus Dashboard security contracts in a fabric.
- Security contracts are reusable rule sets referenced by security associations.
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
    - List of security contracts.
    type: list
    elements: dict
    required: true
    suboptions:
      name:
        description:
        - Security contract name.
        type: str
        required: true
      tenant_name:
        description:
        - Tenant that owns the security contract.
        - Omit this option for non-tenant VXLAN fabrics.
        - Set this only when the tenant is associated with the target fabric.
        type: str
      display_name:
        description:
        - Display name shown in Nexus Dashboard.
        type: str
      description:
        description:
        - Description for the security contract.
        type: str
      direction:
        description:
        - Contract direction.
        type: str
        choices: [ bidirectional, unidirectional, custom ]
      rules:
        description:
        - Rules that make up the contract.
        type: list
        elements: dict
        suboptions:
          rule_direction:
            description:
            - Rule direction.
            type: str
            required: true
            choices: [ bidirectional, unidirectional ]
          action:
            description:
            - Action to apply when the rule matches.
            type: str
            required: true
            choices: [ permit, permitLog, deny, denyLog ]
          protocol_definition_name:
            description:
            - Existing protocol definition referenced by this rule.
            type: str
            required: true
      aci_data:
        description:
        - Optional ACI integration fields.
        type: dict
        suboptions:
          subject_name:
            description:
            - ACI subject name.
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
    - Desired state of the security contracts.
    - O(state=merged) creates missing contracts and updates specified fields.
    - O(state=replaced) replaces the listed contracts.
    - O(state=overridden) makes the fabric's contract set match O(config). Use with caution.
    - O(state=deleted) removes the listed contracts.
    - O(state=gathered) is intentionally deferred to a future release.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Protocol definitions must exist before contract rules can reference them.
"""

EXAMPLES = r"""
- name: Create a security contract
  cisco.nd.nd_manage_security_contracts:
    fabric_name: SITE1
    config:
      - name: allow_web
        direction: bidirectional
        rules:
          - rule_direction: bidirectional
            action: permit
            protocol_definition_name: web_tcp
    config_actions:
      save: true
      deploy: true
      type: switch
    state: merged

- name: Replace a security contract
  cisco.nd.nd_manage_security_contracts:
    fabric_name: SITE1
    config:
      - name: allow_web
        direction: bidirectional
        rules:
          - rule_direction: bidirectional
            action: permitLog
            protocol_definition_name: web_tcp
    state: replaced

- name: Override security contracts
  cisco.nd.nd_manage_security_contracts:
    fabric_name: SITE1
    config:
      - name: allow_web
        direction: bidirectional
    state: overridden

- name: Delete a security contract
  cisco.nd.nd_manage_security_contracts:
    fabric_name: SITE1
    config:
      - name: allow_web
    state: deleted
"""

RETURN = r"""
"""

from ansible_collections.cisco.nd.plugins.module_utils.models.security.contracts import SecurityContractModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.security import SecurityContractOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.security_module import run_security_module


def main():
    """Module entry point."""
    run_security_module(
        model_class=SecurityContractModel,
        orchestrator_class=SecurityContractOrchestrator,
        logger_name="nd.nd_manage_security_contracts",
    )


if __name__ == "__main__":
    main()
