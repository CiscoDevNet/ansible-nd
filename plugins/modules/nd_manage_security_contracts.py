#!/usr/bin/python

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage security contracts on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: nd_manage_security_contracts
version_added: "2.0.0"
short_description: Manage security contracts on Cisco Nexus Dashboard
description:
- Manage security contracts through the Nexus Dashboard (ND) Manage Security and Segmentation API.
- ND 4.2.1 and ND 4.3.1 are supported.
- Contracts contain rules that reference existing security protocol definitions and are referenced by security associations.
author:
- Mike Wiebe (@mikewiebe)
options:
  fabric_name:
    description:
    - Name of the standalone fabric or parent fabric group that owns the contracts.
    type: str
    required: true
  cluster_name:
    description:
    - Name of the ND cluster that manages the fabric in a multi-cluster deployment.
    - When set, the value is sent as the C(clusterName) query parameter on fabric, resource, and action requests.
    type: str
  config:
    description:
    - List of security contracts.
    - Required for write states. Omit for O(state=gathered) to return all contracts.
    type: list
    elements: dict
    required: false
    suboptions:
      name:
        description:
        - Security contract name. Names are case insensitive.
        - A name without O(config.tenant_name) can contain at most 63 characters.
        - The maximum qualified-name length is 92 characters on ND 4.2.1 and 102 characters on ND 4.3.1.
        type: str
        required: true
      tenant_name:
        description:
        - Tenant that owns the security contract.
        - The module sends tenant-scoped names as C(tenant_name~name) and returns gathered names in separate O(config.tenant_name) and O(config.name) fields.
        - Omit this option for non-tenant VXLAN fabrics.
        type: str
      display_name:
        description:
        - Display name shown in ND. The maximum length is 64 characters.
        type: str
      description:
        description:
        - Description for the security contract. The maximum length is 128 characters.
        - ND 4.3.1 does not accept carriage-return or line-feed characters.
        type: str
      direction:
        description:
        - Contract direction.
        - For a new contract or O(state=replaced) and O(state=overridden),
          omission selects C(custom) for a default-tenant contract on ND 4.2.1.
          On ND 4.3.1, or when the controller version is unavailable, omission
          selects C(bidirectional). Tenant-scoped omission selects
          C(bidirectional) on both releases.
        - With O(state=merged), omission preserves the direction of an existing contract.
        - On ND 4.2.1, a contract without O(config.tenant_name) accepts only C(custom).
        - On ND 4.3.1, a contract without O(config.tenant_name) accepts C(bidirectional), C(unidirectional), or C(custom).
        - Tenant-scoped contracts accept C(bidirectional) or C(unidirectional) on both releases and do not accept C(custom).
        - An existing controller-returned direction can be gathered and replayed unchanged, including a legacy direction and tenant combination.
        type: str
        choices: [ bidirectional, unidirectional, custom ]
      rules:
        description:
        - Unique rules that make up the contract.
        - Referenced protocol definitions must already exist in the same fabric and tenant scope.
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
            - Existing protocol definition referenced by this rule. This reference is case insensitive.
            - Use C(tenant_name~protocol_definition_name) for a non-default tenant.
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
    - Controls fabric save and deploy actions after a resource change.
    - Omit this option when O(state=gathered). Read-only runs never save or deploy.
    type: dict
    suboptions:
      save:
        description:
        - Save and recalculate the fabric configuration after a resource change.
        type: bool
        default: false
      deploy:
        description:
        - Deploy pending fabric configuration after a resource change.
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
    - Desired state of the security contracts.
    - O(state=merged) creates missing contracts and updates specified fields.
    - O(state=replaced) replaces the listed contracts.
    - O(state=overridden) makes the fabric's contract set match O(config). Use with caution.
    - O(state=deleted) removes the listed contracts.
    - O(state=gathered) returns replayable configuration without changing, saving, or deploying anything.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted, gathered ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Group Based Policy must already be enabled and ready on the target fabric. This module does not enable the feature or reload switches.
- Security resources are supported only on iBGP VXLAN fabrics. PVLAN, change-control, and eBGP-underlay VXLAN fabrics are unsupported.
- Create protocol definitions before contracts, then create groups and associations. Delete in reverse dependency order.
- A contract referenced by an association cannot be removed until the association is deleted.
- CSV import and export workflows are outside this module's scope.
"""

EXAMPLES = r"""
- name: Create a security contract without saving or deploying
  cisco.nd.nd_manage_security_contracts:
    fabric_name: SITE1
    config:
      - name: allow_web
        direction: custom
        rules:
          - rule_direction: bidirectional
            action: permit
            protocol_definition_name: web_tcp
    state: merged

- name: Replace a contract and save and deploy all pending fabric changes
  cisco.nd.nd_manage_security_contracts:
    fabric_name: SITE1
    cluster_name: cluster-1
    config:
      - name: allow_web
        tenant_name: TenantA
        direction: bidirectional
        rules:
          - rule_direction: bidirectional
            action: permitLog
            protocol_definition_name: TenantA~web_tcp
    config_actions:
      save: true
      deploy: true
      type: global
    state: replaced

- name: Gather contracts as replayable module configuration
  cisco.nd.nd_manage_security_contracts:
    fabric_name: SITE1
    state: gathered
  register: security_contracts

- name: Authoritatively retain only the listed contracts
  cisco.nd.nd_manage_security_contracts:
    fabric_name: SITE1
    config:
      - name: allow_web
        # With tenant_name omitted, direction defaults to custom on ND 4.2.1
        # and bidirectional on ND 4.3.1.
        rules:
          - rule_direction: bidirectional
            action: permit
            protocol_definition_name: web_tcp
    state: overridden

- name: Delete a security contract after its associations have been deleted
  cisco.nd.nd_manage_security_contracts:
    fabric_name: SITE1
    config:
      - name: allow_web
    state: deleted
"""

RETURN = r"""
changed:
  description: Whether the module changed, or in check mode would change, security contracts.
  returned: always
  type: bool
  sample: true
output_level:
  description: Output verbosity selected by O(output_level).
  returned: always
  type: str
  sample: normal
before:
  description: Contracts before reconciliation. Empty for O(state=gathered).
  returned: always
  type: list
  elements: dict
after:
  description: Contracts after reconciliation. Empty for O(state=gathered).
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
  - Contracts read from ND, pruned to fields accepted by O(config).
  - An empty list is returned when no contracts exist.
  returned: when O(state=gathered)
  type: list
  elements: dict
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

from ansible_collections.cisco.nd.plugins.module_utils.models.security.contracts import (
    SecurityContractModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.security import (
    SecurityContractOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.security_module import (
    run_security_module,
)


def main():
    """Module entry point."""
    run_security_module(
        model_class=SecurityContractModel,
        orchestrator_class=SecurityContractOrchestrator,
        logger_name="nd.nd_manage_security_contracts",
    )


if __name__ == "__main__":
    main()
