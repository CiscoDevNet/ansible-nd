#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name,logging-fstring-interpolation
__metaclass__ = type
# pylint: enable=invalid-name
__copyright__ = "Copyright (c) 2026 Cisco and/or its affiliates."
__author__ = "L Nikhil Sri Krishna"

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: nd_policy_group
version_added: "1.0.0"
short_description: Manages policy groups on Nexus Dashboard.
description:
- Supports creating, updating, deleting, gathering, and deploying policy groups
  based on templates.
- A policy group applies a single template-based policy to B(multiple switches)
  simultaneously, unlike C(nd_policy) which targets one switch per policy.
- Supports C(merged) state for idempotent policy group management.
- Supports C(deleted) state for removing policy groups from ND and optionally
  from switches.
- Supports C(gathered) state for exporting existing policy groups as
  playbook-compatible config.
- By default (O(use_desc_as_key=true)), the B(description) uniquely identifies
  each policy group.  The internal C(POLICY-GROUP-xxxxx) ID is auto-generated
  by the controller and not intended for direct user reference. The module
  queries the controller by description to resolve the internal ID for
  update and delete operations.
- B(Atomic behavior) — the entire task is treated as a single transaction.
  If any validation check fails (e.g., missing or duplicate descriptions), the
  module aborts B(before) making any changes to the controller.
- When O(use_desc_as_key=true), every O(config[].description) B(must) be
  non-empty and unique within the playbook. The module also fails if duplicate
  descriptions are found on the ND controller itself (created outside of this
  playbook). This ensures unambiguous policy group matching.
- When O(use_desc_as_key=false), the user must provide a C(POLICY-GROUP-xxxxx)
  ID directly in O(config[].name) for update/delete. Template names alone
  cannot uniquely identify a policy group.
- B(Update behavior) — when O(use_desc_as_key=true), in-place updates are
  fully supported. The module compares the desired state against the existing
  policy group matched by description and applies only the necessary changes.
  When O(use_desc_as_key=false) and a template name is given, existing policy
  groups are never updated in-place — a new policy group is always created.
author:
- L Nikhil Sri Krishna (@nisaikri)
options:
  fabric_name:
    description:
    - The name of the fabric containing the target switches.
    type: str
    required: true
    aliases: [ fabric ]
  config:
    description:
    - A list of dictionaries, each defining a policy group.
    - Required for C(merged) and C(deleted) states.
    - Optional for C(gathered) state. When omitted with C(gathered), all policy
      groups in the fabric are exported. When provided, only matching policy
      groups are exported.
    - Each entry specifies a template, description, priority, template inputs,
      and the list of target switches. Unlike C(nd_policy), there is no separate
      switch entry or global/override structure — each config entry is
      self-contained with its own O(config[].switch_ids).
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - This can be one of the following.
        - B(Template Name) — a name identifying the template
          (e.g., C(feature_enable), C(switch_freeform)).
          Used when creating new policy groups.
        - B(Policy Group ID) — a unique ID identifying an existing policy group
          (e.g., C(POLICY-GROUP-143310)). Only needed when O(use_desc_as_key=false)
          for updating or deleting specific policy groups.
        - When O(use_desc_as_key=true) (default), this should be a template name
          and the policy group is identified by O(config[].description) instead.
        - For C(deleted) state with O(use_desc_as_key=true), this is optional if
          O(config[].description) is provided.
        type: str
      description:
        description:
        - Description of the policy group.
        - When O(use_desc_as_key=true) (default), this is used as the B(unique
          identifier) for the policy group and B(must) be non-empty and unique
          across all policy groups in the fabric.
        - The module fails atomically if duplicate descriptions are detected in
          the playbook or on the ND controller.
        type: str
        default: ""
      priority:
        description:
        - Priority of the policy group.
        - Valid range is 1-2000.
        type: int
        default: 500
      template_inputs:
        description:
        - Dictionary of name/value pairs passed to the policy template.
        - The required inputs depend on the template specified in O(config[].name).
        type: dict
        default: {}
      switch_ids:
        description:
        - List of target switch serial numbers, management IPs, or hostnames.
        - The policy group will apply the template-based policy to all switches
          in this list simultaneously.
        - Required for C(merged) state.
        - If management IPs or hostnames are provided, the module resolves them
          to switch serial numbers before calling policy group APIs.
        type: list
        elements: str
  use_desc_as_key:
    description:
    - When set to V(true) (default), the policy group description is used as the
      unique key for matching existing policy groups on the controller.
    - This is the B(recommended mode) for policy groups because the
      C(POLICY-GROUP-xxxxx) ID is auto-generated internally and not user-facing.
    - When V(true), every O(config[].description) must be non-empty (for C(merged)
      and C(deleted) states) and unique within the playbook. The module will
      B(fail immediately) if duplicate descriptions are found in the playbook
      config or on the ND controller.
    - When set to V(false), the user must provide a C(POLICY-GROUP-xxxxx) ID in
      O(config[].name) for update/delete operations. Creating new policy groups
      with a template name is still supported.
    type: bool
    default: true
  deploy:
    description:
    - When set to V(true), policy groups are deployed to devices after
      create/update/delete operations.
    - For C(merged) state, this triggers a pushConfig action via
      C(switchActions/deploy) for the affected switches.
    - For C(deleted) state, this triggers C(markDelete) → C(pushConfig) →
      C(remove) to remove config from switches and then hard-delete the
      policy group records from the controller.
    - For C(deleted) with O(deploy=false), only C(markDelete) is performed on
      the controller. Policy group records remain marked for deletion until a
      subsequent run with O(deploy=true) or manual intervention.
    type: bool
    default: true
  ticket_id:
    description:
    - Change Control Ticket ID to associate with mutation operations.
    - Required when Change Control is enabled on the ND controller.
    type: str
  cluster_name:
    description:
    - Target cluster name in a multi-cluster deployment.
    type: str
  state:
    description:
    - Use C(merged) to create or update policy groups.
    - Use C(deleted) to delete policy groups.
    - For C(deleted) with O(deploy=true), the module performs
      C(markDelete) → C(pushConfig) → C(remove).
    - For C(deleted) with O(deploy=false), only C(markDelete) is performed.
    - Use C(gathered) to export existing policy groups as playbook-compatible
      config. The output under the C(gathered) return key can be used directly
      as O(config) in a subsequent C(merged) task.
    type: str
    choices: [ merged, deleted, gathered ]
    default: merged
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
seealso:
- module: cisco.nd.nd_policy
- module: cisco.nd.nd_rest
notes:
- Policy groups differ from individual policies (C(nd_policy)) in that they
  apply a single template to B(multiple switches) at once.  Individual policies
  target one switch per policy record.
- When O(use_desc_as_key=true) (default), the description uniquely identifies
  the policy group, so in-place updates B(are) supported. If the template name
  changes, the old policy group is deleted and a new one is created.
- When O(use_desc_as_key=false) and O(config[].name) is a template name,
  existing policy groups are B(never) updated in-place. The module always
  creates a new policy group. To update a specific policy group, provide its
  ID (C(POLICY-GROUP-xxxxx)) in O(config[].name).
- The module uses the C(GET /policyGroups) endpoint with Lucene filtering to
  match existing policy groups by description. Post-filtering ensures exact
  description matching (Lucene does tokenized matching by default).
"""

EXAMPLES = r"""
# =============================================================================
# CREATE — Basic policy group applied to multiple switches
# =============================================================================
#
# Creates a policy group using the 'feature_enable' template to enable LACP
# on two switches.  The description "Enable LACP" uniquely identifies this
# policy group (use_desc_as_key defaults to true).

- name: Create a policy group to enable LACP on multiple switches
  cisco.nd.nd_policy_group:
    fabric_name: "{{ fabric_name }}"
    state: merged
    deploy: true
    config:
      - name: feature_enable
        description: "Enable LACP"
        priority: 500
        template_inputs:
          featureName: lacp
        switch_ids:
          - "{{ switch1 }}"
          - "{{ switch2 }}"
          - "{{ switch3 }}"

# =============================================================================
# CREATE — Multiple policy groups in a single task
# =============================================================================
#
# Each config entry is a separate policy group with its own switch list.
# Descriptions must be unique across all entries.

- name: Create multiple policy groups
  cisco.nd.nd_policy_group:
    fabric_name: "{{ fabric_name }}"
    state: merged
    deploy: true
    config:
      - name: feature_enable
        description: "Enable LACP on spine switches"
        template_inputs:
          featureName: lacp
        switch_ids:
          - "{{ spine1 }}"
          - "{{ spine2 }}"

      - name: feature_enable
        description: "Enable LLDP on leaf switches"
        template_inputs:
          featureName: lldp
        switch_ids:
          - "{{ leaf1 }}"
          - "{{ leaf2 }}"
          - "{{ leaf3 }}"

      - name: switch_freeform
        description: "NTP configuration for all switches"
        priority: 100
        template_inputs:
          CONF: |
            ntp server 10.1.1.1
            ntp server 10.1.1.2
        switch_ids:
          - "{{ spine1 }}"
          - "{{ spine2 }}"
          - "{{ leaf1 }}"
          - "{{ leaf2 }}"
          - "{{ leaf3 }}"

# =============================================================================
# UPDATE — Modify an existing policy group (use_desc_as_key=true)
# =============================================================================
#
# The description "Enable LACP on spine switches" identifies the existing
# policy group.  The module detects the diff (priority change + added switch)
# and performs a PUT with the resolved POLICY-GROUP-xxxxx ID.

- name: Update policy group — change priority and add a switch
  cisco.nd.nd_policy_group:
    fabric_name: "{{ fabric_name }}"
    state: merged
    deploy: true
    config:
      - name: feature_enable
        description: "Enable LACP on spine switches"
        priority: 100
        template_inputs:
          featureName: lacp
        switch_ids:
          - "{{ spine1 }}"
          - "{{ spine2 }}"
          - "{{ spine3 }}"

# =============================================================================
# UPDATE — Modify switch list only
# =============================================================================
#
# Add or remove switches from an existing policy group by providing the
# updated switch_ids list.  The description matches the existing group.

- name: Remove a switch from the policy group
  cisco.nd.nd_policy_group:
    fabric_name: "{{ fabric_name }}"
    state: merged
    config:
      - name: feature_enable
        description: "Enable LACP on spine switches"
        template_inputs:
          featureName: lacp
        switch_ids:
          - "{{ spine1 }}"
          - "{{ spine2 }}"

# =============================================================================
# UPDATE — Using policy group ID directly (use_desc_as_key=false)
# =============================================================================
#
# When use_desc_as_key is false, you can reference the auto-generated
# POLICY-GROUP-xxxxx ID directly.  This is useful when you have the ID
# from a previous gathered output.

- name: Update policy group using its ID
  cisco.nd.nd_policy_group:
    fabric_name: "{{ fabric_name }}"
    use_desc_as_key: false
    state: merged
    config:
      - name: POLICY-GROUP-143310
        description: "Updated description"
        priority: 200
        template_inputs:
          featureName: lacp
        switch_ids:
          - "{{ spine1 }}"
          - "{{ spine2 }}"

# =============================================================================
# DELETE — Delete policy groups by description (use_desc_as_key=true)
# =============================================================================
#
# The module resolves the description to the internal POLICY-GROUP-xxxxx ID
# and performs markDelete → pushConfig → remove.

- name: Delete policy groups by description
  cisco.nd.nd_policy_group:
    fabric_name: "{{ fabric_name }}"
    state: deleted
    deploy: true
    config:
      - name: feature_enable
        description: "Enable LACP on spine switches"

      - name: feature_enable
        description: "Enable LLDP on leaf switches"

# =============================================================================
# DELETE — Delete using policy group ID (use_desc_as_key=false)
# =============================================================================

- name: Delete policy groups using their IDs
  cisco.nd.nd_policy_group:
    fabric_name: "{{ fabric_name }}"
    use_desc_as_key: false
    state: deleted
    config:
      - name: POLICY-GROUP-143310
      - name: POLICY-GROUP-143320

# =============================================================================
# DELETE — Mark for deletion only (no deploy)
# =============================================================================
#
# Only markDelete is performed.  Policy groups remain marked for deletion
# until a subsequent run with deploy=true.

- name: Mark policy groups for deletion without deploying
  cisco.nd.nd_policy_group:
    fabric_name: "{{ fabric_name }}"
    state: deleted
    deploy: false
    config:
      - name: switch_freeform
        description: "NTP configuration for all switches"

# =============================================================================
# GATHERED — Export all policy groups in the fabric
# =============================================================================

- name: Gather all policy groups in the fabric
  cisco.nd.nd_policy_group:
    fabric_name: "{{ fabric_name }}"
    state: gathered
  register: all_policy_groups

# =============================================================================
# GATHERED — Export specific policy groups by description
# =============================================================================

- name: Gather specific policy groups by description
  cisco.nd.nd_policy_group:
    fabric_name: "{{ fabric_name }}"
    state: gathered
    config:
      - description: "Enable LACP on spine switches"
      - description: "NTP configuration for all switches"
  register: specific_groups

# =============================================================================
# GATHERED → MERGED — Re-create gathered policy groups on another fabric
# =============================================================================

- name: Re-create policy groups on target fabric from gathered output
  cisco.nd.nd_policy_group:
    fabric_name: "{{ target_fabric }}"
    state: merged
    config: "{{ all_policy_groups.gathered }}"

# =============================================================================
# GATHERED → DELETED — Delete the exact gathered policy groups
# =============================================================================

- name: Delete gathered policy groups
  cisco.nd.nd_policy_group:
    fabric_name: "{{ fabric_name }}"
    state: deleted
    config: "{{ all_policy_groups.gathered }}"

# =============================================================================
# CREATE with Change Control ticket
# =============================================================================

- name: Create policy group with change control ticket
  cisco.nd.nd_policy_group:
    fabric_name: "{{ fabric_name }}"
    state: merged
    deploy: true
    ticket_id: "CHG-20260415-001"
    config:
      - name: feature_enable
        description: "Enable BFD on all switches"
        template_inputs:
          featureName: bfd
        switch_ids:
          - "{{ spine1 }}"
          - "{{ spine2 }}"
          - "{{ leaf1 }}"
          - "{{ leaf2 }}"

# =============================================================================
# CREATE with freeform config on all fabric switches
# =============================================================================

- name: Push freeform configuration to all switches via policy group
  cisco.nd.nd_policy_group:
    fabric_name: "{{ fabric_name }}"
    state: merged
    config:
      - name: switch_freeform
        description: "RADIUS server configuration"
        priority: 100
        template_inputs:
          CONF: |
            radius-server host 10.1.1.2 key 7 "ljw3976!" authentication accounting
        switch_ids:
          - "{{ switch1 }}"
          - "{{ switch2 }}"
          - "{{ switch3 }}"
          - "{{ switch4 }}"
"""

RETURN = r"""
# TODO: Add return documentation
"""

# =============================================================================
# Module implementation placeholder
# =============================================================================

# import logging

# from ansible.module_utils.basic import AnsibleModule
# from ansible_collections.cisco.nd.plugins.module_utils.common.log import Log
# from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
#     NDModule,
#     NDModuleError,
#     nd_argument_spec,
# )
# from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
# from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.config_models import (
#     PlaybookPolicyGroupConfig,
# )


# def main():
#     """Main entry point for the nd_policy_group module."""
#
#     argument_spec = nd_argument_spec()
#     argument_spec.update(PlaybookPolicyGroupConfig.get_argument_spec())
#
#     module = AnsibleModule(
#         argument_spec=argument_spec,
#         supports_check_mode=True,
#     )
#
#     # TODO: Implement NDPolicyGroupModule resource class and wire up here
#     pass
#
#
# if __name__ == "__main__":
#     main()
