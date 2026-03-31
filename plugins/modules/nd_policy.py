#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name
__copyright__ = "Copyright (c) 2026 Cisco and/or its affiliates."
__author__ = "L Nikhil Sri Krishna"

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_policy
version_added: "1.0.0"
short_description: Manages policies on Nexus Dashboard Fabric Controller (NDFC).
description:
- Supports creating, updating, deleting, querying, gathering, and deploying policies based on templates.
- Supports C(merged) state for idempotent policy management.
- Supports C(deleted) state for removing policies from NDFC and optionally from switches.
- Supports C(query) state for retrieving existing policy information.
- Supports C(gathered) state for exporting existing policies as playbook-compatible config.
  The gathered output can be copy-pasted directly into a playbook for use with C(merged) state.
- When O(use_desc_as_key=true), policies are identified by their description instead of policy ID.
- B(Atomic behavior) — the entire task is treated as a single transaction.
  If any validation check fails (e.g., missing or duplicate descriptions), the module
  aborts B(before) making any changes to the controller.
- When O(use_desc_as_key=true), every O(config[].description) B(must) be non-empty and
  unique per switch within the playbook. The module also fails if duplicate descriptions
  are found on the NDFC controller itself (created outside of this playbook). This ensures
  unambiguous policy matching. To manage policies with non-unique descriptions, use
  O(use_desc_as_key=false) and reference policies by policy ID.
- Policies and switches are specified separately in the O(config) list. Global policies
  apply to all switches listed in the C(switch) entry. Per-switch policy overrides can
  be specified using the C(policies) suboption inside each switch entry (only when
  O(use_desc_as_key=false)). Per-switch policies override global policies with the
  same template name for that switch.
- B(Update behavior) — when O(use_desc_as_key=false) and a template name is given,
  existing policies are never updated in-place. A new policy is always created. To update
  a specific policy, provide its policy ID (C(POLICY-xxxxx)) as the O(config[].name).
  When O(use_desc_as_key=true), the description uniquely identifies the policy, so
  in-place updates are supported.
author:
- L Nikhil Sri Krishna
options:
  fabric_name:
    description:
    - The name of the fabric containing the target switches.
    type: str
    required: true
    aliases: [ fabric ]
  config:
    description:
    - A list of dictionaries containing policy and switch information.
    - Required for C(merged), C(deleted), and C(query) states.
    - Optional for C(gathered) state. When omitted with C(gathered), all policies on all
      fabric switches are exported. When provided, only matching policies are exported.
    - Policy entries define the template, description, priority, and template inputs.
    - A separate C(switch) entry lists the target switches and optional per-switch policy overrides.
    - All global policies (entries without C(switch) key) are applied to every switch listed
      in the C(switch) entry. Per-switch policies (specified under C(switch[].policies))
      override global policies with the same template name for that particular switch
      (only when O(use_desc_as_key=false); when O(use_desc_as_key=true) per-switch
      policies are simply merged with global policies).
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - This can be one of the following.
        - B(Template Name) — a name identifying the template (e.g., C(switch_freeform), C(feature_enable)).
          Note that a template name can be used by multiple policies and hence does not identify a policy uniquely.
        - B(Policy ID) — a unique ID identifying a policy (e.g., C(POLICY-121110)).
          Policy ID B(must) be used for modifying existing policies when O(use_desc_as_key=false),
          since template names cannot uniquely identify a policy.
        - For C(query) and C(deleted) states, this is optional. When omitted, all policies
          on the specified switch are returned/deleted.
        type: str
      description:
        description:
        - Description of the policy.
        - When O(use_desc_as_key=true), this is used as the unique identifier for the policy
          and B(must) be non-empty and unique per switch. The module fails atomically if
          duplicate descriptions are detected in the playbook or on the NDFC controller.
        type: str
        default: ""
      priority:
        description:
        - Priority of the policy.
        - Valid range is 1-2000.
        type: int
        default: 500
      create_additional_policy:
        description:
        - A flag indicating if a policy is to be created even if an identical policy already exists.
        - When set to V(true), a new duplicate policy is created regardless of whether a matching one exists.
        - When set to V(false), duplicate creation is skipped if an identical policy already exists.
        - Only relevant when O(use_desc_as_key=false) and O(config[].name) is a template name.
        type: bool
        default: true
      template_inputs:
        description:
        - Dictionary of name/value pairs passed to the policy template.
        - The required inputs depend on the template specified in O(config[].name).
        type: dict
        default: {}
      switch:
        description:
        - A list of switches and optional per-switch policy overrides.
        - All switches in this list will be deployed with the global policies defined
          at the top level of O(config). Per-switch policy overrides can be specified
          using the C(policies) suboption.
        type: list
        elements: dict
        suboptions:
          serial_number:
            description:
            - Serial number of the target switch (e.g., C(FDO25031SY4)).
            - The alias C(ip) is kept for backward compatibility and may be a
              switch management IP or hostname. The module resolves that value
              to the switch serial number before calling policy APIs.
            type: str
            required: true
            aliases: [ ip ]
          policies:
            description:
            - A list of policies specific to this switch that override global policies
              with the same template name (when O(use_desc_as_key=false)).
            - When O(use_desc_as_key=true), per-switch policies are simply merged with
              global policies rather than overriding by template name.
            type: list
            elements: dict
            default: []
            suboptions:
              name:
                description:
                - Template name or policy ID, same semantics as the top-level O(config[].name).
                type: str
                required: true
              description:
                description:
                - Description of the policy.
                type: str
                default: ""
              priority:
                description:
                - Priority of the policy.
                type: int
                default: 500
              create_additional_policy:
                description:
                - A flag indicating if a policy is to be created even if an identical policy already exists.
                type: bool
                default: true
              template_inputs:
                description:
                - Dictionary of name/value pairs passed to the policy template.
                type: dict
                default: {}
  use_desc_as_key:
    description:
    - When set to V(true), the policy description is used as the unique key for matching.
    - When set to V(false), the template name (or policy ID if name starts with C(POLICY-)) is used.
    - When V(true), every O(config[].description) must be non-empty (for C(merged) and C(deleted) states)
      and unique per switch within the playbook. The module will B(fail immediately) if duplicate
      C(description + switch) combinations are found in the playbook config or on the NDFC controller.
    - This atomic-fail behavior ensures no partial changes are made when descriptions are ambiguous.
    type: bool
    default: false
  deploy:
    description:
    - When set to V(true), policies are deployed to devices after create/update/delete operations.
    - For C(merged) state, this triggers a pushConfig action for the affected policy IDs.
    - For C(deleted) state, this triggers C(markDelete) → C(pushConfig) → C(remove) to remove
      config from switches and then hard-delete the policy records from the controller.
    - For C(deleted) with O(deploy=false), only C(markDelete) is performed on the controller.
      Policy records remain marked for deletion (with negative priority) until a subsequent
      run with O(deploy=true) or manual intervention.
    - B(Exception) — C(switch_freeform) policies are always deleted via a direct C(DELETE)
      API call regardless of the O(deploy) setting, because the C(markDelete) operation
      is not supported for this template.
    type: bool
    default: true
  ticket_id:
    description:
    - Change Control Ticket ID to associate with mutation operations.
    - Required when Change Control is enabled on the NDFC controller.
    type: str
  cluster_name:
    description:
    - Target cluster name in a multi-cluster deployment.
    type: str
  state:
    description:
    - Use C(merged) to create or update policies.
    - Use C(deleted) to delete policies.
    - For C(deleted) with O(deploy=true), the module performs
      C(markDelete) → C(pushConfig) → C(remove).
    - For C(deleted) with O(deploy=false), only C(markDelete) is performed on the controller.
      Policy records remain marked for deletion (with negative priority) until a subsequent
      run with O(deploy=true) or manual intervention.
    - B(Exception) — C(switch_freeform) policies skip the C(markDelete) flow entirely
      and are removed via a direct C(DELETE) API call regardless of the O(deploy) setting.
    - Use C(query) to retrieve existing policies without making changes.
    - Use C(gathered) to export existing policies as playbook-compatible config.
      When O(config) is provided, only matching policies are exported.
      When O(config) is omitted, all policies on all fabric switches are exported.
      The output under the C(gathered) return key can be used directly as O(config)
      in a subsequent C(merged) task.
    type: str
    choices: [ merged, deleted, query, gathered ]
    default: merged
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
seealso:
- name: Cisco NDFC Policy Management
  description: Understanding switch policy management on NDFC 4.x.
notes:
- When O(use_desc_as_key=false) and O(config[].name) is a template name (not a policy ID),
  existing policies are B(never) updated in-place. The module always creates a new policy.
  This is because multiple policies can share the same template name, making it ambiguous
  which policy to update. To update a specific policy, use its policy ID (C(POLICY-xxxxx)).
- When O(use_desc_as_key=true), the description uniquely identifies the policy per switch,
  so in-place updates B(are) supported. If the template name changes, the old policy is
  deleted and a new one is created.
- C(switch_freeform) policies do not support the C(markDelete) API. They are always
  removed via a direct C(DELETE) API call, regardless of the O(deploy) setting.
"""

EXAMPLES = r"""
# NOTE: In the following create task, policies template_101, template_102, and template_103
#       are deployed on switch2, whereas policies template_104 and template_105 are the only
#       policies installed on switch1 (per-switch override).

- name: Create different policies with per-switch overrides
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    state: merged
    deploy: true
    config:
      - name: template_101
        create_additional_policy: false
        priority: 101

      - name: template_102
        create_additional_policy: false
        description: "102 - No priority given"

      - name: template_103
        create_additional_policy: false
        description: "Both description and priority given"
        priority: 500

      - switch:
          - serial_number: "{{ switch1 }}"
            policies:
              - name: template_104
                create_additional_policy: false
              - name: template_105
                create_additional_policy: false
          - serial_number: "{{ switch2 }}"

# CREATE POLICY (including template inputs)

- name: Create policy including required template inputs
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    config:
      - name: switch_freeform
        create_additional_policy: false
        priority: 101
        template_inputs:
          CONF: |
            feature lacp

      - switch:
          - serial_number: "{{ switch1 }}"

# MODIFY POLICY (using policy ID)

# NOTE: Since there can be multiple policies with the same template name, policy-id MUST be used
#       to modify a particular policy when use_desc_as_key is false.

- name: Modify policies using policy IDs
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    state: merged
    deploy: true
    config:
      - name: POLICY-101101
        create_additional_policy: false
        priority: 101

      - name: POLICY-102102
        create_additional_policy: false
        description: "Updated description"

      - switch:
          - serial_number: "{{ switch1 }}"

# UPDATE using description as key

- name: Use description as key to update
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    use_desc_as_key: true
    config:
      - name: feature_enable
        description: "Enable LACP"
        priority: 100
        template_inputs:
          featureName: lacp

      - switch:
          - serial_number: "{{ switch1 }}"
    state: merged

# Use description as key with per-switch policies

- name: Create policies with description as key
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    use_desc_as_key: true
    config:
      - name: switch_freeform
        create_additional_policy: false
        description: "policy_radius"
        template_inputs:
          CONF: |
            radius-server host 10.1.1.2 key 7 "ljw3976!" authentication accounting
      - switch:
          - serial_number: "{{ switch1 }}"
            policies:
              - name: switch_freeform
                create_additional_policy: false
                priority: 101
                description: "feature bfd"
                template_inputs:
                  CONF: |
                    feature bfd
              - name: switch_freeform
                create_additional_policy: false
                priority: 102
                description: "feature bash-shell"
                template_inputs:
                  CONF: |
                    feature bash-shell
          - serial_number: "{{ switch2 }}"
          - serial_number: "{{ switch3 }}"

# DELETE POLICY

- name: Delete policies using template name
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    state: deleted
    config:
      - name: template_101
      - name: template_102
      - name: template_103
      - switch:
          - serial_number: "{{ switch1 }}"
          - serial_number: "{{ switch2 }}"

- name: Delete policies using policy-id
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    state: deleted
    config:
      - name: POLICY-101101
      - name: POLICY-102102
      - switch:
          - serial_number: "{{ switch1 }}"

- name: Delete all policies on switches
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    state: deleted
    config:
      - switch:
          - serial_number: "{{ switch1 }}"
          - serial_number: "{{ switch2 }}"

- name: Delete policies without deploying (mark for deletion only)
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    state: deleted
    deploy: false
    config:
      - name: template_101
      - switch:
          - serial_number: "{{ switch1 }}"

# NOTE: switch_freeform policies are always directly deleted
#       regardless of the deploy setting.

- name: Delete switch_freeform policies (direct DELETE)
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    state: deleted
    config:
      - name: switch_freeform
      - switch:
          - serial_number: "{{ switch1 }}"

- name: Delete policies using description as key
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    use_desc_as_key: true
    state: deleted
    config:
      - name: switch_freeform
        description: "Enable LACP"
      - switch:
          - serial_number: "{{ switch1 }}"

# QUERY

- name: Query all policies from specified switches
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    state: query
    config:
      - switch:
          - serial_number: "{{ switch1 }}"
          - serial_number: "{{ switch2 }}"

- name: Query policies matching template names
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    state: query
    config:
      - name: template_101
      - name: template_102
      - switch:
          - serial_number: "{{ switch1 }}"

- name: Query policies using policy-ids
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    state: query
    config:
      - name: POLICY-101101
      - name: POLICY-102102
      - switch:
          - serial_number: "{{ switch1 }}"

- name: Gather all policies on all fabric switches (no config needed)
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    state: gathered
  register: all_policies

- name: Gather only switch_freeform policies on a specific switch
  cisco.nd.nd_policy:
    fabric_name: "{{ fabric_name }}"
    state: gathered
    config:
      - name: switch_freeform
      - switch:
          - serial_number: "{{ switch1 }}"
  register: freeform_policies

- name: Use gathered output to re-create policies on another fabric
  cisco.nd.nd_policy:
    fabric_name: "{{ target_fabric }}"
    state: merged
    config: "{{ all_policies.gathered }}"
"""

RETURN = r"""
changed:
  description: Whether any changes were made.
  returned: always
  type: bool
  sample: false
failed:
  description: Whether the operation failed.
  returned: always
  type: bool
  sample: false
before:
  description:
  - List of policy snapshots B(before) the module made any changes.
  - For C(merged) state, contains the existing policy state prior to create/update.
  - For C(deleted) state, contains the policies that were deleted.
  - For C(query) state, this is an empty list.
  returned: always
  type: list
  elements: dict
after:
  description:
  - List of policy snapshots B(after) the module completed.
  - For C(merged) state, contains the new/updated policy state.
  - For C(deleted) state, this is an empty list (policies were removed).
  - For C(query) state, contains the queried policies.
  returned: always
  type: list
  elements: dict
gathered:
  description:
  - List of policies exported as playbook-compatible config dicts.
  - Each entry contains C(name) (template name), C(policy_id), C(switch),
    C(description), C(priority), C(template_inputs), and C(create_additional_policy).
  - Internal template input keys (e.g., C(FABRIC_NAME), C(POLICY_ID)) are
    stripped so the output can be used directly as O(config) in a C(merged) task.
  - Only returned when O(state=gathered).
  returned: when state is gathered
  type: list
  elements: dict
  sample:
    - name: switch_freeform
      policy_id: POLICY-28240
      switch:
        - serial_number: FDO29080NBU
      description: my freeform policy
      priority: 500
      template_inputs:
        CONF: "interface loopback100\n  description gathered"
      create_additional_policy: false
proposed:
  description:
  - List of proposed policy changes derived from the playbook config.
  - Only returned when O(output_level) is set to V(info) or V(debug).
  returned: when output_level is info or debug
  type: list
  elements: dict
diff:
  description: List of differences between desired and existing state.
  returned: always
  type: list
  elements: dict
response:
  description: List of controller responses.
  returned: always
  type: list
  elements: dict
result:
  description: List of operation results.
  returned: always
  type: list
  elements: dict
metadata:
  description: List of operation metadata.
  returned: always
  type: list
  elements: dict
"""

import logging

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.log import Log
from ansible_collections.cisco.nd.plugins.module_utils.nd_policy_resources import NDPolicyModule
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule,
    NDModuleError,
    nd_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.config_models import PlaybookPolicyConfig


# =============================================================================
# Main
# =============================================================================
def main():
    """Main entry point for the nd_policy module."""

    argument_spec = nd_argument_spec()
    argument_spec.update(PlaybookPolicyConfig.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Initialize logging
    try:
        log_config = Log()
        log_config.commit()
        log = logging.getLogger("nd.nd_policy")
    except ValueError as error:
        module.fail_json(msg=str(error))

    # Initialize NDModule (REST client)
    try:
        nd = NDModule(module)
    except Exception as error:
        module.fail_json(msg=f"Failed to initialize NDModule: {str(error)}")

    # Initialize Results
    state = module.params.get("state")
    output_level = module.params.get("output_level")
    results = Results()
    results.state = state
    results.check_mode = module.check_mode
    results.action = f"policy_{state}"

    try:
        log.info(f"Starting nd_policy module: state={state}")

        # Create NDPolicyModule — all business logic lives here
        policy_module = NDPolicyModule(
            nd=nd,
            results=results,
            logger=log,
        )

        # manage_state handles the full pipeline:
        # pydantic validation → resolve switches → translate → validate → dispatch
        policy_module.manage_state()

        # Exit with results
        log.info(f"State management completed successfully. Changed: {results.changed}")
        policy_module.exit_json()

    except NDModuleError as error:
        log.error(f"NDModule error: {error.msg}")

        try:
            results.response_current = nd.rest_send.response_current
            results.result_current = nd.rest_send.result_current
        except (AttributeError, ValueError):
            results.response_current = {
                "RETURN_CODE": error.status if error.status else -1,
                "MESSAGE": error.msg,
                "DATA": error.response_payload if error.response_payload else {},
            }
            results.result_current = {"success": False, "found": False}

        results.diff_current = {}
        results.register_api_call()
        results.build_final_result()

        if output_level == "debug":
            results.final_result["error_details"] = error.to_dict()

        log.error(f"Module failed: {results.final_result}")
        module.fail_json(msg=error.msg, **results.final_result)

    except Exception as error:
        import traceback
        tb_str = traceback.format_exc()

        log.error(f"Unexpected error during module execution: {str(error)}")
        log.error(f"Error type: {type(error).__name__}")

        try:
            results.response_current = {
                "RETURN_CODE": -1,
                "MESSAGE": f"Unexpected error: {str(error)}",
                "DATA": {},
            }
            results.result_current = {"success": False, "found": False}
            results.diff_current = {}
            results.register_api_call()
            results.build_final_result()

            fail_kwargs = results.final_result
        except Exception:
            fail_kwargs = {}

        if output_level == "debug":
            fail_kwargs["traceback"] = tb_str

        module.fail_json(msg=f"{type(error).__name__}: {str(error)}", **fail_kwargs)


if __name__ == "__main__":
    main()
