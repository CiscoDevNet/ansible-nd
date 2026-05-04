# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
---
module: nd_policy_group
short_description: Manage policy groups on Cisco Nexus Dashboard
version_added: "0.7.0"
description:
- Manage policy groups on Cisco Nexus Dashboard Fabric Controller (NDFC).
- Policy groups apply a template to multiple switches simultaneously.
- Each policy group is uniquely identified by the combination of
  O(config.description) and O(config.name) (template name).
author:
- L Nikhil Sri Krishna (@nisaikri)
options:
  fabric_name:
    description:
    - Name of the fabric where the policy groups are managed.
    type: str
    required: true
    aliases: [ fabric ]
  deploy:
    description:
    - Whether to deploy changes after create/update/delete operations.
    - When C(true), pushConfig is called after create/update, and DELETE verb
      is issued after markDelete for deletions.
    - When C(false), changes are staged but not deployed.
    - "B(Deploy behavior for switch_ids changes:)"
    - When switches are B(added) to a policy group, C(pushConfig) is called
      with the policy group ID. The controller deploys the policy configuration
      to all current members, including newly added switches.
    - When switches are B(removed) from a policy group, C(pushConfig) alone is
      not sufficient — the controller does not push the negative (removal)
      configuration to the removed switches. To handle this, a switch-level
      deploy (C(POST /switchActions/deploy)) is issued targeting only the
      removed switch serial numbers. This pushes the negative configuration
      and cleanly removes the policy from those switches.
    - When switches are B(added and removed in the same task), both mechanisms
      are used — C(pushConfig) deploys to all current members (handling additions),
      and C(switchActions/deploy) targets the removed switches (handling removals).
    type: bool
    default: true
  config:
    description:
    - List of policy group configurations.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - "This can be one of the following:"
        - "a) Template Name - A unique name identifying the template (e.g., C(feature_enable), C(switch_freeform))."
        - "   A template name can be used by multiple policy groups and hence does not identify a policy group uniquely."
        - "b) Policy Group ID - A unique ID identifying a policy group (e.g., C(POLICY-GROUP-123456))."
        - "   Policy Group ID MUST be used for modifying specific policies since template names cannot uniquely identify"
        - "   a policy group without O(config.description)."
        - "B(Policy Group ID resolution:)"
        - When a C(POLICY-GROUP-*) ID is provided, the module queries the controller to resolve it
          to its corresponding C(template_name) and C(description). The resolved values are then used
          internally as the composite key for state machine operations (create/update/delete).
        - For O(state=merged), if the ID is not found on the controller, the module fails with an error.
          Policy group IDs are server-generated and cannot be used to create new policy groups.
          Use a template name in O(config.name) together with O(config.description) to create new policy groups.
        - For O(state=deleted), if the ID is not found, it is silently skipped (assumed already deleted).
        - For O(state=gathered), the ID is used directly to query the specific policy group by ID.
        - Required for O(state=merged) and O(state=deleted). Optional for O(state=gathered)
          where entries can filter by O(config.description) alone.
        type: str
      description:
        description:
        - Description of the policy group.
        - Used together with O(config.name) as the unique identifier when name is a template name.
        - Required when O(state=merged) and name is a template name (not a policy group ID).
        - "When O(state=deleted):"
        - "  If provided with a template name, deletes the specific policy group matching (description, template_name)."
        - "  If omitted with a template name, deletes ALL policy groups using that template."
        - "  Not required when name is a policy group ID."
        type: str
      switch_ids:
        description:
        - List of switch serial numbers to apply the policy group to.
        type: list
        elements: str
      priority:
        description:
        - Priority of the policy group (1-2000).
        - If not provided, defaults to 500 on create. On update, the existing
          value is preserved.
        type: int
      template_inputs:
        description:
        - Dictionary of name/value pairs passed to the policy template.
        type: dict
      create_additional_policy:
        description:
        - A flag indicating if a policy group should be created even if an identical one already exists.
        - When V(true), the policy group is always created without idempotency checks.
        - O(config.description) is not required when this is V(true).
        - Only applicable when O(state=merged).
        type: bool
        default: false
  state:
    description:
    - The desired state of the policy group resources on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new policy groups and update existing ones.
    - Use O(state=deleted) to remove policy groups from the fabric.
    - Use O(state=gathered) to export existing policy groups as playbook-compatible config.
    - "For O(state=gathered):"
    - "  When O(config) is omitted, all policy groups on the fabric are returned."
    - "  When O(config) is provided, results are filtered by the given criteria:"
    - "    O(config.name) with a C(POLICY-GROUP-*) ID returns that specific policy group."
    - "    O(config.name) with a template name returns all policy groups using that template."
    - "    O(config.name) with a template name and O(config.description) returns the exact match."
    - The output under the C(gathered) return key can be used directly as O(config)
      with O(state=merged) for round-trip operations.
    type: str
    default: merged
    choices: [ merged, deleted, gathered ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Policy groups are identified by (description, template_name) composite key.
- The O(config.name) field can be a template name or a C(POLICY-GROUP-xxxxx) ID.
- When using a policy group ID, it is resolved to its template name and description
  by querying the controller. The resolved values are used as the composite key
  for all subsequent state machine operations.
- For O(state=deleted) with only a template name (no description), ALL policy groups
  using that template are expanded and deleted.
- After creation, C(pushConfig) deploys the policy groups to switches.
- "B(Deletion behavior:)"
- "Deletion uses a two-step flow: C(markDelete) is called first to soft-delete the
  policy groups, then C(DELETE) verb is issued when O(deploy=true) to finalize removal."
- "B(switch_freeform and PYTHON content-type templates:)"
- Policy groups using PYTHON content-type templates (e.g., C(switch_freeform),
  C(switch_freeform_config)) cannot be soft-deleted via C(markDelete). The controller
  returns a 207 partial-success response with per-policy failure status for these.
- When C(markDelete) fails for a policy group, the module falls back to a direct
  C(DELETE /policyGroups/{id}) call. This hard-deletes the policy group record.
- After a direct DELETE of a PYTHON content-type policy group, the controller
  internally creates a transient C(switch_freeform_config) artifact with a non-empty
  C(source) field. These ghost records are automatically filtered out during
  C(query_all) operations so they do not appear in gathered output or affect
  idempotency checks.
- "For direct-deleted policy groups (when O(deploy=true)), a switch-level deploy
  (C(POST /switchActions/deploy)) is issued targeting the affected switches to push
  the negative (removal) configuration. This ensures the switch running config is
  updated even though C(markDelete) + C(pushConfig) could not be used."
"""

EXAMPLES = r"""
- name: Create a policy group to enable LACP on multiple switches
  cisco.nd.nd_policy_group:
    fabric_name: my_fabric
    state: merged
    config:
      - name: feature_enable
        description: "Enable LACP on leaf switches"
        switch_ids:
          - FDO25031SY4
          - FDO245206N5
        template_inputs:
          featureName: lacp

- name: Create multiple policy groups in one task
  cisco.nd.nd_policy_group:
    fabric_name: my_fabric
    state: merged
    config:
      - name: feature_enable
        description: "Enable LACP"
        switch_ids: [ FDO25031SY4 ]
        template_inputs:
          featureName: lacp
      - name: feature_enable
        description: "Enable LLDP"
        switch_ids: [ FDO25031SY4 ]
        template_inputs:
          featureName: lldp

- name: Create duplicate policy groups (always create, skip idempotency)
  cisco.nd.nd_policy_group:
    fabric_name: my_fabric
    state: merged
    config:
      - name: switch_freeform
        create_additional_policy: true
        switch_ids: [ FDO25031SY4 ]
        template_inputs:
          CONF: "system vlan long-name"

- name: Delete policy groups by description + template name
  cisco.nd.nd_policy_group:
    fabric_name: my_fabric
    state: deleted
    config:
      - name: feature_enable
        description: "Enable LACP"

- name: Delete ALL policy groups using a specific template (no description)
  cisco.nd.nd_policy_group:
    fabric_name: my_fabric
    state: deleted
    config:
      - name: feature_enable

- name: Delete specific policy groups by policy group ID
  cisco.nd.nd_policy_group:
    fabric_name: my_fabric
    state: deleted
    config:
      - name: POLICY-GROUP-123456
      - name: POLICY-GROUP-789012

- name: Update a policy group by policy group ID
  cisco.nd.nd_policy_group:
    fabric_name: my_fabric
    state: merged
    config:
      - name: POLICY-GROUP-123456
        switch_ids:
          - FDO25031SY4
          - FDO245206N5
        template_inputs:
          featureName: lacp

- name: Delete without deploying (stage only)
  cisco.nd.nd_policy_group:
    fabric_name: my_fabric
    state: deleted
    deploy: false
    config:
      - name: feature_enable
        description: "Enable LACP"

- name: Gather all policy groups on the fabric (no config needed)
  cisco.nd.nd_policy_group:
    fabric_name: my_fabric
    state: gathered
  register: all_policy_groups

- name: Gather policy groups filtered by template name
  cisco.nd.nd_policy_group:
    fabric_name: my_fabric
    state: gathered
    config:
      - name: feature_enable
  register: feature_policies

- name: Gather a specific policy group by ID
  cisco.nd.nd_policy_group:
    fabric_name: my_fabric
    state: gathered
    config:
      - name: POLICY-GROUP-143310

- name: Gather policy groups by template name and description
  cisco.nd.nd_policy_group:
    fabric_name: my_fabric
    state: gathered
    config:
      - name: feature_enable
        description: "Enable LACP"

- name: Use gathered output to re-create policy groups on another fabric
  cisco.nd.nd_policy_group:
    fabric_name: "{{ target_fabric }}"
    state: merged
    config: "{{ all_policy_groups.gathered }}"

- name: Use gathered output to delete those exact policy groups
  cisco.nd.nd_policy_group:
    fabric_name: my_fabric
    state: deleted
    config: "{{ all_policy_groups.gathered }}"
"""

RETURN = r"""
"""

import logging
import os

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.policy_group_base import PolicyGroupCreate
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_policy_group import PolicyGroupOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.gathered_models import GatheredPolicyGroup
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import Log
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


def _resolve_config(config, existing_groups, state, module, log):
    """Resolve config entries for policy group ID and template-name-only cases.

    Handles three name patterns:
    1. POLICY-GROUP-* (direct ID): Resolves to (description, template_name) from existing.
    2. Template name + description: Used as-is (normal composite key).
    3. Template name only (no description, deleted state): Expands to ALL existing
       policy groups with that template name.

    For merged state with POLICY-GROUP-* ID, the entry is resolved to its
    existing description/template_name so the state machine can find and update it.

    Args:
        config: List of config dicts from module params.
        existing_groups: List of policy group dicts from query_all API response.
        state: Current module state (merged/deleted).
        module: AnsibleModule instance for fail_json.
        log: Logger instance.

    Returns:
        Resolved list of config dicts with description and name populated.
    """
    log.debug("ENTER: _resolve_config() — %d entries, state=%s", len(config), state)

    # Build lookup structures from existing groups
    by_policy_id = {}
    by_template_name = {}
    for group in existing_groups:
        pid = group.get("policyId", "")
        tname = group.get("templateName", "")
        desc = group.get("description", "")
        by_policy_id[pid] = group
        by_template_name.setdefault(tname, []).append(group)

    log.debug("_resolve_config: %d existing groups, %d unique IDs, %d unique templates",
              len(existing_groups), len(by_policy_id), len(by_template_name))

    resolved = []
    for idx, entry in enumerate(config):
        name = entry.get("name", "") or ""
        description = entry.get("description")

        if name.startswith("POLICY-GROUP-"):
            # Direct policy group ID — resolve to description + template_name
            existing = by_policy_id.get(name)
            if existing:
                resolved_entry = dict(entry)
                resolved_entry["name"] = existing.get("templateName", "")
                resolved_entry["description"] = existing.get("description", "")
                # Carry the policy_id for the orchestrator
                resolved_entry["policy_id"] = name
                resolved.append(resolved_entry)
                log.info("config[%d]: Resolved ID '%s' → template='%s', description='%s'",
                         idx, name, resolved_entry["name"], resolved_entry["description"])
            elif state == "deleted":
                # ID not found — skip silently (already deleted)
                log.info("config[%d]: ID '%s' not found — skipping (already deleted)", idx, name)
                continue
            else:
                log.error("config[%d]: Policy group ID '%s' not found on controller (state=%s)",
                          idx, name, state)
                module.fail_json(
                    msg=(
                        f"config[{idx}]: Policy group ID '{name}' not found on controller. "
                        "Policy group IDs are server-generated and cannot be used to create "
                        "new policy groups. Use a template name in 'name' together with "
                        "'description' to create a new policy group."
                    )
                )

        elif not description and state == "deleted":
            # Template name only — expand to ALL existing with that template
            matching = by_template_name.get(name, [])
            if matching:
                log.info("config[%d]: Template '%s' (no description) — expanded to %d policy groups",
                         idx, name, len(matching))
            else:
                log.info("config[%d]: Template '%s' (no description) — no matches found, skipping",
                         idx, name)
            for group in matching:
                resolved_entry = dict(entry)
                resolved_entry["name"] = name
                resolved_entry["description"] = group.get("description", "")
                resolved.append(resolved_entry)
            # If no matches, nothing to delete — skip silently

        else:
            # Normal case: name + description provided
            log.debug("config[%d]: Pass-through — name='%s', description='%s'", idx, name, description)
            resolved.append(entry)

    log.debug("EXIT: _resolve_config() — %d entries resolved from %d input", len(resolved), len(config))
    return resolved


def _handle_gathered_state(orchestrator, config, log):
    """Handle state=gathered: export existing policy groups as playbook-ready config.

    Modes:
        - No config: Return ALL policy groups on the fabric.
        - name=POLICY-GROUP-*: Return the specific policy group by ID.
        - name=template_name: Return all policy groups using that template.
        - name=template_name + description: Return the exact matching policy group.

    Args:
        orchestrator: PolicyGroupOrchestrator instance.
        config: List of config filter entries (may be empty).
        log: Logger instance.

    Returns:
        List of playbook-compatible config dicts.
    """
    raw_groups = []

    if not config:
        # No config — fetch everything
        log.info("Gathered: fetching all policy groups")
        raw_groups = orchestrator.query_all()
    else:
        for entry in config:
            name = entry.get("name", "") or ""
            description = entry.get("description")

            if name.startswith("POLICY-GROUP-"):
                # Specific policy group by ID
                log.info("Gathered: querying by ID %s", name)
                result = orchestrator.query_by_id(name)
                if result:
                    raw_groups.append(result)
            elif name and description:
                # Filter by template name + description
                log.info("Gathered: filtering by template=%s, description=%s", name, description)
                filtered = orchestrator.query_filtered(template_name=name, description=description)
                raw_groups.extend(filtered)
            elif name:
                # Filter by template name only
                log.info("Gathered: filtering by template=%s", name)
                filtered = orchestrator.query_filtered(template_name=name)
                raw_groups.extend(filtered)
            elif description:
                # Filter by description only
                log.info("Gathered: filtering by description=%s", description)
                filtered = orchestrator.query_filtered(description=description)
                raw_groups.extend(filtered)

    if not raw_groups:
        log.info("Gathered: no policy groups found")
        return []

    # De-duplicate by policyId and convert to playbook-ready config
    seen_ids = set()
    gathered = []
    for group in raw_groups:
        pid = group.get("policyId", "")
        if not pid or pid in seen_ids:
            continue
        seen_ids.add(pid)
        try:
            model = GatheredPolicyGroup.from_api_policy_group(group)
            gathered.append(model.to_gathered_config())
        except Exception as exc:
            log.warning("Failed to parse policy group %s for gathered output: %s", pid, exc)

    log.info("Gathered %d unique policy groups", len(gathered))
    return gathered


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(PolicyGroupCreate.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Initialize logging (use separate log file for policy_group)
    try:
        policy_group_log_config = os.path.join(
            os.path.dirname(__file__),
            "..", "module_utils", "logging_config_policy_group.json"
        )
        log_config = Log(config=policy_group_log_config)
        log_config.commit()
        log = logging.getLogger("nd.nd_policy_group")
    except ValueError as error:
        module.fail_json(msg=str(error))

    state = module.params.get("state")
    config = module.params.get("config") or []

    # Config is mandatory for merged and deleted states.
    # For gathered, it is optional (no config = fetch all).
    if not config and state != "gathered":
        module.fail_json(
            msg=f"'config' is required when state='{state}'."
        )

    if module.check_mode:
        log.info("Running in check mode — no changes will be made to the controller.")

    # Per-entry validation for merged and deleted states.
    # For gathered, name is optional (allows filter-by-description-only).
    if state == "merged":
        for idx, entry in enumerate(config):
            name = entry.get("name", "") or ""
            if not name:
                module.fail_json(
                    msg=f"config[{idx}]: 'name' is required for every config entry when state=merged."
                )
            # Policy group ID in name field doesn't need description for update
            if name.startswith("POLICY-GROUP-"):
                continue
            # create_additional_policy bypasses idempotency — description not required
            if entry.get("create_additional_policy", False):
                continue
            if not entry.get("description"):
                module.fail_json(
                    msg=(
                        f"config[{idx}]: 'description' is required when state=merged "
                        "and name is not a policy group ID and create_additional_policy is not True. "
                        "Policy groups are identified by (description, template_name) composite key."
                    )
                )
    elif state == "deleted":
        for idx, entry in enumerate(config):
            name = entry.get("name", "") or ""
            if not name:
                module.fail_json(
                    msg=f"config[{idx}]: 'name' is required for every config entry when state=deleted."
                )

    # Cross-entry duplicate validation: (description, template_name) must be
    # unique within the config to prevent ambiguous state machine operations.
    if state in ("merged", "deleted") and config:
        seen_keys = {}
        for idx, entry in enumerate(config):
            name = entry.get("name", "") or ""
            # Skip policy group IDs — they are unique by definition
            if name.startswith("POLICY-GROUP-"):
                continue
            # Skip entries without description (template-only delete expands later)
            desc = entry.get("description", "")
            if not desc:
                continue
            key = (desc, name)
            if key in seen_keys:
                module.fail_json(
                    msg=(
                        f"config[{idx}]: Duplicate (description, name) combination found: "
                        f"description='{desc}', name='{name}'. "
                        f"First occurrence at config[{seen_keys[key]}]. "
                        "Each policy group must be uniquely identified within the config."
                    )
                )
            seen_keys[key] = idx

    try:
        log.info("Starting nd_policy_group module: state=%s, config_entries=%d, deploy=%s",
                 state, len(config), module.params.get("deploy"))

        # Build REST infrastructure for orchestrator instance
        sender = Sender()
        sender.ansible_module = module
        rest_send = RestSend(
            {
                "check_mode": module.check_mode,
                "state": module.params.get("state"),
            }
        )
        rest_send.sender = sender
        rest_send.response_handler = ResponseHandler()

        # Create orchestrator instance (needs fabric_name and deploy before query_all)
        orchestrator = PolicyGroupOrchestrator(
            rest_send=rest_send,
            fabric_name=module.params["fabric_name"],
            deploy=module.params["deploy"],
        )

        # --- Gathered state: bypass the state machine entirely ---
        if state == "gathered":
            gathered = _handle_gathered_state(orchestrator, config, log)
            result = {"changed": False}
            if gathered:
                result["gathered"] = gathered
            log.info("Gathered state completed. Returned %d policy groups.", len(gathered))
            module.exit_json(**result)

        # Pre-process config for deleted/merged states to resolve:
        # 1. POLICY-GROUP-* IDs → resolve to (description, template_name)
        # 2. Template-name-only (no description) in deleted → expand to all matching
        if config and state in ("merged", "deleted"):
            existing_groups = orchestrator.query_all()
            resolved_config = _resolve_config(config, existing_groups, state, module, log)
            module.params["config"] = resolved_config

        # Handle create_additional_policy items separately (bypass state machine).
        # These are always created without idempotency checks.
        force_create_items = []
        normal_config = []
        if state == "merged":
            for entry in (module.params.get("config") or []):
                if entry.get("create_additional_policy", False):
                    force_create_items.append(entry)
                else:
                    normal_config.append(entry)
            module.params["config"] = normal_config
            if force_create_items:
                log.info("Force-create items (create_additional_policy): %d", len(force_create_items))
            log.info("Normal state machine items: %d", len(normal_config))

        force_created = False
        if force_create_items and not module.check_mode:
            models = [PolicyGroupCreate.from_config(e) for e in force_create_items]
            orchestrator.create_bulk(models)
            force_created = True

        # Initialize and run StateMachine for normal items
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=orchestrator,
        )
        nd_state_machine.manage_state()

        # Deploy unchanged policies when deploy=true (push config even if no diff)
        if state in ("merged", "replaced", "overridden") and orchestrator.deploy and not module.check_mode:
            sent_identifiers = {item.get_identifier_value() for item in nd_state_machine.sent}
            unchanged_policy_ids = []
            for item in nd_state_machine.existing:
                if item.get_identifier_value() not in sent_identifiers and getattr(item, "policy_id", None):
                    unchanged_policy_ids.append(item.policy_id)
            if unchanged_policy_ids:
                log.info("Deploying %d unchanged policy groups (deploy=true): %s", len(unchanged_policy_ids), unchanged_policy_ids)
                orchestrator._push_config(unchanged_policy_ids)

        result = nd_state_machine.output.format()
        # If we force-created items, ensure changed=True
        if force_created:
            result["changed"] = True

        log.info("State management completed successfully. Changed: %s", result.get("changed", False))
        module.exit_json(**result)

    except NDStateMachineError as e:
        log.error("State machine error: %s", str(e))
        module.fail_json(msg=str(e))

    except Exception as e:
        import traceback

        tb_str = traceback.format_exc()
        log.error("Unexpected error during module execution: %s", str(e))
        log.error("Error type: %s", e.__class__.__name__)
        log.error("Traceback:\n%s", tb_str)

        fail_kwargs = {}
        if module.params.get("output_level") == "debug":
            fail_kwargs["traceback"] = tb_str

        module.fail_json(msg=f"{e.__class__.__name__}: {str(e)}", **fail_kwargs)


if __name__ == "__main__":
    main()
