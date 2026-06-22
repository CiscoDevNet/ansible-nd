# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
---
module: nd_manage_policy_group
short_description: Manage policy groups on Cisco Nexus Dashboard (ND)
version_added: "2.0.0"
description:
- Manage policy groups on Cisco Nexus Dashboard (ND)
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
        - This field is mutually exclusive with O(config.policy_id) as the primary key;
          when both are present, O(config.policy_id) takes precedence.
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
      policy_id:
        description:
        - The unique policy group ID assigned by the controller (e.g., C(POLICY-GROUP-123456)).
        - Populated automatically in O(state=gathered) output to support round-trip operations.
        - When provided together with O(config.name) (template name) and O(config.description),
          this field is used as the authoritative key for ID-based resolution, bypassing the
          composite (description, template_name) lookup.
        - Optional for O(state=merged) and O(state=deleted). Not applicable for O(state=gathered)
          (use O(config.name) with a C(POLICY-GROUP-*) value to filter by ID in gathered).
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
        - List of switch identifiers to apply the policy group to.
        - Each entry may be either a switch serial number (e.g. C(FDO25031SY4))
          or a management IPv4 address (e.g. C(10.122.84.58)). IPv4 addresses
          are transparently resolved to serial numbers by querying the fabric
          switch inventory before the policy group is created or updated.
          Serials and IPs may be freely mixed in the same list.
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
  ticket_id:
    description:
    - Change Control Ticket ID to associate with mutation operations
      (C(POST)/C(PUT)/C(DELETE)/C(markDelete)).
    - Required when Change Control is enabled on the ND controller.
    - Must start with a letter and contain only letters, digits, underscores,
      or hyphens (max 64 characters).
    type: str
  cluster_name:
    description:
    - Target cluster name in a multi-cluster deployment.
    type: str
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
  cisco.nd.nd_manage_policy_group:
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
  cisco.nd.nd_manage_policy_group:
    fabric_name: my_fabric
    state: merged
    config:
      - name: feature_enable
        description: "Enable LACP"
        switch_ids: [FDO25031SY4]
        template_inputs:
          featureName: lacp
      - name: feature_enable
        description: "Enable LLDP"
        switch_ids: [FDO25031SY4]
        template_inputs:
          featureName: lldp

- name: Create duplicate policy groups (always create, skip idempotency)
  cisco.nd.nd_manage_policy_group:
    fabric_name: my_fabric
    state: merged
    config:
      - name: switch_freeform
        create_additional_policy: true
        switch_ids: [FDO25031SY4]
        template_inputs:
          CONF: "system vlan long-name"

- name: Delete policy groups by description + template name
  cisco.nd.nd_manage_policy_group:
    fabric_name: my_fabric
    state: deleted
    config:
      - name: feature_enable
        description: "Enable LACP"

- name: Delete ALL policy groups using a specific template (no description)
  cisco.nd.nd_manage_policy_group:
    fabric_name: my_fabric
    state: deleted
    config:
      - name: feature_enable

- name: Delete specific policy groups by policy group ID
  cisco.nd.nd_manage_policy_group:
    fabric_name: my_fabric
    state: deleted
    config:
      - name: POLICY-GROUP-123456
      - name: POLICY-GROUP-789012

- name: Update a policy group by policy group ID
  cisco.nd.nd_manage_policy_group:
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
  cisco.nd.nd_manage_policy_group:
    fabric_name: my_fabric
    state: deleted
    deploy: false
    config:
      - name: feature_enable
        description: "Enable LACP"

- name: Gather all policy groups on the fabric (no config needed)
  cisco.nd.nd_manage_policy_group:
    fabric_name: my_fabric
    state: gathered
  register: all_policy_groups

- name: Gather policy groups filtered by template name
  cisco.nd.nd_manage_policy_group:
    fabric_name: my_fabric
    state: gathered
    config:
      - name: feature_enable
  register: feature_policies

- name: Gather a specific policy group by ID
  cisco.nd.nd_manage_policy_group:
    fabric_name: my_fabric
    state: gathered
    config:
      - name: POLICY-GROUP-143310

- name: Gather policy groups by template name and description
  cisco.nd.nd_manage_policy_group:
    fabric_name: my_fabric
    state: gathered
    config:
      - name: feature_enable
        description: "Enable LACP"

- name: Use gathered output to re-create policy groups on another fabric
  cisco.nd.nd_manage_policy_group:
    fabric_name: "{{ target_fabric }}"
    state: merged
    config: "{{ all_policy_groups.gathered }}"

- name: Use gathered output to delete those exact policy groups
  cisco.nd.nd_manage_policy_group:
    fabric_name: my_fabric
    state: deleted
    config: "{{ all_policy_groups.gathered }}"
"""

RETURN = r"""
"""

import logging

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.log import Log
from ansible_collections.cisco.nd.plugins.module_utils.fabric_inventory import (
    FabricSwitchInventory,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.policy_group_base import (
    PolicyGroupCreate,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.policy_group_gathered import (
    PolicyGroupGathered,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_data_models import (
    SwitchDataModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_policy_group import (
    PolicyGroupOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
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

    log.debug(
        "_resolve_config: %d existing groups, %d unique IDs, %d unique templates",
        len(existing_groups),
        len(by_policy_id),
        len(by_template_name),
    )

    resolved = []
    for idx, entry in enumerate(config):
        name = entry.get("name", "") or ""
        description = entry.get("description")

        # If a separate policy_id field is provided (e.g. from gathered
        # round-trip), promote it so the existing POLICY-GROUP-* resolution
        # path below handles it uniformly. The user-facing 'name' in this case
        # is the template name; the policy_id is the authoritative key.
        explicit_pgid = entry.get("policy_id")
        if explicit_pgid and not name.startswith("POLICY-GROUP-"):
            log.debug(
                "config[%d]: policy_id='%s' provided — promoting to ID-based resolution",
                idx,
                explicit_pgid,
            )
            name = explicit_pgid

        if name.startswith("POLICY-GROUP-"):
            # Direct policy group ID — resolve to description + template_name
            existing = by_policy_id.get(name)
            if existing:
                resolved_entry = dict(entry)
                # The user-facing 'policy_id' key carries the POLICY-GROUP-* ID;
                # its value is preserved below as resolved_entry["policy_id"]
                # for the orchestrator (same key name).
                resolved_entry["name"] = existing.get("templateName", "")
                # Preserve user-supplied description (e.g., the user wants to
                # add/change a description on an existing policy group by ID).
                # Only fall back to the existing description when the user
                # didn't provide one. ``description`` is None when the key was
                # omitted entirely; empty string is treated the same here so
                # that the existing value is used as the safe default.
                user_supplied_desc = entry.get("description")
                if user_supplied_desc:
                    resolved_entry["description"] = user_supplied_desc
                else:
                    resolved_entry["description"] = existing.get("description", "")
                # Carry the policy_id for the orchestrator
                resolved_entry["policy_id"] = name
                # Stash the existing description so the main() partitioning
                # can detect rename-via-id and route to the direct-action path
                # (the state machine keys on description and cannot represent
                # a description change).
                resolved_entry["_existing_description"] = existing.get("description", "")
                resolved.append(resolved_entry)
                log.info(
                    "config[%d]: Resolved ID '%s' → template='%s', description='%s' (existing description='%s')",
                    idx,
                    name,
                    resolved_entry["name"],
                    resolved_entry["description"],
                    resolved_entry["_existing_description"],
                )
            elif state == "deleted":
                # ID not found — skip silently (already deleted)
                log.info(
                    "config[%d]: ID '%s' not found — skipping (already deleted)",
                    idx,
                    name,
                )
                continue
            else:
                log.error(
                    "config[%d]: Policy group ID '%s' not found on controller (state=%s)",
                    idx,
                    name,
                    state,
                )
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
                log.info(
                    "config[%d]: Template '%s' (no description) — expanded to %d policy groups",
                    idx,
                    name,
                    len(matching),
                )
            else:
                log.info(
                    "config[%d]: Template '%s' (no description) — no matches found, skipping",
                    idx,
                    name,
                )
            for group in matching:
                resolved_entry = dict(entry)
                resolved_entry["name"] = name
                resolved_entry["description"] = group.get("description", "")
                resolved.append(resolved_entry)
            # If no matches, nothing to delete — skip silently

        else:
            # Normal case: name + description provided
            log.debug(
                "config[%d]: Pass-through — name='%s', description='%s'",
                idx,
                name,
                description,
            )
            resolved.append(entry)

    log.debug(
        "EXIT: _resolve_config() — %d entries resolved from %d input",
        len(resolved),
        len(config),
    )
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
        raw_groups = orchestrator.query_all(include_no_description=True, deduplicate=False)
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
                log.info(
                    "Gathered: filtering by template=%s, description=%s",
                    name,
                    description,
                )
                filtered = orchestrator.query_filtered(template_name=name, description=description, deduplicate=False)
                raw_groups.extend(filtered)
            elif name:
                # Filter by template name only
                log.info("Gathered: filtering by template=%s", name)
                filtered = orchestrator.query_filtered(template_name=name, deduplicate=False)
                raw_groups.extend(filtered)
            elif description:
                # Filter by description only
                log.info("Gathered: filtering by description=%s", description)
                filtered = orchestrator.query_filtered(description=description, deduplicate=False)
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
            model = PolicyGroupGathered.from_api_policy_group(group)
            gathered.append(model.to_gathered_config())
        except Exception as exc:
            log.warning("Failed to parse policy group %s for gathered output: %s", pid, exc)

    log.info("Gathered %d unique policy groups", len(gathered))
    return gathered


def _looks_like_ipv4(value: str) -> bool:
    """Return True if *value* is a dotted-quad IPv4 address."""
    if not value:
        return False
    parts = str(value).strip().split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _resolve_switch_ips_in_config(module, log, config, fabric_name):
    """Replace IPv4 entries in every ``config[].switch_ids`` with serial numbers.

    Walks the config; if any ``switch_ids`` entry is an IPv4 address it is
    resolved to its switch serial number via ``FabricSwitchInventory``.
    Serials are passed through unchanged.  Mixed serial/IP lists are
    supported.

    The fabric inventory is fetched at most once per module invocation,
    and only when the config actually contains an IP (zero overhead for
    serial-only playbooks).  Read-only check_mode users still get
    resolution because RestSend's ``check_mode`` is temporarily
    overridden for this single GET.

    Args:
        module: ``AnsibleModule`` instance (used for ``fail_json``).
        log: Logger instance.
        config: List of config entry dicts (mutated in place).
        fabric_name: Fabric to query for switch inventory.
    """
    if not config:
        return
    has_ip = any(_looks_like_ipv4(sid) for entry in config for sid in (entry.get("switch_ids") or []))
    if not has_ip:
        return

    log.info(
        "Resolving switch IPv4 addresses to serial numbers for fabric '%s'",
        fabric_name,
    )
    nd = NDModule(module)
    rest_send = nd.get_rest_send()
    rest_send.save_settings()
    rest_send.check_mode = False
    try:
        inventory = FabricSwitchInventory.from_fabric(nd, fabric_name, log, SwitchDataModel)
    finally:
        rest_send.restore_settings()

    ip_map = inventory.by_ip()

    for idx, entry in enumerate(config):
        switch_ids = entry.get("switch_ids")
        if not switch_ids:
            continue
        resolved_list = []
        for j, sid in enumerate(switch_ids):
            if not _looks_like_ipv4(sid):
                resolved_list.append(sid)
                continue
            value = str(sid).strip()
            switch = ip_map.get(value)
            if switch is None:
                module.fail_json(
                    msg=(
                        f"config[{idx}].switch_ids[{j}]: unable to resolve IP '{sid}' "
                        f"to a serial number in fabric '{fabric_name}'. Provide a valid "
                        "switch serial number or management IP from the fabric inventory."
                    )
                )
            resolved_list.append(switch.switch_id)
        entry["switch_ids"] = resolved_list


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(PolicyGroupCreate.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Initialize logging
    try:
        log_config = Log()
        log_config.commit()
        log = logging.getLogger("nd.nd_manage_policy_group")
    except ValueError as error:
        module.fail_json(msg=str(error))

    state = module.params.get("state")
    config = module.params.get("config") or []

    # Config is mandatory for merged and deleted states.
    # For gathered, it is optional (no config = fetch all).
    if not config and state != "gathered":
        module.fail_json(msg=f"'config' is required when state='{state}'.")

    if module.check_mode:
        log.info("Running in check mode — no changes will be made to the controller.")

    # Per-entry validation for merged and deleted states.
    # For gathered, name is optional (allows filter-by-description-only).
    if state == "merged":
        for idx, entry in enumerate(config):
            name = entry.get("name", "") or ""
            if not name:
                module.fail_json(msg=f"config[{idx}]: 'name' is required for every config entry when state=merged.")
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
                module.fail_json(msg=f"config[{idx}]: 'name' is required for every config entry when state=deleted.")

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
        log.info(
            "Starting nd_manage_policy_group module: state=%s, config_entries=%d, deploy=%s",
            state,
            len(config),
            module.params.get("deploy"),
        )

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
            ticket_id=module.params.get("ticket_id"),
            cluster_name=module.params.get("cluster_name"),
        )

        # Resolve any switch_ids entries that are IPv4 addresses to serial
        # numbers via the fabric inventory.  This is a no-op (no API call)
        # when every switch_ids entry is already a serial number.  Skipped
        # for state=gathered since gathered config is filter-only and does
        # not carry switch_ids the controller needs to act on.
        if state in ("merged", "deleted"):
            _resolve_switch_ips_in_config(module, log, config, module.params["fabric_name"])

        # --- Gathered state: bypass the state machine entirely ---
        if state == "gathered":
            gathered = _handle_gathered_state(orchestrator, config, log)
            result = {"changed": False, "gathered": gathered}
            log.info("Gathered state completed. Returned %d policy groups.", len(gathered))
            module.exit_json(**result)

        # Pre-process config for deleted/merged states to resolve:
        # 1. POLICY-GROUP-* IDs → resolve to (description, template_name)
        # 2. Template-name-only (no description) in deleted → expand to all matching
        # We pass include_no_description=True so POLICY-GROUP-* IDs of
        # no-description groups can also be resolved (these groups bypass the
        # state machine via the direct-action path below).
        existing_groups = None
        if config and state in ("merged", "deleted"):
            existing_groups = orchestrator.query_all(include_no_description=True, deduplicate=False)
            resolved_config = _resolve_config(config, existing_groups, state, module, log)
            module.params["config"] = resolved_config

        # Partition resolved entries into three buckets:
        #   1. force_create_items — `create_additional_policy: true` (existing path)
        #   2. direct_action_items — entries targeting a no-description group
        #      via POLICY-GROUP-* ID (cannot fit the state-machine composite key)
        #   3. normal_config — everything else (state-machine path)
        force_create_items = []
        direct_action_items = []
        normal_config = []
        if state in ("merged", "deleted"):
            for entry in module.params.get("config") or []:
                if entry.get("create_additional_policy", False):
                    force_create_items.append(entry)
                elif entry.get("policy_id") and (not entry.get("description") or entry.get("description") != entry.get("_existing_description")):
                    # Resolved from POLICY-GROUP-* AND either:
                    #   (a) the target has no description (state machine cannot
                    #       index a None composite key), or
                    #   (b) the user is changing the description via ID
                    #       (the state machine keys on description and would
                    #       see this as delete-old + create-new instead of
                    #       an in-place update).
                    # Either way, bypass the state machine and call
                    # orchestrator.update / delete_bulk directly by policy_id.
                    direct_action_items.append(entry)
                else:
                    normal_config.append(entry)
            # Strip the bookkeeping field from normal_config entries before
            # they hit Pydantic validation; the state machine path doesn't
            # need ``_existing_description``.
            for entry in normal_config:
                entry.pop("_existing_description", None)
            module.params["config"] = normal_config
            if force_create_items:
                log.info(
                    "Force-create items (create_additional_policy): %d",
                    len(force_create_items),
                )
            if direct_action_items:
                log.info(
                    "Direct-action items (managed by policy_id): %d",
                    len(direct_action_items),
                )
            log.info("Normal state machine items: %d", len(normal_config))

        force_created = False
        force_created_models: list = []
        if force_create_items and not module.check_mode:
            # `create_additional_policy: true` items share the same composite
            # identifier (description, template_name) as existing groups, so
            # they CANNOT show up in before/after — the identifier-keyed
            # NDConfigCollection collapses duplicates. Surface them via a
            # dedicated `force_created` key in the result instead.
            force_created_models = [PolicyGroupCreate.from_config(e) for e in force_create_items]
            orchestrator.create_bulk(force_created_models)
            force_created = True

        # Execute direct-action items (no-description groups referenced by ID).
        # These bypass the state machine because their composite identifier
        # (None, template_name) cannot be uniquely indexed in NDConfigCollection.
        # Surface results via a dedicated `direct_actions` key.
        direct_actions_result = {"updated": [], "deleted": []}
        if direct_action_items:
            for entry in direct_action_items:
                pid = entry["policy_id"]
                entry_for_model = {k: v for k, v in entry.items() if k != "_existing_description"}
                if state == "merged":
                    model = PolicyGroupCreate.from_config(entry_for_model)
                    model.policy_id = pid
                    if not module.check_mode:
                        orchestrator.update(model)
                    direct_actions_result["updated"].append(model.model_dump(by_alias=False, exclude_none=True))
                    log.info(
                        "Direct-action: updated policy group %s (description='%s')",
                        pid,
                        model.description,
                    )
                elif state == "deleted":
                    model = PolicyGroupCreate.from_config(entry_for_model)
                    model.policy_id = pid
                    if not module.check_mode:
                        orchestrator.delete_bulk([model])
                    direct_actions_result["deleted"].append(model.model_dump(by_alias=False, exclude_none=True))
                    log.info("Direct-action: deleted policy group %s", pid)

        # Initialize and run StateMachine for normal items
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=orchestrator,
        )
        nd_state_machine.manage_state()

        # Deploy unchanged policies when deploy=true (push config even if no diff).
        # The orchestrator method scopes strictly to policies the user mentioned
        # in `config:` so we never touch unrelated fabric policies, and is a
        # no-op when deploy=false.
        if state == "merged" and not module.check_mode:
            orchestrator.deploy_unchanged_user_mentioned(nd_state_machine)

        result = nd_state_machine.output.format()
        # Surface force-created items as a dedicated key so they're visible
        # even though identifier collisions prevent them from appearing in
        # the state-machine's before/after.
        if force_created:
            result["changed"] = True
            result["force_created"] = [m.model_dump(by_alias=False, exclude_none=True) for m in force_created_models]
        # Surface direct-action results (no-description groups managed by ID).
        # These bypass the state machine, so they don't show up in before/after.
        if direct_action_items:
            result["changed"] = True
            result["direct_actions"] = direct_actions_result

        log.info(
            "State management completed successfully. Changed: %s",
            result.get("changed", False),
        )
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
