# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
---
module: nd_manage_policy_group
short_description: Manage policy groups on Cisco Nexus Dashboard (ND)
version_added: "2.0.0"
description:
- Manage policy groups on Cisco Nexus Dashboard (ND).
- Policy groups apply one template to multiple switches.
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
    - When V(false), changes are staged on the controller but running config is
      not deployed to the switches until a later deploy.
    - Policy groups have no per-policy deploy path. The ND
      C(policyActions/pushConfig) operation is B(not) honoured for policy groups,
      so every O(deploy=true) path uses switch-level deploy.
    - For C(create), the deploy target is the new policy group's member switches.
    - For C(update), the deploy target is the B(union of the new member set and
      the removed member set), meaning B(post-update members) plus B(removed members).
      The removed members are included so the controller pushes the negative
      (removal) configuration to switches that no longer belong to the policy group.
      This formula covers all three sub-cases identically, switches added only,
      switches removed only, and switches added-and-removed in the same task.
    - For C(delete), the module calls C(markDelete) once with all policy group IDs.
      The operation returns C(207 Multi-Status) with per-policy success or failure
      status.
    - For policy groups where C(markDelete) fails, typically PYTHON content-type
      templates such as C(switch_freeform) and C(switch_freeform_config), the module
      falls back to direct C(DELETE). This fallback is unconditional on the
      C(markDelete) failure and is B(not) gated by O(deploy).
    - For C(delete) with O(deploy=true), C(markDelete)-succeeded groups and direct
      C(DELETE) fallback groups are followed by one consolidated switch-level deploy
      against the union of all affected switches. With O(deploy=false), the
      switch-level deploy step is skipped and running config remains on the switches
      until a later deploy.
    - If a later C(delete) run uses O(deploy=true) for a policy group already pending
      deletion from a previous O(deploy=false) run, the normal active policy-group
      view will not return C(markDeleted=true) rows or generated child rows with
      non-empty C(source). The module reads C(policySummary) with
      C(filter=policyId:*POLICY-GROUP-*) and matches hidden C(markDeleted=true) rows
      by requested ID as C(policyId), requested ID as generated-child C(source), or
      exact description. Only matched pending-delete rows contribute switches to the
      consolidated switch-level deploy target, so a mistyped or already-clean target
      does not deploy unless C(policySummary) contains a matching pending row.
    - For user-mentioned policy groups listed in O(config) whose desired state
      already matches the controller with no diff, switch-level deploy is still
      issued against the existing member switches so the user-expressed deploy
      intent is honoured.
    - Because every O(deploy=true) step uses switch-level deploy, whenever the
      targeted policy groups have member switches, the controller deploys B(every
      pending configuration change staged for those switches), not only the
      policy-group changes performed by this task. The ND controller does not provide
      a per-task or staged-only variant of switch-level deploy. Use O(deploy=false)
      to stage policy-group changes without triggering switch-level deploy.
    type: bool
    default: true
  config:
    description:
    - List of policy group configurations.
    - Required for C(merged) and C(deleted). Optional for C(gathered).
    - For C(merged), O(config[].name) is required. If O(config[].name) is a
      template name, O(config[].description) is also required unless
      O(config[].create_additional_policy=true).
    - For C(deleted), O(config[].name) is required. A template name without
      O(config[].description) expands to all active policy groups using that template.
    - For C(gathered), entries are filters. They may use O(config[].name),
      O(config[].description), or both. See O(state) for the gathered filter matrix.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - Template name (for example, C(feature_enable) or C(switch_freeform)) or
          policy group ID (for example, C(POLICY-GROUP-123456)).
        - When both O(config[].name) and O(config[].policy_id) are supplied and
          O(config[].name) is a template name, O(config[].policy_id) takes precedence
          as the primary key for resolution. If O(config[].name) is already a
          C(POLICY-GROUP-*) ID, that ID is used directly.
        - Template names can be used by multiple policy groups and do not identify a
          policy group uniquely without O(config[].description).
        - When a C(POLICY-GROUP-*) ID is provided, the module queries the controller to resolve it
          to its corresponding C(template_name) and C(description). The resolved values are then used
          internally as the composite key for state machine operations (create/update/delete).
        - For C(merged), if the ID is not found on the controller, the module fails with an error.
          Policy group IDs are server-generated and cannot be used to create new policy groups.
          Use a template name in O(config[].name) together with O(config[].description)
          to create new policy groups.
        - For C(deleted), if the ID is not found in the active policy-group view,
          it is treated as already deleted unless O(deploy=true) finds a matching
          C(markDeleted=true) row in C(policySummary). Matching accepts the requested
          ID as the hidden row's C(policyId), or as the C(source) value on a generated
          child row. This means either the original ID or the generated child row ID
          can work when it identifies the pending row returned by C(policySummary).
          When matched, the module deploys the switches reported by C(policySummary).
        - For C(gathered), the ID is used directly to query the specific policy group by ID.
        - Required for C(merged) and C(deleted). Optional for C(gathered) where
          entries can filter by O(config[].description) alone.
        type: str
      policy_id:
        description:
        - The unique policy group ID assigned by the controller (e.g., C(POLICY-GROUP-123456)).
        - Populated automatically in C(state=gathered) output to support round-trip operations.
        - When provided together with O(config[].name) as a template name and
          O(config[].description),
          this field is used as the authoritative key for ID-based resolution, bypassing the
          composite (description, template_name) lookup.
        - This is B(not) an alias for O(config[].name).
        - Use snake-case O(config[].policy_id). C(policyId) is not an alias.
        - Optional for C(merged) and C(deleted).
        - Not used as a C(state=gathered) filter. To gather one policy group by ID,
          set O(config[].name) to the C(POLICY-GROUP-*) value.
        - ID-based updates for no-description groups or description changes bypass
          the normal composite-key state machine and are returned under
          C(direct_actions), not normal C(before)/C(after).
        - When an ID-based C(merged) update changes the group's description, the request
          bypasses the composite-key merge state machine and is sent as a direct
          C(PUT /policyGroups/{policy_id}) payload. Always include the intended
          O(config[].switch_ids) on these entries — B(omitting O(config[].switch_ids) on a direct-ID PUT
          will replace the group's member set with an empty list), removing the policy
          group from every switch it previously covered.
        type: str
      description:
        description:
        - Description of the policy group.
        - Used together with template-name O(config[].name) as the normal composite
          key, C(description, template_name).
        - Required when C(state=merged) and O(config[].name) is a template name,
          B(unless) O(config[].create_additional_policy=true) is set. In that case,
          the composite-key idempotency check is bypassed and O(config[].description)
          becomes optional.
        - For C(deleted), if provided with a template name, deletes the specific policy
          group matching C(description, template_name). If omitted with a template name,
          deletes all active policy groups using that template. Not required when
          O(config[].name) is a policy group ID.
        - For C(gathered), can be used by itself to gather all groups with that description,
          or with O(config[].name) to gather the exact template+description match.
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
        - For C(merged), non-empty inputs are validated per entry against the template
          parameters endpoint before that entry is sent to the controller. Entries
          that fail validation are removed from the write bucket and reported in the
          final task failure; valid entries can still be created, updated, or
          deployed. The final task result is failed when any entry fails. Controller
          parameter-fetch failures degrade to controller-side validation.
        - System-injected keys returned by gathered output are stripped before
          validation so gathered-to-merged round trips do not fail on controller-only
          fields.
        type: dict
      create_additional_policy:
        description:
        - A flag indicating if a policy group should be created even if an identical one already exists.
        - When V(true), the policy group is always created without idempotency checks.
        - O(config[].description) is not required when this is V(true).
        - Only applicable when O(state=merged).
        - Force-created groups are returned under C(force_created), not the normal
          C(before)/C(after) state-machine lists, because duplicate composite
          identifiers cannot be represented in those collections.
        type: bool
        default: false
  ticket_id:
    description:
    - Change Control Ticket ID to associate with create/update operations,
      C(markDelete), and direct C(DELETE).
    - Required when Change Control is enabled on the ND controller.
    - Must start with a letter and contain only letters, digits, underscores,
      or hyphens (max 64 characters).
    - B(Note) - switch-level deploy does not accept a C(ticketId) parameter, so
      deploy steps are B(not) bound to the supplied ticket. Only controller-side
      mutation operations carry the ticket.
    type: str
  cluster_name:
    description:
    - Target cluster name in a multi-cluster deployment.
    type: str
  state:
    description:
    - The desired state of the policy group resources on the Cisco Nexus Dashboard.
    - Use C(merged) to create new policy groups and update existing ones.
    - Use C(deleted) to remove policy groups from the fabric.
    - Use C(gathered) to export existing policy groups as playbook-compatible config.
      When O(config) is omitted, all active, user-manageable policy groups on the
      fabric are returned. When O(config) is provided, results are filtered by the
      provided criteria.
    - For C(gathered), O(config[].name) with a C(POLICY-GROUP-*) ID returns that
      specific policy group.
    - For C(gathered), O(config[].name) with a template name returns all policy
      groups using that template.
    - For C(gathered), O(config[].name) with a template name and
      O(config[].description) returns the exact match.
    - For C(gathered), O(config[].description) without O(config[].name) returns all
      policy groups with that description.
    - The output under the C(gathered) return key can be used directly as O(config)
      with C(state=merged) for round-trip operations.
    - C(state=gathered) excludes policy groups with C(markDeleted=true) and
      generated/internal rows with non-empty C(source).
    type: str
    default: merged
    choices: [ merged, deleted, gathered ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- The module is validation-first but B(not) a rollback transaction. Input validation
  and duplicate checks run before write operations. After controller writes begin,
  later API or deploy failures can leave earlier successful operations in place.
- "B(Ghost-record cleanup for PYTHON content-type templates:)"
- After a direct C(DELETE) of a PYTHON content-type policy group,
  the controller internally creates a transient C(switch_freeform_config) artifact
  with a non-empty C(source) field referencing the deleted policy group. These
  ghost records are automatically filtered out during normal query operations so
  they do not appear in C(gathered) output and do not affect idempotency checks
  on subsequent runs.
- Query and gathered paths use C(policySummary) instead of C(GET /policyGroups)
  because supported controller builds can return incorrect C(priority) and
  C(markDeleted) values from C(GET /policyGroups). The module requests
  C(filter=policyId:*POLICY-GROUP-*) and still filters policy group rows in Python.
- Query and gathered paths filter out controller artifacts with a non-empty C(source)
  field and fully pending-delete records where C(policySummary.switches[].markDeleted)
  is true for every switch. Normal state-machine reads also exclude no-description
  policy groups because they cannot be indexed by the composite key; ID-based direct
  actions and C(gathered) use broader reads when they need to see no-description groups.
- C(state=merged) uses this active policy-summary view. A C(markDeleted=true) policy
  group or a generated child row with non-empty C(source) does not satisfy idempotency.
  Replaying the same desired config creates or updates an active group instead of
  becoming a no-op against a pending-delete row. Pending-delete rows are consulted only
  by the C(state=deleted) + O(deploy=true) cleanup path, and only through the
  C(policySummary) validation described above.
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

- name: Delete all active policy groups using a specific template (no description)
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

- name: Gather all active policy groups on the fabric (no config needed)
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
changed:
  description:
  - Whether the module changed controller state or issued a requested deploy/cleanup action.
  type: bool
  returned: always
before:
  description:
  - Policy groups matched before normal state-machine operations.
  type: list
  elements: dict
  returned: when C(state=merged) or C(state=deleted) uses the normal state-machine path
after:
  description:
  - Policy groups after normal state-machine operations.
  type: list
  elements: dict
  returned: when C(state=merged) or C(state=deleted) uses the normal state-machine path
gathered:
  description:
  - Active, user-manageable policy groups exported as playbook-compatible config.
  - Rows with C(markDeleted=true) and generated/internal rows with non-empty C(source)
    are excluded.
  type: list
  elements: dict
  returned: when C(state=gathered)
force_created:
  description:
  - Policy groups created through O(config[].create_additional_policy=true).
  - These are returned separately because duplicate composite identifiers cannot be
    represented in the normal C(before)/C(after) state-machine collections.
  type: list
  elements: dict
  returned: when force-created entries are processed
direct_actions:
  description:
  - ID-based policy-group updates or deletes that bypassed the composite-key state machine.
  - Used for no-description groups and description changes addressed by C(policy_id).
  type: dict
  returned: when direct-action entries are processed
  contains:
    updated:
      description: Policy groups updated directly by controller ID.
      type: list
      elements: dict
    deleted:
      description: Policy groups deleted directly by controller ID.
      type: list
      elements: dict
pending_deleted_cleanup:
  description:
  - Details for C(state=deleted) + O(deploy=true) cleanup of rows already hidden from
    the active view by C(markDeleted=true) or non-empty C(source).
  - Policy groups are validated through C(policySummary) before their switches are
    added to the consolidated C(switchActions/deploy) request.
  type: dict
  returned: when pending-delete cleanup is scheduled
template_input_validation_failed:
  description:
  - Per-entry template-input validation failures. Valid entries may already have been
    processed before the module returns the final failed result.
  type: list
  elements: dict
  returned: when one or more C(template_inputs) entries fail schema validation
"""

import logging

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.log import Log
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    require_pydantic,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.template_validation import (
    fetch_template_params as _shared_fetch_template_params,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.template_validation import (
    strip_system_injected_keys as _shared_strip_system_injected_keys,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.template_validation import (
    validate_template_inputs as _shared_validate_template_inputs,
)
from ansible_collections.cisco.nd.plugins.module_utils.constants import (
    SYSTEM_INJECTED_TEMPLATE_KEYS,
)
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

# =============================================================================
# Module-level configuration
# =============================================================================
#
# Internal kill switch for the live template-input schema validation hook
# (see ``_validate_template_inputs_in_buckets`` below).  When ``True`` (the
# default), every policy-group entry destined for a POST or PUT to the
# controller is pre-flighted against the template's
# ``GET /api/v1/manage/configTemplates/<name>/parameters`` schema. Invalid
# entries are removed from their execution bucket and reported in the final
# module result; valid entries can still be applied.
#
# Flip to ``False`` ONLY as a temporary escape hatch if the controller's
# parameters endpoint produces false positives in the field -- this degrades
# us to "trust the controller" behaviour (same as before this PR).  Not
# exposed in the argspec; meant to be flipped here in-tree and not by users.
_ENABLE_TEMPLATE_INPUT_VALIDATION: bool = True


def _validate_template_inputs_in_buckets(
    *,
    force_create_items: list[dict],
    direct_action_items: list[dict],
    normal_config: list[dict],
    state: str,
    orchestrator,
    log: logging.Logger,
) -> list[dict]:
    """Validate template inputs and remove invalid entries from write buckets.

    The policy-group create / update path POSTs ``{"policyGroups": [...]}``
    (bulk-create) or PUTs ``/policyGroups/{id}`` with a body that contains
    user-supplied ``templateInputs``.  ND validates those inputs against the
    config template named by ``templateName`` and returns a per-item 207 on
    schema violations.  That feedback only arrives **after** the bulk call
    so we cannot easily surface a structured per-entry error from it.

    This helper closes the gap: for every entry that is going to carry
    ``templateInputs`` in its outbound body, fetch the template's parameter
    schema (cached per-task), strip the ND-injected SYSTEM_INJECTED keys
    (so gathered -> merged round-trip is clean), and validate. Invalid
    entries are pruned from the bucket they came from and returned as
    structured failures. The caller reports those failures after processing
    the remaining valid entries, matching the policy module's per-entry
    validation semantics.

    Skip rules (validation is a no-op when the corresponding write does not
    carry ``templateInputs``):

    - ``_ENABLE_TEMPLATE_INPUT_VALIDATION`` is ``False``   -> skip everything
    - ``state != "merged"``                                -> skip everything
        (``deleted`` uses policy IDs in markDelete + DELETE-by-id; the body
        never carries ``templateInputs``.  ``gathered`` is read-only and
        short-circuits long before this hook.)
    - Entry has no ``template_inputs`` (or empty dict)     -> skip the entry
    - Template name resolves to a ``POLICY-GROUP-*``       -> skip the entry
        (defensive: the partitioning step always resolves the alias to a
        real template name; this is a belt-and-braces guard for any future
        code path that bypasses ``_resolve_config``.)

    The fetch uses ``orchestrator._request`` (so retries, error handling
    and 404 semantics match every other policy-group endpoint call) and
    forwards ``cluster_name`` (but NOT ``ticket_id``, since the parameters
    endpoint is a read endpoint that does not accept ticketId).

    Errors are aggregated across every validated entry into the returned
    failure list. The bucket lists are mutated in-place so downstream create,
    direct-action, and state-machine paths never send invalid entries.

    Args:
        force_create_items:   Bucket from ``main()`` partitioning -- entries
                              with ``create_additional_policy: true``.
        direct_action_items:  Bucket from ``main()`` partitioning -- entries
                              resolved from ``POLICY-GROUP-*`` IDs that
                              bypass the state machine.
        normal_config:        Bucket from ``main()`` partitioning -- the
                              state-machine-managed entries.
        state:                Module state ("merged" / "deleted" / "gathered").
        orchestrator:         The ``PolicyGroupOrchestrator`` instance.
                              Used for its ``_request`` method and its
                              ``_apply_endpoint_params`` plumbing (so the
                              ``cluster_name`` query parameter is honoured).
        log:                  Logger -- ENTER / EXIT / per-entry pass / fail
                              lines are emitted at DEBUG; aggregated error
                              count at WARNING via the shared helper.

    Returns:
        List of structured per-entry validation failures. Empty when no
        failures were found or validation was skipped.
    """
    if not _ENABLE_TEMPLATE_INPUT_VALIDATION:
        log.debug("Template-input validation disabled (kill switch); skipping.")
        return []
    if state != "merged":
        log.debug("Template-input validation skipped: state=%s (no body carries templateInputs).", state)
        return []

    # Build the union of write-bound entries.  Order is preserved so the
    # error message lists violations in the same order the user supplied
    # them.  The buckets are disjoint by construction (see ``main()``).
    candidates = (
        [("force_create", entry) for entry in force_create_items]
        + [("direct_action", entry) for entry in direct_action_items]
        + [("normal", entry) for entry in normal_config]
    )
    if not candidates:
        log.debug("Template-input validation skipped: no write-bound entries.")
        return []

    # Per-task fetch cache: {template_name: [param_def, ...]}.  Shared
    # across every entry so N policy groups with the same template incur
    # exactly one GET.  Owned here (not on the orchestrator) so the
    # orchestrator's lifecycle is unaffected and the cache is discarded
    # on every task run.
    param_cache: dict[str, list[dict]] = {}

    def _request_fn(path: str, verb) -> dict:
        # Wraps orchestrator._request so the shared helper sees the same
        # auth / retry / error-handling envelope as every other GET in
        # this module.  Re-raises to let the helper's outer try/except
        # cache an empty list and log a WARNING (graceful degradation).
        return orchestrator._request(path=path, verb=verb, not_found_ok=False)

    def _set_endpoint_params(ep) -> None:
        # Forward cluster_name (read endpoint -- NO ticket_id).  Honours
        # the same per-endpoint capability matrix every other policy-group
        # call uses via the orchestrator's ``_apply_endpoint_params``.
        orchestrator._apply_endpoint_params(ep, with_ticket=False)

    log.debug(
        "Template-input validation: pre-flighting %d entries (force_create=%d, direct_action=%d, normal=%d)",
        len(candidates),
        len(force_create_items),
        len(direct_action_items),
        len(normal_config),
    )

    failures: list[dict] = []
    valid_by_bucket: dict[str, list[dict]] = {
        "force_create": [],
        "direct_action": [],
        "normal": [],
    }
    for idx, (bucket, entry) in enumerate(candidates):
        raw_inputs = entry.get("template_inputs") or {}
        if not raw_inputs:
            log.debug("config[%d] (%s): no template_inputs -- skip validation.", idx, bucket)
            valid_by_bucket[bucket].append(entry)
            continue
        template_name = entry.get("name", "") or ""
        # Defensive: the partitioning step always resolves POLICY-GROUP-*
        # to a real template name BEFORE entries land in any bucket.  This
        # guard catches any future code path that forgets to do so.
        if not template_name or template_name.startswith("POLICY-GROUP-"):
            log.debug(
                "config[%d] (%s): template name unresolved (%r) -- skip validation.",
                idx,
                bucket,
                template_name,
            )
            valid_by_bucket[bucket].append(entry)
            continue

        # Strip ND-injected control keys before validation so the
        # gathered -> merged round-trip stays clean.  ``raw_inputs`` is not
        # mutated; the helper returns a fresh dict.
        cleaned_inputs = _shared_strip_system_injected_keys(
            template_name,
            raw_inputs,
            SYSTEM_INJECTED_TEMPLATE_KEYS,
            logger=log,
        )

        # Fetch (with cache) the template's parameter schema.  A controller
        # error or 404 caches an empty schema and degrades to "trust the
        # controller" for this entry (the shared helper's documented
        # graceful-degradation behaviour).
        params = _shared_fetch_template_params(
            template_name,
            request_fn=_request_fn,
            cache=param_cache,
            endpoint_modifier_fn=_set_endpoint_params,
            logger=log,
        )

        entry_errors = _shared_validate_template_inputs(
            template_name,
            cleaned_inputs,
            params,
            logger=log,
        )
        if entry_errors:
            # Prefix each error with a stable per-entry identifier so the
            # final report tells the user which config[] index hit which
            # violation. Uses ``description`` when available (the
            # user's primary handle) and falls back to ``policy_id`` (for
            # direct-action / round-trip entries).
            ident = entry.get("description") or entry.get("policy_id") or "<unidentified>"
            failures.append(
                {
                    "index": idx,
                    "bucket": bucket,
                    "identifier": ident,
                    "template_name": template_name,
                    "errors": entry_errors,
                    "entry": entry,
                }
            )
            continue
        valid_by_bucket[bucket].append(entry)

    force_create_items[:] = valid_by_bucket["force_create"]
    direct_action_items[:] = valid_by_bucket["direct_action"]
    normal_config[:] = valid_by_bucket["normal"]

    if failures:
        log.error(
            "Template-input validation failed for %d entry/entries; continuing with valid entries.",
            len(failures),
        )
    else:
        log.debug("Template-input validation passed for all %d candidate entries.", len(candidates))
    return failures


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


def _pending_cleanup_candidates(config, existing_groups, log):
    """Return delete+deploy entries absent from the active policy-group view.

    The active view excludes ``markDeleted`` and ``source`` artifacts.  If a
    delete target is missing there, the orchestrator checks policySummary for a
    matching hidden ``markDeleted`` row before scheduling switch cleanup.
    """
    active_policy_ids = {group.get("policyId") for group in existing_groups if group.get("policyId")}
    active_composites = {(group.get("description"), group.get("templateName")) for group in existing_groups if group.get("templateName")}
    active_templates = {group.get("templateName") for group in existing_groups if group.get("templateName")}

    candidates = []
    for index, entry in enumerate(config or []):
        name = entry.get("name") or ""
        description = entry.get("description")
        policy_group_id, _cleanup_description = PolicyGroupOrchestrator._cleanup_identity(entry)

        if policy_group_id:
            if policy_group_id in active_policy_ids:
                continue
            log.info(
                "config[%d]: policy group ID '%s' absent from active view; checking policySummary for pending-delete cleanup.",
                index,
                policy_group_id,
            )
            candidates.append(entry)
            continue

        if description:
            if (description, name) in active_composites:
                continue
            log.info(
                "config[%d]: policy group '%s' description '%s' absent from active view; checking policySummary for pending-delete cleanup.",
                index,
                name,
                description,
            )
            candidates.append(entry)
            continue

        if name and name not in active_templates:
            log.info(
                "config[%d]: template '%s' absent from active view; checking policySummary for pending-delete cleanup.",
                index,
                name,
            )
            candidates.append(entry)

    return candidates


def _handle_gathered_state(orchestrator, config, log):
    """Handle state=gathered: export existing policy groups as playbook-ready config.

    Modes:
        - No config: Return all active, user-manageable policy groups on the fabric.
        - name=POLICY-GROUP-*: Return the active policy group with that ID.
        - name=template_name: Return active policy groups using that template.
        - name=template_name + description: Return the active exact match.

    Args:
        orchestrator: PolicyGroupOrchestrator instance.
        config: List of config filter entries (may be empty).
        log: Logger instance.

    Returns:
        List of playbook-compatible config dicts.
    """
    raw_groups = []

    if not config:
        # No config — fetch the active user-managed view.
        log.info("Gathered: fetching all active user-managed policy groups")
        raw_groups = orchestrator.query_all(include_no_description=True, deduplicate=False)
    else:
        for entry in config:
            name = entry.get("name", "") or ""
            description = entry.get("description")

            if name.startswith("POLICY-GROUP-"):
                # Specific policy group by ID
                log.info("Gathered: querying by ID %s", name)
                result = orchestrator.query_by_id(name)
                if result and orchestrator._is_active_user_group(result):
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

    # Pydantic is a hard runtime dependency for this module (argspec helpers,
    # orchestrator and model translation all rely on it).  Fail fast with the
    # standard Ansible ``missing_required_lib`` message if it is not
    # installed, so users get a clear error rather than a downstream
    # AttributeError from the pydantic_compat shim.
    require_pydantic(module)

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

        pending_deleted_cleanup_config = []
        if state == "deleted" and module.params.get("deploy"):
            # Keep the user's original delete intent before POLICY-GROUP-* ID
            # resolution drops already-absent active records.  Those entries
            # can be checked against policySummary for hidden markDeleted rows
            # and then unioned into the normal delete deploy.
            pending_deleted_cleanup_config = [dict(entry) for entry in config]

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
            if state == "deleted" and pending_deleted_cleanup_config:
                cleanup_candidates = _pending_cleanup_candidates(
                    pending_deleted_cleanup_config,
                    existing_groups,
                    log,
                )
                if cleanup_candidates:
                    orchestrator.schedule_pending_deleted_cleanup(cleanup_candidates)
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

        # Pre-flight template-input schema validation across every bucket
        # destined for a POST/PUT.  No-op for state=deleted (body never
        # carries templateInputs) and state=gathered (short-circuited
        # earlier). Invalid entries are removed from their execution bucket
        # and reported after valid entries have been processed.
        template_input_validation_failures: list[dict] = []
        if state == "merged":
            template_input_validation_failures = _validate_template_inputs_in_buckets(
                force_create_items=force_create_items,
                direct_action_items=direct_action_items,
                normal_config=normal_config,
                state=state,
                orchestrator=orchestrator,
                log=log,
            )
            module.params["config"] = normal_config

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
            direct_delete_models = []
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
                    direct_delete_models.append(model)
                    direct_actions_result["deleted"].append(model.model_dump(by_alias=False, exclude_none=True))
                    log.info("Direct-action: deleted policy group %s", pid)
            if state == "deleted" and direct_delete_models and not module.check_mode:
                orchestrator.delete_bulk(direct_delete_models)

        # Initialize and run StateMachine for normal items.  Deleted requests
        # can legitimately resolve to no active policy groups (for example an
        # unknown POLICY-GROUP-* ID that is already absent).  In that case,
        # avoid a second broad query_all from NDStateMachine initialization and
        # let the policySummary pending-delete cleanup pass below decide whether
        # any hidden markDeleted switches should still be deployed.
        nd_state_machine = None
        if state == "deleted" and not normal_config:
            log.info("Deleted state resolved to no active policy groups; skipping normal state-machine delete path.")
            result = {"changed": False}
        else:
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

        if state == "deleted" and pending_deleted_cleanup_config:
            pending_cleanup = orchestrator.deploy_scheduled_pending_deleted_cleanup()
            if pending_cleanup["changed"]:
                result["changed"] = True
                result["pending_deleted_cleanup"] = pending_cleanup

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

        if template_input_validation_failures:
            result["failed"] = True
            result["template_input_validation_failed"] = template_input_validation_failures
            failure_messages = []
            for failure in template_input_validation_failures:
                prefix = "config[{index}] (bucket={bucket}, identifier={identifier!r})".format(
                    index=failure["index"],
                    bucket=failure["bucket"],
                    identifier=failure["identifier"],
                )
                failure_messages.extend(f"{prefix}: {err}" for err in failure["errors"])
            module.fail_json(
                msg=("Template input validation failed for {0} entry/entries; " "valid entries were processed. {1}").format(
                    len(template_input_validation_failures),
                    "; ".join(failure_messages),
                ),
                **result,
            )

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
