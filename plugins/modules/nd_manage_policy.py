# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
---
module: nd_manage_policy
version_added: "2.0.0"
short_description: Manages policies on Cisco Nexus Dashboard (ND).
description:
- Manages template-based policies on Cisco Nexus Dashboard.
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
    - A list of dictionaries containing policy and switch information.
    - Required for C(merged) and C(deleted). Optional for C(gathered).
    - Use one of the following two config shapes. Do not mix the two shapes in the
      same O(config) list.
    - B(Two-level shape) - top-level policy entries define global policies, and one
      O(config[].switch) entry defines the target switches. Global policies apply to
      every switch in that switch list. A switch can also define
      O(config[].switch[].policies) for switch-specific policy overrides or additional
      policies.
    - In the two-level shape, when O(use_desc_as_key=false), a per-switch policy whose
      template name matches a global policy B(replaces) that global for the particular
      switch; per-switch entries with different template names are B(added) alongside
      the globals. When O(use_desc_as_key=true), global and per-switch policy entries
      are both emitted; there is no name-based replacement.
    - B(Gathered output shape) - each named policy entry includes its own
      O(config[].switch) list. This is the shape returned by O(state=gathered) and
      can be replayed with O(state=merged) or O(state=deleted).
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - Template name (for example, C(switch_freeform) or C(feature_enable)) or
          policy ID (for example, C(POLICY-121110)).
        - Template names are not unique policy identifiers. When
          O(use_desc_as_key=false), use a policy ID to update a specific existing
          policy.
        - In gathered output shape, O(config[].name) contains the template name and
          O(config[].policy_id) contains the controller-assigned policy ID.
        - For C(deleted) state, this is optional. When omitted, all policies
          on the specified switch are deleted.
        type: str
      policy_id:
        description:
        - Controller-assigned policy ID (e.g., C(POLICY-28440)).
        - Emitted in C(state=gathered) output alongside O(config[].name) (which carries
          the C(template_name)). In the gathered output shape, when the unmodified
          gathered output is replayed via C(state=merged) or C(state=deleted), this
          value is promoted to O(config[].name)
          before matching, so each policy is updated in place by ID.
        - This is B(not) an alias for O(config[].name).
        - Use snake-case O(config[].policy_id). C(policyId) is not an alias.
        - B(Scope) - only honored in the gathered output shape. In the two-level
          shape, use O(config[].name) with the C(POLICY-*) value to target a
          specific policy by ID.
        - To force fresh policy creation from gathered output, remove C(policy_id) values
          before replaying; matching will then fall back to (C(template_name), C(description))
          or (C(name), C(switch)) per the O(use_desc_as_key) mode.
        type: str
      description:
        description:
        - Description of the policy.
        - When O(use_desc_as_key=true), this is used as the unique identifier for the policy
          and must be non-empty and unique per switch for template-name entries.
        - When omitted in C(state=merged), the module sends an empty description.
          Include the existing description when updating by policy ID if it should
          be preserved.
        type: str
        default: ""
      priority:
        description:
        - Priority of the policy.
        - Valid range is 1-2000.
        - When omitted while creating a policy, the module uses the controller default of 500.
        - When omitted while updating an existing policy, the existing priority is preserved.
        type: int
      create_additional_policy:
        description:
        - A flag indicating if a policy is to be created even if an identical policy already exists.
        - When set to V(true), a new duplicate policy is created regardless of whether a matching one exists.
        - When set to V(false), duplicate creation is skipped if an identical policy already exists.
        - Most relevant when O(use_desc_as_key=false) and O(config[].name) is a template name.
          Also applies when O(config[].name) is a policy ID — if V(true) and no diff exists,
          the module creates a new copy of the policy (with a new ID) instead of skipping.
        type: bool
        default: true
      template_inputs:
        description:
        - Dictionary of name/value pairs passed to the policy template.
        - The required inputs depend on the template specified in O(config[].name).
        - When omitted, no template inputs are sent.
        type: dict
      switch:
        description:
        - A list of switches and optional per-switch policy overrides.
        - In the two-level shape, every switch in this list receives all global
          policies defined at the top level of O(config), plus any switch-specific
          O(config[].switch[].policies) entries.
        type: list
        elements: dict
        suboptions:
          serial_number:
            description:
            - Serial number of the target switch (e.g., C(FDO25031SY4)).
            - The backward-compatible C(ip) key is also accepted for this switch
              entry. It may be a switch management IPv4 address; the module resolves
              that value to the switch serial number via the fabric inventory before
              policy operations.
            type: str
            required: true
          policies:
            description:
            - A list of policies scoped to this switch in the two-level shape.
            - See O(config) for how per-switch policies interact with top-level
              global policies.
            - When omitted, no switch-specific policy overrides are applied.
            type: list
            elements: dict
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
                - When omitted while creating a policy, the module uses the controller default of 500.
                - When omitted while updating an existing policy, the existing priority is preserved.
                type: int
              create_additional_policy:
                description:
                - A flag indicating if a policy is to be created even if an identical policy already exists.
                type: bool
                default: true
              template_inputs:
                description:
                - Dictionary of name/value pairs passed to the policy template.
                - When omitted, no template inputs are sent.
                type: dict
  use_desc_as_key:
    description:
    - When set to V(true), policy descriptions are used as unique keys per switch.
    - Template-name entries must have non-empty descriptions that are unique per switch
      in the playbook and on the ND controller. Policy-ID entries, gathered output
      shape entries with O(config[].policy_id), and switch-only entries are exempt.
    - If a matching description exists and the template name changes, the module deletes
      the old policy and creates a new policy.
    - When set to V(false), matching uses the policy ID when O(config[].name) starts
      with C(POLICY-). Otherwise, template-name entries create policies and do not
      update existing policies in place because multiple policies can share a template
      name.
    - Duplicate or ambiguous descriptions are rejected before create, update, or delete
      operations are sent.
    type: bool
    default: false
  deploy:
    description:
    - When set to V(true), policies are deployed to devices after create/update/delete operations.
    - When set to V(false), controller-side changes are staged without deploying
      the corresponding config changes to devices.
    - For C(merged), create/update deploy uses the resource-level policy deploy
      operation scoped to the affected policy IDs. Entries that already match the
      controller are also deployed when O(deploy=true), but this no-diff deploy does
      not by itself mark the task changed.
    - If policy deploy fails after create or update, the policy record may already
      exist or be updated on the controller. Fix the deploy issue and rerun with
      O(deploy=true).
    - For C(deleted), the module attempts C(markDelete) first. PYTHON content-type
      policies such as C(switch_freeform) do not support C(markDelete), so the module
      retries only the C("content type PYTHON") failure with direct C(DELETE).
    - For C(deleted) with O(deploy=true), successful C(markDelete) or direct C(DELETE)
      operations are followed by one consolidated switch-level deploy operation for
      the affected switches. For C(deleted) with O(deploy=false), running config
      remains on the switch until a later deploy.
    - Policies successfully marked with C(markDelete) remain in C(markDeleted) state
      on the controller until switch-level deploy cleanup completes. PYTHON
      content-type policies that use the direct C(DELETE) fallback are removed from
      the controller, but their running config remains on the switch until deploy.
    - Switch-level deploy is also used for C(merged) replacement flows where
      O(use_desc_as_key=true) and the template name changes. Switch-level deploy
      pushes every pending configuration change staged for the targeted switches, not
      only the changes made by this task.
    - If an earlier delete ran with O(deploy=false), a later delete with
      O(deploy=true) can perform switch-level cleanup even when the policy is no
      longer visible in the active-policy view. The module does not perform extra
      validation reads to prove that a pending row exists. This requires the config
      to resolve to a switch ID and may also deploy a mistyped or already-clean
      target.
    type: bool
    default: true
  ticket_id:
    description:
    - Change Control Ticket ID to associate with create/update operations,
      C(markDelete), and direct C(DELETE) operations.
    - Required when Change Control is enabled on the ND controller.
    - B(Note) - policy deploy and switch-level deploy operations do not accept
      a C(ticketId) parameter, so deploy steps are B(not) bound to the supplied
      ticket. Only controller-side mutation operations carry the ticket.
    type: str
  cluster_name:
    description:
    - Target cluster name in a multi-cluster deployment.
    type: str
  state:
    description:
    - Use C(merged) to create or update policies from O(config).
    - Use C(deleted) to delete policies from O(config).
    - Use C(gathered) to export existing policies as playbook-compatible config.
      When O(config) is omitted, all active, user-manageable policies on all fabric
      switches are exported. When O(config) is provided, only matching active policies
      are exported.
      C(gathered) filters are switch-scoped in the current implementation, so provide
      a switch target using either the two-level shape or the gathered output shape when
      filtering. To export across the whole fabric, omit O(config).
      The output under the C(gathered) return key can be used directly as O(config)
      in a subsequent C(merged) task.
    - C(state=gathered) excludes policies with C(markDeleted=true) and
      generated/internal policies with non-empty C(source).
    - See O(deploy) for delete/deploy behavior.
    type: str
    choices: [ merged, deleted, gathered ]
    default: merged
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
seealso:
- module: cisco.nd.nd_rest
notes:
- The module is validation-first but not transactionally rolled back. Playbook
  schema validation, switch IP resolution, empty-description checks for
  O(use_desc_as_key=true), and duplicate description+switch checks run before
  write operations.
- O(config[].description) has C(default=""). When updating by policy ID, omitting
  O(config[].description) uses that default, so include the existing description
  if it should be preserved.
- Template-input validation is per-entry, so invalid policy entries are reported as
  failures while valid entries can still be created, updated, deleted, or deployed.
  The final task result is failed when any entry fails. Failures returned after
  write calls begin are reported in task output and may require a rerun or manual
  cleanup.
- C(state=gathered) and C(state=merged) idempotency checks use the active-policy
  view. Policies with C(markDeleted=true) and generated/internal policies with
  non-empty C(source) do not satisfy desired state, so replaying the same config
  creates or updates an active policy instead of becoming a no-op against a
  pending-delete or generated row.
"""

EXAMPLES = r"""
# EXAMPLE 1 — Per-switch extra policies (no name overlap with globals)
#
# NOTE: Three global policies (template_101, template_102, template_103) are defined.
#       switch1 also has per-switch policies template_104 and template_105. Since those
#       names do not match any global, they are ADDED alongside the globals.
#
#       Result:
#         switch1: template_101, template_102, template_103, template_104, template_105
#         switch2: template_101, template_102, template_103

- name: Create policies with per-switch extras
  cisco.nd.nd_manage_policy:
    fabric_name: "{{ fabric_name }}"
    state: merged
    deploy: true
    config:
      - name: template_101  # This must be a valid template name
        create_additional_policy: false  # Do not create a policy if it already exists
        priority: 101

      - name: template_102  # This must be a valid template name
        create_additional_policy: false  # Do not create a policy if it already exists
        description: "102 - No priority given"

      - name: template_103  # This must be a valid template name
        create_additional_policy: false  # Do not create a policy if it already exists
        description: "Both description and priority given"
        priority: 500

      - switch:
          - serial_number: "{{ switch1 }}"
            policies:
              - name: template_104  # Different name → added alongside globals
                create_additional_policy: false
              - name: template_105  # Different name → added alongside globals
                create_additional_policy: false
          - serial_number: "{{ switch2 }}"

# EXAMPLE 2 — Per-switch override (same template name replaces the global)
#
# NOTE: Three global policies (template_101, template_102, template_103) are defined.
#       switch1 overrides template_101 with a different priority and adds template_104.
#       Since template_101 matches a global, the global version is REPLACED for switch1.
#       template_104 does not match any global, so it is ADDED.
#
#       Result:
#         switch1: template_101 (priority 999), template_102, template_103, template_104
#         switch2: template_101 (priority 101), template_102, template_103

- name: Create policies with per-switch override
  cisco.nd.nd_manage_policy:
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
              - name: template_101  # Same name as global → REPLACES it for switch1
                create_additional_policy: false
                priority: 999
              - name: template_104  # Different name → ADDED alongside globals
                create_additional_policy: false
          - serial_number: "{{ switch2 }}"

# CREATE POLICY (including template inputs)

- name: Create policy including required template inputs
  cisco.nd.nd_manage_policy:
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
  cisco.nd.nd_manage_policy:
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
  cisco.nd.nd_manage_policy:
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
  cisco.nd.nd_manage_policy:
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
  cisco.nd.nd_manage_policy:
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
  cisco.nd.nd_manage_policy:
    fabric_name: "{{ fabric_name }}"
    state: deleted
    config:
      - name: POLICY-101101
      - name: POLICY-102102
      - switch:
          - serial_number: "{{ switch1 }}"

- name: Delete all policies on switches
  cisco.nd.nd_manage_policy:
    fabric_name: "{{ fabric_name }}"
    state: deleted
    config:
      - switch:
          - serial_number: "{{ switch1 }}"
          - serial_number: "{{ switch2 }}"

- name: Delete policies without deploying (mark for deletion only)
  cisco.nd.nd_manage_policy:
    fabric_name: "{{ fabric_name }}"
    state: deleted
    deploy: false
    config:
      - name: template_101
      - switch:
          - serial_number: "{{ switch1 }}"

# NOTE: switch_freeform policies are attempted through markDelete first. When
#       the controller rejects markDelete for a PYTHON content-type template,
#       the module retries that policy through direct DELETE. When deploy=true,
#       switch-level deploy pushes config removal to the switch. When
#       deploy=false, only the policy record is removed from the controller.

- name: Delete switch_freeform policies (direct DELETE fallback)
  cisco.nd.nd_manage_policy:
    fabric_name: "{{ fabric_name }}"
    state: deleted
    config:
      - name: switch_freeform
      - switch:
          - serial_number: "{{ switch1 }}"

- name: Delete policies using description as key
  cisco.nd.nd_manage_policy:
    fabric_name: "{{ fabric_name }}"
    use_desc_as_key: true
    state: deleted
    config:
      - name: switch_freeform
        description: "Enable LACP"
      - switch:
          - serial_number: "{{ switch1 }}"

- name: Gather all policies on all fabric switches (no config needed)
  cisco.nd.nd_manage_policy:
    fabric_name: "{{ fabric_name }}"
    state: gathered
  register: all_policies

- name: Gather only switch_freeform policies on a specific switch
  cisco.nd.nd_manage_policy:
    fabric_name: "{{ fabric_name }}"
    state: gathered
    config:
      - name: switch_freeform
      - switch:
          - serial_number: "{{ switch1 }}"
  register: freeform_policies

- name: Use gathered output to re-create policies on another fabric
  cisco.nd.nd_manage_policy:
    fabric_name: "{{ target_fabric }}"
    state: merged
    config: "{{ all_policies.gathered }}"

- name: Round-trip on the same fabric — gathered output updates existing policies in place by policy_id
  cisco.nd.nd_manage_policy:
    fabric_name: "{{ fabric_name }}"
    state: merged
    config: "{{ all_policies.gathered }}"

- name: Use gathered output to delete those exact policies by policy ID
  cisco.nd.nd_manage_policy:
    fabric_name: "{{ fabric_name }}"
    state: deleted
    config: "{{ all_policies.gathered }}"
"""

RETURN = r"""
changed:
  description:
  - Whether the module created, updated, deleted, or switch-deployed any policy.
  - No-diff C(merged) deploys of already matching policies do not by themselves
    mark the task changed.
  returned: always
  type: bool
before:
  description:
  - Active policy snapshots observed before mutation for entries that were changed
    or checked.
  returned: always
  type: list
  elements: dict
after:
  description:
  - Policy snapshots after successful creates or updates.
  - C(state=deleted) returns no deleted policies in C(after).
  returned: always
  type: list
  elements: dict
gathered:
  description:
  - Playbook-compatible active policy configuration returned by C(state=gathered).
  - Contains C(policy_id) so gathered output can be replayed to target the same
    controller policy directly.
  returned: when state is gathered and active policies match
  type: list
  elements: dict
proposed:
  description:
  - Desired policy payloads considered by the module.
  returned: when output_level is info or debug
  type: list
  elements: dict
warnings_nd:
  description:
  - Non-fatal ND warning messages captured from policy action responses.
  returned: when ND returns warnings
  type: list
  elements: str
api_path:
  description:
  - API paths called by the module, exposed at higher verbosity.
  returned: with -vv or higher
  type: list
  elements: str
api_payload:
  description:
  - API request payloads called by the module, exposed at higher verbosity.
  returned: with -vv or higher
  type: list
  elements: dict
api_diff:
  description:
  - Per-step action details, including create/update/delete/deploy decisions and
    per-entry failures.
  returned: with -vvv or higher
  type: list
  elements: dict
"""

# pylint: disable=logging-fstring-interpolation
import logging

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.log import Log
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    require_pydantic,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.config_models import (
    PlaybookPolicyConfig,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.nd_policy_resources import (
    NDPolicyModule,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule,
    NDModuleError,
    nd_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results


# =============================================================================
# Output helpers — ensure the error paths in main() produce exactly the same
# output shape as the success path (NDPolicyModule.exit_module()).  Keeping
# these as module-level free functions (rather than methods on
# NDPolicyModule) means the Exception branch can still produce a well-formed
# result even when the NDPolicyModule constructor itself failed.
# =============================================================================
def _module_verbosity(module: AnsibleModule) -> int:
    """Return the Ansible CLI verbosity for ``module`` (0 when unavailable).

    AnsibleModule._verbosity is a documented-ish attribute on the
    object but it has a leading underscore, so we guard the access.

    Args:
        module: The active :class:`AnsibleModule` instance.

    Returns:
        Integer 0..N matching ``-v`` / ``-vv`` / ``-vvv`` on the
        ansible CLI.  ``0`` when the attribute is unavailable.
    """
    return module._verbosity if hasattr(module, "_verbosity") else 0


def _format_module_result(
    module: AnsibleModule,
    output_level: str | None,
    results: Results,
    **kwargs,
) -> dict:
    """Format a final result dict using :class:`NDOutput`.

    Same shape contract as :meth:`NDPolicyModule.exit_module`: the
    helper exists so that the ``except NDModuleError`` and
    ``except Exception`` branches in :func:`main` produce identical
    top-level keys to the success path (``output_level``, ``changed``,
    ``before``, ``after``, ``diff`` + verbosity-gated ``api_*`` keys).

    Args:
        module: The active :class:`AnsibleModule` instance.
        output_level: ``output_level`` param value ("normal" / "info" /
            "debug"); ``None`` is normalised to ``"normal"``.
        results: The aggregated :class:`Results` instance.
        **kwargs: Forwarded to :meth:`NDOutput.format_with_verbosity`
            (e.g. ``before=[]``, ``after=[]``, ``error_details=...``).

    Returns:
        Dict ready to be ``**``-splatted into ``module.fail_json`` /
        ``module.exit_json``.
    """
    output = NDOutput(output_level=output_level or "normal")
    return output.format_with_verbosity(_module_verbosity(module), results, **kwargs)


def _record_failed_result(
    results: Results,
    message: str,
    return_code: int = -1,
    data: dict | None = None,
) -> None:
    """Stamp a single synthetic failure row onto ``results``.

    Used by :func:`main`'s ``except Exception`` branch when an
    unexpected error happens *outside* of an NDModule REST call (so
    there is no real response to capture).  Mirrors the synthetic
    response shape used by the rest of the module.

    Args:
        results: The aggregated :class:`Results` instance.
        message: Human-readable error message.
        return_code: HTTP-ish return code (defaults to ``-1`` for
            non-HTTP errors).
        data: Optional payload dict to attach under ``DATA``.

    Returns:
        None.
    """
    results.response_current = {
        "RETURN_CODE": return_code,
        "MESSAGE": message,
        "DATA": data if data is not None else {},
    }
    results.result_current = {"success": False, "found": False, "changed": False}
    results.diff_current = {}
    # Errors raised before any business operation has decided its type
    # are treated as writes (verbosity_level=2) so they remain visible
    # at -vv — same as a real failed write.
    results.verbosity_level_current = 2
    results.register_api_call()


def _record_nd_module_error_result(
    results: Results,
    nd: NDModule,
    error: NDModuleError,
    log: logging.Logger,
) -> None:
    """Stamp a single failure row for an :class:`NDModuleError` onto ``results``.

    Prefers the live response from ``nd.rest_send`` when available;
    falls back to fields on the error object.

    Args:
        results: The aggregated :class:`Results` instance.
        nd: The :class:`NDModule` REST client (may have a partial
            ``rest_send`` attribute).
        error: The :class:`NDModuleError` that bubbled out of
            :meth:`NDPolicyModule.manage_state`.
        log: Module-scoped logger.

    Returns:
        None.
    """
    try:
        results.response_current = nd.rest_send.response_current
        results.result_current = nd.rest_send.result_current
    except (AttributeError, ValueError) as exc:
        log.debug("rest_send.response_current unavailable: %s", exc)
        results.response_current = {
            "RETURN_CODE": error.status if error.status else -1,
            "MESSAGE": error.msg,
            "DATA": error.response_payload if error.response_payload else {},
        }
        results.result_current = {"success": False, "found": False}

    results.diff_current = {}
    # NDModuleErrors originate from a real REST call (a write or a
    # failed read); flag as a write so it surfaces at -vv alongside
    # other failed writes.
    results.verbosity_level_current = 2
    results.register_api_call()


# =============================================================================
# Main
# =============================================================================
def main():
    """Main entry point for the nd_manage_policy module."""

    argument_spec = nd_argument_spec()
    argument_spec.update(PlaybookPolicyConfig.get_argument_spec())

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
        log = logging.getLogger("nd.nd_manage_policy")
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
        log.info("Starting nd_manage_policy module: state=%s", state)

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
        log.info("State management completed successfully. Changed: %s", results.changed)
        policy_module.exit_json()

    except NDModuleError as error:
        log.error("NDModule error: %s", error.msg)

        _record_nd_module_error_result(results, nd, error, log)

        # ``error_details`` is debug-only; everything else flows through
        # the standard NDOutput shape so the failure looks like a normal
        # failed task to downstream playbooks.
        extra_kwargs: dict = {}
        if output_level == "debug":
            extra_kwargs["error_details"] = error.to_dict()

        final_result = _format_module_result(module, output_level, results, **extra_kwargs)
        log.error("Module failed: %s", final_result)
        module.fail_json(msg=error.msg, **final_result)

    except Exception as error:
        import traceback

        tb_str = traceback.format_exc()

        log.error("Unexpected error during module execution: %s", str(error))
        log.error("Error type: %s", error.__class__.__name__)

        try:
            _record_failed_result(
                results,
                message=f"Unexpected error: {str(error)}",
            )
            extra_kwargs: dict = {}
            if output_level == "debug":
                extra_kwargs["traceback"] = tb_str
            fail_kwargs = _format_module_result(module, output_level, results, **extra_kwargs)
        except Exception as fmt_error:  # pragma: no cover — last-resort safety net
            log.error("Failed to format error result: %s", fmt_error)
            fail_kwargs = {}
            if output_level == "debug":
                fail_kwargs["traceback"] = tb_str

        module.fail_json(msg=f"{error.__class__.__name__}: {str(error)}", **fail_kwargs)


if __name__ == "__main__":
    main()
