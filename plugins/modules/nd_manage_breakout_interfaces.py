#!/usr/bin/python
# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage breakout parent families with optional collateral topology checks."""

from __future__ import annotations

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_breakout_interfaces
version_added: "2.0.0"
short_description: Break out and unbreak interfaces on Cisco Nexus Dashboard
description:
- Manage interface breakout on switches in a standalone fabric.
- Use a native parent for breakout. Unbreakout accepts the native parent or a breakout child selector and removes the whole breakout family.
- The module selects a verified existing child for the unbreakout API; a supplied child is a family alias, not a request to delete just one lane.
- On some switch models, Nexus Dashboard applies breakout and unbreakout configuration internally without a separate deployment call.
  These topology operations cannot be staged by this module.
- Hardware may couple several breakout parents. With verification enabled, unexpected changes to other breakout families
  fail the task and trigger an attempted direct inverse of the changed operation on the affected switch.
- Known policy-backed breakout child identities are included in verification even when physical discovery is still pending.
  Such controller intent is not proof that the corresponding physical interfaces have been discovered.
- Only switches reporting C(additionalData.platformType=nx-os) are supported.
  IOS-XE is rejected before mutation, including check mode.
author:
- L Nikhil Sri Krishna (@nisaikri)
options:
  fabric_name:
    description:
    - Name of the standalone fabric containing the switches.
    type: str
    required: true
  config:
    description:
    - Grouped switch and interface selector inputs. A non-empty list is required for O(state=merged) and O(state=deleted).
    - For O(state=overridden), a non-empty list scopes reconciliation to the named switches. Groups for the same switch
      contribute to one desired set of breakout parents.
    - For O(state=overridden), omitted config or an empty list selects the whole fabric and removes all existing breakouts.
      This is a fabric-wide, disruptive operation, not a no-op.
    type: list
    elements: dict
    default: []
    suboptions:
      switch_id:
        description:
        - Switch serial number or management IPv4 or IPv6 address.
        - Serial numbers are sent directly to the controller. Management IP addresses use the collection's shared switch-identity resolver.
        - Platform validation reuses management-IP lookup metadata.
          Serial inputs require a targeted switch-metadata lookup, cached per distinct switch within the task.
        type: str
        required: true
      interface_names:
        description:
        - List of native Ethernet parent names such as C(Ethernet1/50). O(state=merged) and O(state=overridden) accept parents only.
        - An empty list is allowed only for O(state=overridden), to remove every breakout on that selected switch.
        - O(state=deleted) also accepts children such as C(Ethernet1/50/2),
          as aliases for unbreaking the whole parent family.
        - When the family is broken out, a supplied child must be an observed member of that family.
          With verification enabled, known active child-policy intent may identify a member before physical discovery completes.
          When the parent is already native, deletion is a no-op even if the child no longer exists.
        - Repeating deletion with the former child, or alternating parent and child selectors across tasks, is a no-op once the parent is native.
          An entirely missing family is an error, not a no-op.
        - The API child is selected from observed children and may differ from the supplied child. No separate child lookup is required.
        - Dotted subinterfaces, four-part names, FEX interfaces and duplicate switch/family inputs are not accepted.
          A parent and its child cannot both be specified.
        type: list
        elements: str
        required: true
      breakout_map:
        description:
        - Map used when creating a new breakout, for example C(25g-4x).
        - Required for O(state=merged) and non-empty O(state=overridden) interface lists. Not required for overridden clear-only groups.
          Must be omitted for O(state=deleted).
        - O(state=merged) and O(state=overridden) leave existing breakouts unchanged even if the map differs. To change an existing map,
          explicitly unbreak the family with O(state=deleted), then create the desired breakout with O(state=merged).
        - Map capability is determined by Nexus Dashboard and the switch, not a module-specific hardware allowlist.
        type: str
  state:
    description:
    - V(merged) ensures that each requested parent is broken out. Existing breakouts are no-ops and are not remapped.
    - V(deleted) ensures that each requested parent family is unbroken, using either a parent or child selector.
      Native parents without breakout children are no-ops.
    - V(overridden) creates missing desired breakout parents first, then unbreaks omitted families within the selected scope.
      It does not replace profiles on existing breakouts.
    type: str
    default: merged
    choices: [merged, deleted, overridden]
  verify:
    description:
    - Optional whole-switch breakout topology checks after each executed action phase. Enabled by default.
    - When enabled, compare breakout parent identities and retained child sets from discovered inventory and known active interface intent,
      and attempt a direct inverse if unexpected collateral is observed.
    - When disabled, skip post-action topology reads, collateral comparisons, readiness waiting, recovery-map inference and compensation.
      Initial discovery, input and platform validation, idempotency and API response checks still apply.
    - This option does not expose retry, polling or timeout settings.
    type: dict
    suboptions:
      enabled:
        description:
        - Enable collateral topology checks and response-reported compensation. Disabling this option accepts unverified hardware-coupled side effects.
        type: bool
        default: true
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Only standalone fabrics and the V(merged), V(deleted) and V(overridden) states are supported.
- Platform eligibility is checked for explicitly selected switches before interface discovery.
  A fabric-wide overridden clear discovers current breakout families first, then checks the switches containing those families before mutation.
  Campus VXLAN fabrics are not rejected merely by fabric type; NX-OS switches remain eligible, while IOS-XE is unsupported.
- Missing, unrecognized or conflicting platform metadata fails safely.
  Multiple management-IP selectors resolving to the same switch must provide consistent platform evidence.
- NX-OS eligibility does not guarantee that a particular hardware model, port or breakout map is supported; the controller validates those capabilities.
- No C(config_actions), save/deploy controls, ticket or cluster parameters, or hardware-model-specific validation are exposed.
- Automatic map replacement and C(replaced) are not supported. Existing breakouts are not remapped, even when their requested map differs.
- Some switch models couple several breakout parent families. With O(verify.enabled=true), include every parent family intended to change.
  For example, if creating C(Ethernet1/21) also creates C(Ethernet1/23), list both parents to permit that coupled creation.
  Individual child lanes and disappearing native siblings such as C(Ethernet1/22) or C(Ethernet1/24) are not additional breakout parents to declare.
- For V(merged), unchanged unlisted breakout families are allowed. For V(overridden), include all coupled parents intended to remain broken out;
  unbreaking an omitted sibling must not remove or alter a retained desired family. For V(deleted), list every family intended to be unbroken.
- Listing all intended parents permits their topology changes but does not guarantee controller success for redundant coupled bulk requests.
  Complete API results are still required. Coupled ownership is not guessed from adjacent port numbers or switch models.
- With verification enabled, the guard checks breakout parent identities and retained child sets, not existing profile maps,
  interface settings, link state or collateral native-port presence.
- The baseline and post-action reads also include policy-backed child identities whose physical discovery is pending.
  A child requires a non-empty policy identifier and an explicit non-deleted marker to establish this controller-intent evidence.
  Existing intent-only families are part of the baseline, not newly created collateral.
  Unowned or marked-deleted configuration-only children do not establish breakout intent.
- An allowed breakout can therefore succeed without waiting for physical child discovery. Such records use
  C(evidence=controller_intent), rather than claiming independent physical topology convergence.
- On a collateral violation, compensation directly reverses changed entries of the violating action phase on the affected switch.
  Earlier validated phases and safe changes on other switches remain; this is not task-wide atomic rollback.
- The inverse of an unbreakout uses the original child count and uniform recognizable child speed to infer its profile locally.
  A profile that cannot be inferred for a planned unbreakout fails recovery readiness before mutation when verification is enabled.
  No policy, running-configuration or profile-discovery API is called to recover a map.
- Compensation normally matches per-item switch and interface identities. For a single inverse target only,
  one explicitly successful result from the expected switch may acknowledge recovery under a different interface name.
  The outcome preserves the submitted C(api_interface_name), exposes C(reported_interface_name), and sets C(identity_matched=false).
  Multiple-target recovery batches retain strict identity matching; one result cannot acknowledge several independent targets.
  No additional topology read verifies recovery; API acknowledgement is not proof that the original topology or configuration was restored.
- Before submitting an inverse, reuse the latest observation to check that its API target is usable.
  An inverse unbreakout requires a discovered physical child; an already ready child is preferred without another GET.
  An inverse breakout requires an explicit parent record, which may be controller-intent-only.
- A normal unbreakout with verification enabled has the same discovered-child prerequisite.
  If the initial family is intent-only, establish a usable child before sending the removal and inferring its recovery map.
  Check mode predicts the removal without waiting for discovery or requiring discovery-derived recovery speeds.
- Only when a required unbreakout or inverse target is not yet usable, perform targeted GET-only readiness checks for that original family.
  The internal loop uses a 90-second budget and a two-second interval; individual requests retain the standard transport timeout.
  Readiness failure leaves the pending unbreakout or inverse unattempted and the task failed.
  Neither the forward mutation nor an inverse is replayed.
  These checks occur before compensation, not after it, and do not verify recovery or wait for unrelated native siblings.
- If a forward request times out or returns HTTP 500, no inverse request is submitted even when the guard observes collateral,
  because the original operation may still be running. Recovery is reported as not attempted rather than verified restoration.
- Partial or unknown API outcomes without observed collateral fail without compensation or further overridden deletion.
  With verification disabled, no collateral compensation is attempted and final topology is not independently checked.
- With O(verify.enabled=false), overridden deletion targets come only from the initial baseline.
  Newly coupled families created during the task are not added to cleanup, even when they are absent from the desired config.
- An explicit deleted-then-merged map change is disruptive and non-atomic. The controller validates the new map when breakout is requested;
  failure may leave the family native. No automatic profile replacement or orchestrator-level write retry is performed.
  Requests use the collection's standard transport retry behavior.
- After unbreakout, interface-level configuration for restored or otherwise affected interfaces may remain pending
  even when the unbreakout itself has been applied.
- Manage that interface-level configuration separately with the appropriate Ethernet interface module,
  such as M(cisco.nd.nd_interface_ethernet_routed), M(cisco.nd.nd_interface_ethernet_access), or M(cisco.nd.nd_interface_ethernet_trunk_host).
- In those interface modules, C(config_actions.deploy=false) stages changes made by the task, while C(config_actions.deploy=true) deploys them.
  These controls do not stage the breakout or unbreakout itself and do not automatically deploy all previously pending interface intent.
- Complete identified API successes confirm the operation response, not an independently observed interface inventory, running configuration or breakout map.
- An uncertain or partial result is reported without a fabricated complete after-state.
  Forward API results are matched by switch and interface identity, not list position.
  The single-target recovery acknowledgement exception described above does not apply to forward requests.
- Standard snapshots and planned diff are always returned. Recovery responses do not turn a pre-recovery observation into a verified final snapshot.
  An empty C(after) with C(after_status=unknown) means that no reliable final snapshot is available,
  not that the interfaces were removed or restored.
- O(output_level=info) adds proposed intent. O(output_level=debug) adds proposed intent and logs.
  Neither proposed intent nor planned diff proves successful controller mutation.
- CLI verbosity C(-vv) adds write API paths and verbs; C(-vvv) adds full API diagnostics and the compact C(api_calls) trace.
- Check mode reads current state and reports planned actions without breakout or unbreakout requests.
- Duplicate aliases for one family are rejected before mutation, including parent/child inputs and IP/serial aliases that resolve to the same switch.
"""

EXAMPLES = r"""
- name: Break out two native parents using a switch serial number
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: merged
    config:
      - switch_id: FDO222425SE
        interface_names: [Ethernet1/50, Ethernet1/51]
        breakout_map: 25g-4x

- name: Break out a native parent without collateral topology verification
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: merged
    config:
      - switch_id: 192.0.2.10
        interface_names: [Ethernet1/50]
        breakout_map: 25g-4x
    verify:
      enabled: false

- name: Reconcile the desired coupled breakout parents on one selected switch
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: overridden
    config:
      - switch_id: FDO222425SE
        interface_names: [Ethernet1/21, Ethernet1/23]
        breakout_map: 25g-4x

- name: Use different creation maps for separate parents on one switch
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: merged
    config:
      - switch_id: FDO222425SE
        interface_names: [Ethernet1/50]
        breakout_map: 25g-4x
      - switch_id: FDO222425SE
        interface_names: [Ethernet1/51]
        breakout_map: 50g-2x

- name: Unbreak every family on one selected switch
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: overridden
    config:
      - switch_id: FDO222425SE
        interface_names: []

- name: Unbreak every family in the fabric
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: overridden
    config: []

- name: Omitting config has the same fabric-wide overridden clear scope
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: overridden

- name: Unbreak a native parent using the same parent-oriented input
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: deleted
    config:
      - switch_id: FDO222425SE
        interface_names: [Ethernet1/50]

- name: Explicitly unbreak the family before changing its map
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: deleted
    config:
      - switch_id: FDO222425SE
        interface_names: [Ethernet1/50]

- name: Create the new map after the preceding unbreakout succeeds
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: merged
    config:
      - switch_id: FDO222425SE
        interface_names: [Ethernet1/50]
        breakout_map: 50g-2x

- name: Unbreak a native parent using an IPv6 switch management address
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: deleted
    config:
      - switch_id: "2001:db8::10"
        interface_names: [Ethernet1/50]

- name: Unbreak the whole parent family using an existing child selector
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: deleted
    config:
      - switch_id: FDO222425SE
        interface_names: [Ethernet1/50/2]
"""

RETURN = r"""
output_level:
  description: Selected collection output level.
  returned: always
  type: str
  sample: normal
changed:
  description: Whether workflow evidence confirms a mutation, or whether check mode predicts a mutation.
  returned: always
  type: bool
before:
  description:
  - Canonical parent-family state read before any action, including when a child was supplied.
  - Guarded snapshots include scoped broken families and requested native parents, not every unrelated native Ethernet interface.
  - Policy-backed intent-only families are included and identified by C(evidence=controller_intent).
  - An empty list alone does not prove that a requested family is native; discovery may not have completed.
  returned: always
  type: list
after_status:
  description:
  - Provenance of the final state, one of C(unchanged), C(predicted), C(response_confirmed), C(observed), C(partially_observed) or C(unknown).
  - C(response_confirmed) is not an independent topology observation.
    An observation made before compensation is not verified final state after compensation.
  - C(partially_observed) combines fresh action-phase observations with initial-discovery evidence for switches not acted on.
  - C(observed) may include controller-intent records whose physical discovery is still pending; inspect each record's C(evidence).
  returned: always
  type: str
  sample: response_confirmed
after:
  description:
  - Final canonical parent state with its evidence source when sufficiently known. Empty when the response leaves affected state unknown.
  - An empty list with C(after_status=unknown) means no reliable snapshot is available, not an empty or restored interface inventory.
  - C(requested_breakout_map) records the submitted map, not an observed existing map. An unknown actual map is not fabricated.
  - C(evidence) identifies initial discovery, post-action discovery, controller intent, API response or prediction for each record.
    C(controller_intent) confirms known interface-policy identities, not physical discovery or switch running configuration.
    After API-confirmed creation, unknown child identities are omitted rather than represented as a fabricated empty child list.
  returned: always
  type: list
diff:
  description: Planned actionable delta. This is not a list of proven successful mutations; consult C(api_outcomes) and C(after_status).
  returned: always
  type: list
proposed:
  description: Grouped requested intent, including no-op parents and normalized child selectors.
    Requested maps are input intent, not independently observed existing maps.
  returned: when output_level is info or debug
  type: list
logs:
  description: Collection diagnostic logs.
  returned: when output_level is debug
  type: list
api_outcomes:
  description:
  - Parent-oriented action outcomes with the switch identity and the actual parent or child API interface name.
  - For child inputs, C(requested_interface_name) preserves the normalized supplied selector while C(interface_name) remains the canonical parent.
  returned: always
  type: list
  elements: dict
may_have_changed:
  description: Whether an uncertain outcome may have modified controller or device state.
  returned: always
  type: bool
api_calls:
  description: Method, path, HTTP status and timing for workflow API calls. Switch-resolution entries identify their purpose and may omit timing.
  returned: at CLI verbosity three or higher
  type: list
  elements: dict
verification:
  description:
  - Whether collateral verification is enabled, action-phase observation status and the protected breakout-family scope.
  - This records forward-action topology checks, not verification of compensation. No-op parents retain their initial evidence,
    including controller-intent evidence where applicable.
  - Known active child-policy intent participates in identity comparisons even when discovery flags are false.
  returned: after an action phase
  type: dict
recovery:
  description:
  - Direct inverse attempts for changed entries of a violating phase on an affected switch.
  - Per-item statuses are API acknowledgements, not independently verified restoration.
  - A single inverse target can accept one successful same-switch result under a different interface name.
    Such an outcome includes C(reported_interface_name) and C(identity_matched=false); C(topology_verified) remains false.
    Forward actions and multiple-target inverse batches retain strict identity matching.
  - Empty when no compensation is attempted. Successful recovery responses do not erase the original task failure or prove full configuration restoration.
  - If a required inverse target remains unusable or its readiness GET fails, report C(not_attempted) without submitting that inverse.
  returned: always
  type: list
  elements: dict
observed_before_recovery:
  description:
  - Last forward-action controller observation when collateral was detected, before any inverse request.
  - May contain policy-backed intent-only child identities; readiness polling does not replace this historical guard snapshot.
  - Contains scoped broken families and requested parents present in that observation, not every native Ethernet interface.
  - This is historical observation evidence, not the current topology after compensation. No recovery readback is performed.
  returned: when collateral topology is observed
  type: list
  elements: dict
"""

from typing import Any

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_breakout_interfaces.breakout_interface import (
    BreakoutInterfaceModel,
    validate_module_params,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_breakout_interfaces import ManageBreakoutInterfacesOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


def _format_output(module: AnsibleModule, report: dict[str, Any], results: Results | None = None) -> dict[str, Any]:
    """Use collection formatting without replacing authoritative workflow evidence."""
    output_level = module.params.get("output_level") or "normal"
    verbosity = getattr(module, "_verbosity", 0) or 0
    fields = dict(report)
    fields["output_level"] = output_level
    fields.setdefault("before", [])
    fields.setdefault("after", [])
    fields.setdefault("diff", [])
    fields.setdefault("after_status", "unknown")
    fields.setdefault("api_outcomes", [])
    fields.setdefault("recovery", [])
    if output_level not in {"info", "debug"}:
        fields.pop("proposed", None)
    if output_level != "debug":
        fields.pop("logs", None)
    if verbosity < 3:
        fields.pop("api_calls", None)
    formatter = NDOutput(output_level=output_level, state=module.params.get("state", "merged"))
    try:
        output = formatter.format_with_verbosity(verbosity, results, **fields)
    except Exception as error:  # pylint: disable=broad-except
        # Diagnostic aggregation must not erase primary operation results.
        output = formatter.format(**fields)
        output["warnings"] = [*output.get("warnings", []), f"Unable to format additional API diagnostics: {error}"]
    # The shared Results accumulator marks write requests as changed and may
    # report envelope failure. Only the workflow can interpret per-item evidence.
    output["changed"] = bool(report.get("changed", False))
    output["failed"] = bool(report.get("failed", False))
    return output


def _finish(module: AnsibleModule, report: dict[str, Any], results: Results | None = None) -> None:
    """Emit the same standard result shape on every business workflow path."""
    output = _format_output(module, report, results)
    if output["failed"]:
        output.setdefault("msg", "Interface breakout operation failed; review api_outcomes for partial or uncertain results")
        module.fail_json(**output)
        return
    module.exit_json(**output)


def main() -> None:
    """Run the breakout workflow without generic planned-state reconciliation."""
    argument_spec = nd_argument_spec()
    argument_spec.update(BreakoutInterfaceModel.get_argument_spec())
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    require_pydantic(module)
    try:
        validate_module_params(module.params)
    except (TypeError, ValueError) as error:
        _finish(module, {"msg": f"Configuration error: {error}", "changed": False, "failed": True, "may_have_changed": False})
        return

    try:
        setup_logging(module)
        sender = Sender()
        sender.ansible_module = module
        params = dict(module.params)
        params["fabric_name"] = params["fabric_name"].strip()
        params["check_mode"] = module.check_mode
        rest_send = RestSend(params)
        rest_send.sender = sender
        rest_send.response_handler = ResponseHandler()
        # The orchestrator guards every write itself. Real discovery GETs remain
        # necessary in check mode; RestSend's simulated response cannot classify them.
        rest_send.check_mode = False
        results = Results()
        results.state = params["state"]
        results.check_mode = module.check_mode
    except Exception as error:  # pylint: disable=broad-except
        _finish(module, {"msg": f"Module initialization failed: {error}", "changed": False, "failed": True, "may_have_changed": False})
        return
    orchestrator = None
    try:
        orchestrator = ManageBreakoutInterfacesOrchestrator(rest_send=rest_send, results=results)
        report = dict(orchestrator.run())
    except Exception as error:  # pylint: disable=broad-except
        # The workflow may already have confirmed sibling mutations. Reporting
        # failures must not replace those facts with a fresh changed=False result.
        report = dict(getattr(orchestrator, "report_snapshot", {}))
        report.setdefault("changed", False)
        report.setdefault("after_status", "unknown")
        report.setdefault("may_have_changed", orchestrator is not None)
        report.update(msg=f"Module execution failed: {error}", failed=True)
    _finish(module, report, results)


if __name__ == "__main__":
    main()
