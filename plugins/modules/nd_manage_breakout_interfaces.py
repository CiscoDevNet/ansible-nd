#!/usr/bin/python
# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage breakout topology through a dedicated bulk-action workflow.

This module deliberately uses ManageBreakoutInterfacesOrchestrator rather than
NDStateMachine for state execution. The dedicated workflow does not update maps
of existing breakout families and, with verification enabled, checks each action
phase for collateral topology changes before continuing. Unexpected collateral
changes can trigger phase-specific, switch-scoped recovery attempts. In overridden state,
creation and its optional verification precede removal of omitted families.

The module continues to use the shared orchestrator base, REST transport,
response handling, Results, and NDOutput.
"""

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
- Breakout and unbreakout cannot be staged through this module.
- Hardware may couple several breakout parents. With verification enabled, unexpected changes to other breakout families
  fail the task and may trigger an attempt to undo the affected changes.
- Only NX-OS switches are supported. IOS-XE switches are rejected before changes, including in check mode.
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
    - Switches and interfaces to manage. A non-empty list is required for O(state=merged) and O(state=deleted).
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
        - Management IP addresses are translated internally to switch serial numbers.
        type: str
        required: true
      interface_names:
        description:
        - List of native Ethernet parent names such as C(Ethernet1/50). O(state=merged) and O(state=overridden) accept parents only.
        - An empty list is allowed only for O(state=overridden). Every breakout on a selected switch is removed
          when its combined desired interface list across all config entries is empty.
        - O(state=deleted) also accepts children such as C(Ethernet1/50/2),
          as aliases for unbreaking the whole parent family.
        - When a family is broken out, a supplied child must belong to that family in Nexus Dashboard.
          When the parent is already native, deletion is a no-op even if the child no longer exists.
        - Repeating deletion with the former child, or alternating parent and child selectors across tasks, is a no-op once the parent is native.
          An entirely missing family is an error, not a no-op.
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
        - Supported breakout maps depend on Nexus Dashboard and the switch.
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
    - Check for unintended breakout changes after each operation. Enabled by default.
    - Checks compare the breakout parent and child interface names reported by Nexus Dashboard on each affected switch.
      Unexpected changes fail the task and may trigger an attempt to undo the affected operation.
    - If all API results succeed but the expected changes are not yet visible, the module checks again every five seconds for up to 30 seconds,
      provided no unintended changes are found. Checks stop when the expected changes appear, unintended changes are found,
      an interface read fails, or time runs out. An interface read already in progress may finish after this limit.
    - When disabled, the module skips post-change interface checks, discovery waiting and automatic recovery.
      It still reads current state, validates inputs and platforms, skips operations already satisfied and checks API results.
    - No post-change verification runs when no changes are needed or in check mode.
    type: dict
    suboptions:
      enabled:
        description:
        - Enable checks for unintended breakout changes and attempted recovery.
          When disabled, hardware-coupled changes are not checked.
        type: bool
        default: true
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Only standalone fabrics and the V(merged), V(deleted) and V(overridden) states are supported.
- Campus VXLAN fabrics can contain supported NX-OS switches; IOS-XE switches are unsupported.
- The module fails before making changes if it cannot reliably determine a switch's platform.
- NX-OS eligibility does not guarantee that a particular hardware model, port or breakout map is supported; the controller validates those capabilities.
- No C(config_actions), save/deploy controls, ticket or cluster parameters are supported.
- Automatic map replacement and C(replaced) are not supported. Existing breakouts are not remapped, even when their requested map differs.
- Some switch models couple several breakout parent families. With O(verify.enabled=true), include every parent family intended to change.
  For example, if creating C(Ethernet1/21) also creates C(Ethernet1/23), list both parents to permit that coupled creation.
  Individual child lanes and disappearing native siblings such as C(Ethernet1/22) or C(Ethernet1/24) are not additional breakout parents to declare.
- For V(merged), unchanged unlisted breakout families are allowed. For V(overridden), include all coupled parents intended to remain broken out;
  unbreaking an omitted sibling must not remove or alter a retained desired family. For V(deleted), list every family intended to be unbroken.
- Listing all intended parents does not guarantee controller acceptance of redundant coupled requests.
- With verification enabled, the module checks breakout parent and child interface names reported by Nexus Dashboard.
  It does not check existing profile maps, interface settings, link state, switch running configuration or collateral native-port presence.
- When unintended changes are found, the module attempts to undo changes from that operation on the affected switch.
  Earlier successful operations and safe changes on other switches remain. Recovery does not undo the entire task.
- With verification enabled, unbreakout requires a discovered child interface and a breakout map that can be used for recovery.
  If the original breakout map cannot be determined, the task fails before unbreakout.
- Recovery results report whether Nexus Dashboard accepted the recovery request.
  Recovery is not independently verified; the module does not re-read interfaces to confirm restoration.
- With verification enabled, an unbreakout or recovery action may wait up to 90 seconds for the required interfaces to become available.
  An interface read already in progress may take longer. If the interfaces remain unavailable or an interface read fails,
  that action is not submitted and the task fails. These checks occur before the action and do not verify recovery.
- If a breakout or unbreakout request times out or returns HTTP 500, no recovery request is submitted,
  because the original operation may still be running.
- Partial or unknown API results without unintended changes fail the task without undoing accepted changes.
  In O(state=overridden), the module does not continue with further unbreakout operations.
- With O(verify.enabled=false), overridden only selects existing breakout families found before the task for removal.
  Additional families created through hardware coupling during the task are not automatically selected for removal.
- Changing a map requires unbreakout followed by breakout. This is disruptive, and failure may leave the family unbroken.
- After unbreakout, interface-level configuration for restored or otherwise affected interfaces may remain pending
  even when the unbreakout itself has been applied.
- Manage that interface-level configuration separately with the appropriate Ethernet interface module,
  such as M(cisco.nd.nd_interface_ethernet_routed), M(cisco.nd.nd_interface_ethernet_access), or M(cisco.nd.nd_interface_ethernet_trunk_host).
- In those interface modules, C(config_actions.deploy=false) stages changes made by the task, while C(config_actions.deploy=true) deploys them.
  These controls do not stage the breakout or unbreakout itself and do not automatically deploy all previously pending interface intent.
- Check mode reads current state and reports planned actions without breakout or unbreakout requests.
  It does not wait for discovery or require a recovery map.
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

- name: Unbreak a family using its parent name
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

- name: Unbreak a family using an IPv6 switch management address
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
  description: Selected collection output level, as specified by O(output_level).
  returned: always
  type: str
  sample: normal
changed:
  description:
  - Whether the workflow detected a change, or predicts a change in check mode.
  - Can remain V(true) when the task fails or attempts recovery; it does not describe only the net final difference.
  returned: always
  type: bool
  sample: true
failed:
  description: Whether the task failed, including incomplete API results or unsuccessful verification.
  returned: always
  type: bool
  sample: false
msg:
  description: Human-readable failure details. Inspect C(api_outcomes), C(verification) and C(recovery), when present, for additional context.
  returned: on failure
  type: str
  sample: "Configuration error: config must be a non-empty list"
before:
  description:
  - Parent-family records read before any breakout or unbreakout action. C(interface_name) is the parent name even when deletion selects a child.
  - Contains requested parents and, when required for reconciliation or verification, other existing breakout families in scope.
    It is not a complete interface inventory.
  - Each record includes C(switch_id), C(interface_name), C(broken_out), C(children) and C(evidence).
    C(evidence=controller_intent) identifies interfaces recorded by Nexus Dashboard whose physical discovery is not confirmed.
  - Can be empty when discovery has not completed or no scoped records exist. An empty list alone does not prove that a requested parent is native.
  returned: always
  type: list
  elements: dict
  sample:
  - switch_id: FDO28481BXX
    interface_name: Ethernet1/50
    broken_out: false
    children: []
    evidence: initial_discovery
after_status:
  description:
  - Describes the source of C(after), not whether the task succeeded.
  - C(unchanged) uses the initial state when no action was needed. C(predicted) identifies check-mode output, including check-mode no-ops.
  - C(response_confirmed) derives changed records from successful API results without an independent post-action interface read.
  - C(observed) uses post-action interface reads. C(partially_observed) combines fresh action-phase observations with
    initial-discovery evidence for switches not acted on.
  - Observations may include C(evidence=controller_intent) records whose physical discovery is not confirmed.
    C(observed) can accompany a failed task; consult C(failed) and C(verification).
  - C(unknown) means no reliable final snapshot is available. An observation made before recovery does not verify the state after recovery.
  returned: always
  type: str
  sample: observed
after:
  description:
  - Parent-family records representing the final state supported by the available evidence, or the predicted state in check mode.
    Uses singular C(interface_name), as in C(before).
  - C(evidence) identifies the source of each record as C(initial_discovery), C(post_action_discovery), C(controller_intent),
    C(api_response) or C(prediction). Controller intent does not confirm physical discovery or switch running configuration.
  - C(children) is optional and lists the identified child interfaces when included.
    It can be omitted in API-derived or predicted records, including a successful unbreakout with verification disabled.
  - C(requested_breakout_map), when present, records the requested map; it is not an independently observed existing map.
  - An empty list with C(after_status=unknown) means no reliable snapshot is available, not an empty or restored interface inventory.
  returned: always
  type: list
  elements: dict
  sample:
  - switch_id: FDO28481BXX
    interface_name: Ethernet1/50
    broken_out: true
    children: [Ethernet1/50/1, Ethernet1/50/2, Ethernet1/50/3, Ethernet1/50/4]
    evidence: post_action_discovery
diff:
  description:
  - Groups of interfaces planned for breakout or unbreakout, using C(switch_id), plural C(interface_names) and, for breakout, C(breakout_map).
  - Excludes no-op parents. In C(overridden), may contain both creation and removal groups.
  - Describes planned actions, not proven successful changes; consult C(api_outcomes), C(after_status) and C(failed).
  returned: always
  type: list
  elements: dict
  sample:
  - switch_id: FDO28481BXX
    interface_names: [Ethernet1/50]
    breakout_map: 25g-4x
proposed:
  description:
  - Grouped requested configuration, including no-op parents and normalized child selectors.
  - Uses plural C(interface_names), unlike the parent records in C(before) and C(after).
    Requested maps describe input intent, not independently observed existing maps.
  - For switch-scoped C(overridden), an empty C(interface_names) list represents a selected switch with no desired breakouts.
  returned: when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
  sample:
  - switch_id: FDO28481BXX
    interface_names: [Ethernet1/50]
    breakout_map: 25g-4x
logs:
  description: Diagnostic messages supplied to the collection output formatter. This module currently returns an empty list.
  returned: when O(output_level) is V(debug)
  type: list
  elements: str
  sample: []
api_outcomes:
  description:
  - Forward-action results identified by C(switch_id) and the canonical parent C(interface_name).
    C(api_interface_name) identifies the parent or child used for the API request, or is null for a no-op.
  - C(outcome) is C(success), C(failed), C(unknown), C(noop) or C(planned). C(planned) identifies an action predicted in check mode.
  - For child inputs, C(requested_interface_name) preserves the normalized supplied selector.
    A C(breakout_map), when present, is the requested map.
  - A successful API acknowledgement does not establish the requested topology or overall task success.
    Recovery results are reported separately under C(recovery).
  returned: always
  type: list
  elements: dict
  sample:
  - switch_id: FDO28481BXX
    interface_name: Ethernet1/50
    api_interface_name: Ethernet1/50
    breakout_map: 25g-4x
    action: breakout
    outcome: success
    message: Action completed
may_have_changed:
  description:
  - Whether the workflow reports that an uncertain outcome or recovery attempt may have changed controller or device state.
  - This flag is independent of C(changed). A successful task can return C(changed=true) and C(may_have_changed=false).
  returned: always
  type: bool
  sample: false
api_calls:
  description:
  - Compact workflow API trace with C(method), C(path), C(http_status), C(elapsed_seconds) and C(response_received).
    Entries for switch metadata can also include C(purpose) and C(transport_error).
  - An unavailable HTTP status or timing can be null. An empty trace means no workflow requests were recorded.
  returned: at CLI verbosity C(-vvv) or higher, when a workflow API trace is available
  type: list
  elements: dict
  sample:
  - method: POST
    path: /api/v1/manage/fabrics/fab1/interfaceActions/breakout
    http_status: 207
    elapsed_seconds: 0.001
    response_received: true
api_paths:
  description:
  - Paths of recorded API requests. At C(-vv), includes qualifying write requests; at C(-vvv) or higher, includes reads and writes.
  - Corresponding entries in C(api_verbs), C(api_response), C(api_result), C(api_diff), C(api_metadata) and C(api_payload)
    refer to the same recorded request.
  returned: at CLI verbosity C(-vv) or higher, when qualifying API diagnostics are available
  type: list
  elements: str
  sample: [/api/v1/manage/fabrics/fab1/interfaceActions/breakout]
api_verbs:
  description: HTTP methods corresponding to C(api_paths), with the same verbosity filtering.
  returned: at CLI verbosity C(-vv) or higher, when qualifying API diagnostics are available
  type: list
  elements: str
  sample: [POST]
api_response:
  description: Response dictionaries for recorded API requests. Discovery responses may be compacted in the collection diagnostics.
  returned: at CLI verbosity C(-vvv) or higher, when qualifying API diagnostics are available
  type: list
  elements: dict
  sample:
  - RETURN_CODE: 207
    METHOD: POST
    REQUEST_PATH: /api/v1/manage/fabrics/fab1/interfaceActions/breakout
    MESSAGE: OK
    DATA:
      results:
      - switchId: FDO28481BXX
        interfaceName: Ethernet1/50
        status: Success
        message: Action completed
    sequence_number: 3
api_result:
  description:
  - Shared response-handler results for recorded requests.
  - Use top-level C(changed), C(failed) and C(api_outcomes) for the workflow result.
  returned: at CLI verbosity C(-vvv) or higher, when qualifying API diagnostics are available
  type: list
  elements: dict
  sample:
  - success: true
    changed: true
    retryable: false
    sequence_number: 3
api_diff:
  description: Per-request diagnostic differences from the collection result accumulator, separate from the planned actions in C(diff).
  returned: at CLI verbosity C(-vvv) or higher, when qualifying API diagnostics are available
  type: list
  elements: dict
  sample:
  - sequence_number: 3
api_metadata:
  description: Action, state, check-mode and sequence metadata for recorded API requests.
  returned: at CLI verbosity C(-vvv) or higher, when qualifying API diagnostics are available
  type: list
  elements: dict
  sample:
  - action: create
    check_mode: false
    sequence_number: 3
    state: merged
api_payload:
  description: Payloads for recorded API requests. Each entry can be a dictionary, a list or null, including null for GET requests.
  returned: at CLI verbosity C(-vvv) or higher, when qualifying API diagnostics are available
  type: list
  elements: raw
  sample:
  - interfaces:
    - switchId: FDO28481BXX
      interfaceName: Ethernet1/50
      breakoutMap: 25g-4x
verification:
  description:
  - Post-action interface-check results. Returned only after a submitted action with O(verify.enabled=true), including actions with failed API results.
  - C(enabled) is V(true). C(complete) indicates whether the interface snapshots needed for verification were obtained;
    it does not mean that the requested topology matched or that the task succeeded.
  - C(phases) contains per-switch records with C(phase) set to C(breakout) or C(unbreakout), C(topology_matches),
    and a C(collateral) list describing unintended changes.
  - Check results can use C(controller_intent) records. No-op parents retain their initial evidence. Recovery is reported under C(recovery).
  returned: after an action is submitted with O(verify.enabled=true); omitted for no-op runs, check mode and disabled verification
  type: dict
  sample:
    enabled: true
    complete: true
    phases:
    - switch_id: FDO28481BXX
      phase: breakout
      collateral: []
      topology_matches: true
recovery:
  description:
  - Per-switch recovery records created when verification detects unintended changes. Empty when no such recovery records were created.
  - C(phase) identifies the original operation and C(action) its inverse. C(status) is C(not_attempted), C(unknown), C(failed) or C(response_confirmed).
  - C(not_attempted) means no inverse request was submitted; a record can exist with an empty C(api_outcomes) list.
    C(response_confirmed) means the inverse API reported success. C(msg), when present, explains the result.
  - C(topology_verified) remains V(false). Recovery is not independently verified and does not clear the original task failure.
  - A successful single-target inverse result can include C(reported_interface_name) and C(identity_matched=false)
    when Nexus Dashboard reports another interface on the same switch. This is an API acknowledgement, not proof of restoration.
  returned: always
  type: list
  elements: dict
  sample: []
observed_before_recovery:
  description:
  - Parent-family records available when unintended changes were detected, before any inverse request, using the same record shape as C(before).
  - Includes scoped breakout families and requested parents present in that snapshot. Untouched switches can retain initial-discovery evidence;
    records with C(evidence=controller_intent) do not confirm physical discovery.
  - This is historical observation evidence, not the current topology after compensation. It can be returned even when no inverse could be submitted.
  returned: when verification detects unintended topology changes
  type: list
  elements: dict
  sample:
  - switch_id: FDO28481BXX
    interface_name: Ethernet1/21
    broken_out: true
    children: [Ethernet1/21/1, Ethernet1/21/2, Ethernet1/21/3, Ethernet1/21/4]
    evidence: post_action_discovery
  - switch_id: FDO28481BXX
    interface_name: Ethernet1/23
    broken_out: true
    children: [Ethernet1/23/1, Ethernet1/23/2, Ethernet1/23/3, Ethernet1/23/4]
    evidence: post_action_discovery
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
    """Run the dedicated breakout workflow described in the module docstring."""
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
