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
- Nexus Dashboard applies breakout and unbreakout configuration internally without a separate deployment call.
  These topology operations cannot be staged by this module.
- Hardware may couple several breakout parents. With verification enabled, unexpected changes to other breakout families
  fail the task and trigger an attempt to undo the affected changes.
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
        - When the family is broken out, a supplied child must be an observed member of that family.
          With verification enabled, an active child recorded by Nexus Dashboard may be accepted before physical discovery finishes.
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
    - Checks cover breakout parents and their child interfaces on each affected switch.
      Unexpected changes fail the task and trigger an attempt to undo the affected operation.
    - Nexus Dashboard may record active breakout interfaces before switch discovery finishes.
      Verification uses these records without waiting for physical discovery to complete.
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
- With verification enabled, the module checks breakout parents and child interface names, not existing profile maps,
  interface settings, link state or collateral native-port presence.
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
  - C(observed) identifies the snapshot's provenance, not successful desired-state convergence.
    The task may still fail when a verification phase reports C(topology_matches=false).
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
  - A successful API acknowledgement does not establish the requested topology. With verification enabled,
    the task can fail if the requested changes cannot be confirmed.
  returned: always
  type: list
  elements: dict
may_have_changed:
  description: Whether an uncertain outcome may have modified controller or device state.
  returned: always
  type: bool
api_calls:
  description:
  - Method, path, HTTP status and timing for workflow API calls. Switch-resolution entries identify their purpose and may omit timing.
  - CLI verbosity C(-vv) adds write API paths and verbs; C(-vvv) adds full API diagnostics and the compact C(api_calls) trace.
  returned: at CLI verbosity three or higher
  type: list
  elements: dict
verification:
  description:
  - Reports whether verification is enabled, whether requested changes were observed and whether unintended changes were found.
  - Covers breakout and unbreakout checks. Recovery is reported separately under C(recovery).
  - Checks may use active breakout records before discovery finishes. No-op parents retain their initial evidence.
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
  - C(not_attempted) means that no recovery request was submitted for that target.
  returned: always
  type: list
  elements: dict
observed_before_recovery:
  description:
  - Last forward-action controller observation when collateral was detected, before any inverse request.
  - May include active breakout records whose physical discovery is still pending.
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
