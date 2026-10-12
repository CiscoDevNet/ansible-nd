#!/usr/bin/python
# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage interface breakout through response-first controller actions."""

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
- Hardware may couple several ports. The module does not promise that only the named parent will be affected.
- Only switches reporting C(additionalData.platformType=nx-os) are supported.
  IOS-XE is rejected before interface discovery or any mutation, including check mode.
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
    - Non-empty list of grouped switch and interface selector inputs.
    type: list
    elements: dict
    required: true
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
        - Non-empty list of native Ethernet parent names such as C(Ethernet1/50).
        - O(state=merged) accepts parent names only. O(state=deleted) also accepts children such as C(Ethernet1/50/2),
          as aliases for unbreaking the whole parent family.
        - When the family is broken out, a supplied child must be a discovered physical member.
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
        - Required for O(state=merged), and must be omitted for O(state=deleted).
        - O(state=merged) leaves existing breakouts unchanged even if the map differs. To change an existing map,
          explicitly unbreak the family with O(state=deleted), then create the desired breakout with O(state=merged).
        - Map capability is determined by Nexus Dashboard and the switch, not a module-specific hardware allowlist.
        type: str
  state:
    description:
    - V(merged) ensures that each requested parent is broken out. Existing breakouts are no-ops and are not remapped.
    - V(deleted) ensures that each requested parent family is unbroken, using either a parent or child selector.
      Native parents without breakout children are no-ops.
    type: str
    default: merged
    choices: [merged, deleted]
  verify:
    description:
    - Optional focused controller readback after executed actions. Disabled by default.
    - This option is specific to this module and does not expose the generic post-write verification prototype's retry settings.
    type: dict
    suboptions:
      enabled:
        description:
        - Enable focused post-action controller readback instead of relying only on completed per-item API results.
        type: bool
        default: false
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Only standalone fabrics and the V(merged) and V(deleted) states are supported.
- Platform eligibility is checked for every requested switch before interface discovery.
  Campus VXLAN fabrics are not rejected merely by fabric type; NX-OS switches remain eligible, while IOS-XE is unsupported.
- Missing, unrecognized or conflicting platform metadata fails safely.
  Multiple management-IP selectors resolving to the same switch must provide consistent platform evidence.
- NX-OS eligibility does not guarantee that a particular hardware model, port or breakout map is supported; the controller validates those capabilities.
- No C(config_actions), save/deploy controls, ticket or cluster parameters, or hardware-model-specific validation are exposed.
- Automatic map replacement and overridden state are not supported. No reliable hardware-coupled ownership model is implemented,
  and hardware coupling can affect interfaces outside the requested parents.
- An explicit deleted-then-merged map change is disruptive and non-atomic. The controller validates the new map when breakout is requested;
  failure may leave the family native. No automatic rollback or write retry is performed.
- After unbreakout, interface-level configuration for restored or otherwise affected interfaces may remain pending
  even when the unbreakout itself has been applied.
- Manage that interface-level configuration separately with the appropriate Ethernet interface module,
  such as M(cisco.nd.nd_interface_ethernet_routed), M(cisco.nd.nd_interface_ethernet_access), or M(cisco.nd.nd_interface_ethernet_trunk_host).
- In those interface modules, C(config_actions.deploy=false) stages changes made by the task, while C(config_actions.deploy=true) deploys them.
  These controls do not stage the breakout or unbreakout itself and do not automatically deploy all previously pending interface intent.
- Complete identified API successes confirm the operation response, not an independently observed interface inventory, running configuration or breakout map.
- An uncertain or partial result is reported without a fabricated complete after-state.
  API results are matched by switch and interface identity, not list position.
- Standard snapshots and planned diff are always returned. An empty C(after) with C(after_status=unknown) means that no reliable final snapshot is available,
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

- name: Break out a native parent using the switch management IP
  cisco.nd.nd_manage_breakout_interfaces:
    fabric_name: fab1
    state: merged
    config:
      - switch_id: 192.0.2.10
        interface_names: [Ethernet1/50]
        breakout_map: 25g-4x
    verify:
      enabled: true

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
  description: Canonical parent-family state read before any action, including when a child was supplied.
    Empty when discovery did not complete; this does not prove that the family is native.
  returned: always
  type: list
after_status:
  description:
  - Provenance of the final state, one of C(unchanged), C(predicted), C(response_confirmed), C(observed), C(partially_observed) or C(unknown).
  - C(response_confirmed) is not an independent topology observation.
    C(partially_observed) combines post-action readback for submitted parents with initial discovery for no-op parents.
  returned: always
  type: str
  sample: response_confirmed
after:
  description:
  - Final canonical parent state with its evidence source when sufficiently known. Empty when the response leaves affected state unknown.
  - An empty list with C(after_status=unknown) means no reliable snapshot is available, not an empty or restored interface inventory.
  - C(requested_breakout_map) records the submitted map, not an observed existing map. An unknown actual map is not fabricated.
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
  - Focused verification status, attempted logical parent scope and whether the observed topology matches the requested state.
  - No-op parents retain initial-discovery evidence rather than being described as newly observed.
  returned: when enabled after an action
  type: dict
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
    try:
        orchestrator = ManageBreakoutInterfacesOrchestrator(rest_send=rest_send, results=results)
        report = dict(orchestrator.run())
    except Exception as error:  # pylint: disable=broad-except
        report = {"msg": f"Module execution failed: {error}", "changed": False, "failed": True, "after_status": "unknown", "may_have_changed": True}
    _finish(module, report, results)


if __name__ == "__main__":
    main()
