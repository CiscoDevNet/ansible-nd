# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
---
module: nd_manage_smart_switches_onboarding
version_added: "1.6.0"
short_description: Manage Smart Switch onboarding on Cisco Nexus Dashboard
description:
- Onboard inventory-present Smart Switches to Cisco Hypershield integrations and deboard existing associations.
- Reconcile individual controller-confirmed results, including partial success in a bulk onboarding request.
- Deboard listed or omitted associations in one fabric-scoped bulk request.
- This module manages onboarding associations, not physical switch discovery or inventory removal.
author:
- Gaspard Micol (@gmicol)
options:
  fabric_name:
    description: Fabric containing all switches managed by this invocation.
    type: str
    required: true
  cluster_name:
    description: Optional Nexus Dashboard cluster routing parameter.
    type: str
  config:
    description:
    - Desired switch associations, identified by exact switch serial numbers.
    - An explicit empty list with O(state=overridden) deboards all onboarded Smart Switches in the selected fabric.
    - An empty list with O(state=replaced) or O(state=deleted) performs no mutation.
    type: list
    elements: dict
    required: true
    suboptions:
      switch_id:
        description: Exact inventory switch identifier (serial number). Matching is case-sensitive.
        type: str
        required: true
      integration_name:
        description:
        - Cisco Hypershield integration name, not the Hypershield tenant name.
        - Required with O(state=replaced) and O(state=overridden).
        - Not required with O(state=deleted).
        type: str
      switch_name:
        description:
        - Optional switch hostname, populated from fabric inventory when omitted.
        - When supplied, it must match the inventory hostname for O(config.switch_id).
        - Hostname is payload metadata, not managed association identity.
        type: str
  state:
    description:
    - V(replaced) onboards listed switches without altering omitted associations.
    - V(overridden) onboards listed switches, then deboards existing associations omitted from O(config).
    - V(deleted) deboards only the listed onboarded switches; absent associations are no-ops.
    - An existing association to the requested integration is retained without a write.
    - A listed switch associated to a different integration is rejected before any mutation; updating associations is unsupported.
    type: str
    default: replaced
    choices: [replaced, overridden, deleted]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Requires Nexus Dashboard 4.2.1 or later and Smart-capable switches already present in fabric inventory.
- For bulk onboarding, HTTP 202 acceptance alone does not establish success. Per-switch success and failure lists determine confirmed effects.
- For bulk deboarding, a bodyless HTTP 202 confirms every requested deboarding effect. An unexpected response body is treated as unknown.
- Partial success fails the task with C(changed=true), preserves successful effects, and reports both successful and failed switches.
- Unknown results or delivery failures omit C(after) and C(diff); C(changed=false) in that case means no change was proven, not proven unchanged.
- Check mode performs reads and validation only. Its C(after) and C(diff) are planned predictions, identified by C(after_status=planned).
- No rollback, automatic mutation replay, post-write readback, or general update operation is performed.
- After a failure, remaining planned requests are not attempted. A subsequent invocation reads a fresh inventory snapshot.
"""

EXAMPLES = r"""
- name: Onboard listed Smart Switches without removing other associations
  cisco.nd.nd_manage_smart_switches_onboarding:
    fabric_name: fabric_1
    state: replaced
    config:
      - switch_id: SAL1948TRST
        integration_name: hypershield-production
        switch_name: leaf1

- name: Enforce the selected fabric's onboarding associations
  cisco.nd.nd_manage_smart_switches_onboarding:
    fabric_name: fabric_1
    state: overridden
    config:
      - switch_id: SAL1948TRST
        integration_name: hypershield-production

- name: Deboard a listed Smart Switch
  cisco.nd.nd_manage_smart_switches_onboarding:
    fabric_name: fabric_1
    state: deleted
    config:
      - switch_id: SAL1948TRST

- name: Preview deboarding every onboarded Smart Switch in a fabric
  cisco.nd.nd_manage_smart_switches_onboarding:
    fabric_name: isolated_test_fabric
    state: overridden
    config: []
  check_mode: true
"""

RETURN = r"""
changed:
  description: Whether a mutation effect was confirmed, or predicted in check mode. Independent of task failure.
  returned: always
  type: bool
failed:
  description: Whether execution failed, including per-switch failures within HTTP 202 responses.
  returned: always
  type: bool
before:
  description: Initial onboarded associations in the selected fabric.
  returned: after successful initial-state discovery
  type: list
  elements: dict
  sample: [{switch_id: SAL1948TRST, switch_name: leaf1, integration_name: hypershield-production}]
after:
  description:
  - Confirmed associations after execution, containing only proven successful effects.
  - In check mode this is prospective state, not controller-confirmed state.
  - Omitted when any final-state uncertainty remains.
  returned: when final state is known, or in check mode
  type: list
  elements: dict
after_status:
  description: Snapshot confidence, one of C(confirmed), C(planned), or C(unknown).
  returned: after state-machine initialization
  type: str
diff:
  description:
  - Snapshot dictionary with C(before) and C(after) lists when known state differs.
  - An empty list when known state is unchanged; omitted when final state is unknown.
  returned: when final state is known, or in check mode
  type: raw
diff_status:
  description: Confidence of the diff, matching C(after_status).
  returned: after state-machine initialization
  type: str
action_results:
  description:
  - Every attempted resource's identifier, operation, outcome, statuses, messages, correlation evidence, and effect confirmation.
  - Includes successful and failed switches on task failure. Empty for no-op and check-mode execution.
  returned: after state-machine initialization
  type: list
  elements: dict
  sample:
  - identifier: SAL1948TRST
    operation: create
    outcome: succeeded
    effect_confirmed: true
    statuses: [SUCCESS]
    messages: [Onboarding successful]
    correlation: [{source: successResults, returned_name: SAL1948TRST, match: exact_switch_id}]
planned_operations:
  description: Planned identifiers and operations with outcomes, including C(not_attempted) requests skipped after failure.
  returned: after successful planning
  type: list
  elements: dict
may_have_changed:
  description: Whether additional, unconfirmed effects may have occurred. Can be true together with C(changed=true).
  returned: after state-machine initialization
  type: bool
reconciliation_complete:
  description: Whether the selected final-state view is known. Check-mode state is still explicitly labeled planned.
  returned: after state-machine initialization
  type: bool
unknown_identifiers:
  description: Requested identifiers whose effects cannot be reconciled exactly.
  returned: after state-machine initialization
  type: list
  elements: str
mutation_errors:
  description: Request-level semantic or delivery errors, in addition to per-resource messages.
  returned: after state-machine initialization
  type: list
  elements: str
proposed:
  description: Prepared desired association configuration.
  returned: when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
msg:
  description: Explanation of task failure.
  returned: on failure
  type: str
"""

import logging

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_onboarding import SmartSwitchOnboardingModel
from ansible_collections.cisco.nd.plugins.module_utils.module_failure import fail_from_exception
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.smart_switches_onboarding import SmartSwitchOnboardingOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


def main() -> None:
    """Run association reconciliation and preserve partial results through fail_json."""
    argument_spec = nd_argument_spec()
    argument_spec.update(SmartSwitchOnboardingModel.get_argument_spec())
    argument_spec.update(fabric_name={"type": "str", "required": True}, cluster_name={"type": "str"})
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_manage_smart_switches_onboarding")
    nd_state_machine = None
    try:
        sender = Sender()
        sender.ansible_module = module
        transport = RestSend({**module.params, "check_mode": module.check_mode})
        transport.sender = sender
        transport.response_handler = ResponseHandler()
        orchestrator = SmartSwitchOnboardingOrchestrator(
            rest_send=transport, fabric_name=module.params["fabric_name"], cluster_name=module.params.get("cluster_name")
        )
        prepared = orchestrator.prepare_config_data(module.params["config"])
        nd_state_machine = NDStateMachine(module, orchestrator, config=prepared)
        nd_state_machine.manage_state()
        module.exit_json(**nd_state_machine.output.format_with_verbosity(getattr(module, "_verbosity", 0), nd_state_machine.results))
    except Exception as error:  # pylint: disable=broad-except
        fail_from_exception(module, module_log, nd_state_machine, error)


if __name__ == "__main__":
    main()
