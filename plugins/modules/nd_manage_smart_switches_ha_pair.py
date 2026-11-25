#!/usr/bin/python
# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Manage high availability pairings between Smart Switches in one fabric."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: nd_manage_smart_switches_ha_pair
short_description: Manage Smart Switch HA pairs in a Nexus Dashboard fabric
version_added: "2.0.0"
description:
  - Manage high availability (HA) associations between two Smart Switches in the selected fabric.
  - Supports both physical vPC peers and standalone switches with a discovered physical link.
author:
  - Gaspard Micol (@gmicol)
options:
  fabric_name:
    description: Fabric containing the Smart Switches.
    type: str
    required: true
  cluster_name:
    description: Target Nexus Dashboard cluster in a multi-cluster deployment.
    type: str
  config:
    description:
      - Pairs identified by their two exact, case-sensitive switch serial numbers. Peer order is interchangeable.
      - Required for V(replaced), V(overridden), and V(deleted). Each switch may appear in only one entry.
      - An explicit empty list with O(state=overridden) unpairs every HA association in the selected fabric.
      - An empty list with O(state=replaced) or O(state=deleted) makes no changes.
      - With O(state=gathered), omit O(config) or pass an empty list to gather all pairs.
    type: list
    elements: dict
    suboptions:
      switch_id:
        description: Exact serial number of one Smart Switch.
        type: str
        required: true
      peer_switch_id:
        description: Exact serial number of the other Smart Switch.
        type: str
        required: true
  state:
    description:
      - V(replaced) ensures the listed pairs exist and retains other associations.
      - V(overridden) ensures the listed pairs exist and unpairs omitted associations.
      - V(deleted) unpairs the specified associations. Absent associations are a no-op.
      - V(gathered) returns each pair whose controller status is C(paired) or C(pairPending) once.
    type: str
    choices: [replaced, overridden, deleted, gathered]
    default: replaced
  config_actions:
    description:
      - Controls recalculation and deployment after changes made by this task.
      - Deploy staged intent from an earlier task explicitly through Nexus Dashboard.
      - In V(gathered), any enabled save or deploy action is rejected.
    type: dict
    suboptions:
      save:
        description: Recalculate the fabric configuration after the HA changes.
        type: bool
        default: false
      deploy:
        description:
          - Deploy pending configuration after this task changes HA intent.
          - Set O(config_actions.save=true) to request deployment.
        type: bool
        default: false
      type:
        description:
          - V(switch) targets both peers of each changed HA pair. It can apply other pending configuration on those switches.
          - V(global) deploys pending configuration across the fabric.
        type: str
        choices: [switch, global]
        default: switch
extends_documentation_fragment:
  - cisco.nd.modules
  - cisco.nd.check_mode
notes:
  - Requires Nexus Dashboard 4.3.1 or later and a supported NX-OS fabric with Smart Switch HA configured.
  - To change a switch's peer, unpair and deploy the existing association first. Wait until Nexus Dashboard reports the switch as unpaired.
  - An identifiable pending vPC unpair can be reversed with V(replaced). Let a standalone pending unpair finish before pairing again.
  - Pair, unpair, and gathered report controller intent. Pending HA states can persist until the switches confirm deployment.
  - On partial failure, confirmed effects are retained. When an effect is uncertain, the final snapshot and diff are omitted.
"""

EXAMPLES = r"""
- name: Stage an HA pair
  cisco.nd.nd_manage_smart_switches_ha_pair:
    fabric_name: vxlan_fabric
    state: replaced
    config:
      - switch_id: FDO292004MB
        peer_switch_id: FDO292004NH

- name: Keep one HA pair and explicitly deploy changes to affected peers
  cisco.nd.nd_manage_smart_switches_ha_pair:
    fabric_name: vxlan_fabric
    state: overridden
    config_actions:
      save: true
      deploy: true
    config:
      - switch_id: FDO292004MB
        peer_switch_id: FDO292004NH

- name: Stage removal of one HA pair
  cisco.nd.nd_manage_smart_switches_ha_pair:
    fabric_name: vxlan_fabric
    state: deleted
    config:
      - switch_id: FDO292004MB
        peer_switch_id: FDO292004NH

- name: Gather current HA pair intent
  cisco.nd.nd_manage_smart_switches_ha_pair:
    fabric_name: vxlan_fabric
    state: gathered
  register: fabric_ha_pairs
"""

RETURN = r"""
changed:
  description: Whether the controller accepted a change to HA intent, or check mode predicts one.
  returned: always
  type: bool
failed:
  description: Whether validation, reconciliation, or a requested config action failed.
  returned: always
  type: bool
gathered:
  description: Sorted pairs in O(config) format. Includes associations in C(paired) or C(pairPending) and is empty when neither state is present.
  returned: when O(state=gathered)
  type: list
  elements: dict
  sample: [{switch_id: FDO292004MB, peer_switch_id: FDO292004NH}]
before:
  description: Initial controller intent for the fabric. Empty in gathered output.
  returned: after state-machine initialization
  type: list
  elements: dict
after:
  description: Resulting controller intent, or prospective intent in check mode. Empty in gathered output.
  returned: after state-machine initialization when final state is known, or in check mode
  type: list
  elements: dict
diff:
  description: Before and after snapshots when intent differs, or an empty list when unchanged.
  returned: after planning a write state when final state is known, or in check mode
  type: raw
after_status:
  description: Snapshot confidence. One of C(confirmed), C(planned), or C(unknown).
  returned: after state-machine initialization
  type: str
diff_status:
  description: Snapshot confidence matching C(after_status).
  returned: after state-machine initialization
  type: str
action_results:
  description: Attempted pair operations and their known outcomes, with controller result evidence.
  returned: after state-machine initialization
  type: list
  elements: dict
planned_operations:
  description: Planned pair operations, including those skipped after failure.
  returned: after successful write planning
  type: list
  elements: dict
may_have_changed:
  description: Whether unconfirmed effects may have occurred.
  returned: after state-machine initialization
  type: bool
reconciliation_complete:
  description: Whether all attempted HA mutation effects are known.
  returned: after state-machine initialization
  type: bool
unknown_identifiers:
  description: Pairs whose controller intent could not be established.
  returned: after state-machine initialization
  type: list
  elements: list
mutation_errors:
  description: Request-level errors from the HA pair or unpair actions.
  returned: after state-machine initialization
  type: list
  elements: str
config_actions_result:
  description: Requested save and deploy steps with status, targets, and available controller responses.
  returned: when config actions are planned or attempted after a change
  type: dict
output_level:
  description: Selected level of result detail.
  returned: after state-machine initialization
  type: str
proposed:
  description: Desired configuration in canonical peer order.
  returned: in a write state when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
logs:
  description: Debug log list.
  returned: after state-machine initialization when O(output_level=debug)
  type: list
  elements: str
msg:
  description: Explanation of task failure.
  returned: on failure
  type: str
"""

import logging
from itertools import chain

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.argument_spec import config_actions_spec
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.parser import parse_config_actions
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import FABRIC_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.raw_args import get_raw_module_args
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActions
from ansible_collections.cisco.nd.plugins.module_utils.models.smart_switches_ha_pair.pairing import SmartSwitchHaPairModel
from ansible_collections.cisco.nd.plugins.module_utils.module_failure import fail_from_exception
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.smart_switches_ha_pair import SmartSwitchHaPairOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender

# HA pair argument validation


def _validate_ha_pair_config(config: list[dict[str, str]] | None, state: str) -> None:
    """Validate state-specific config rules and reject switches shared by multiple pairs."""
    if state == "gathered":
        if config:
            raise ValueError("state=gathered is gather-all and requires empty or omitted config")
        return
    if config is None:
        raise ValueError(f"state={state} requires an explicit config list")
    seen_switch_ids: set[str] = set()
    for pair_config in config:
        pair_switch_ids = (pair_config["switch_id"], pair_config["peer_switch_id"])
        duplicate_switch_ids = seen_switch_ids.intersection(pair_switch_ids)
        if duplicate_switch_ids:
            raise ValueError(f"Switch {min(duplicate_switch_ids)!r} appears in multiple configured HA pairs")
        seen_switch_ids.update(pair_switch_ids)


# Configuration actions for changed HA pairs


def _run_config_actions_for_changed_peers(state_machine: NDStateMachine, orchestrator: SmartSwitchHaPairOrchestrator, config_actions: ConfigActions) -> None:
    """Target planned changes in check mode and accepted changes during execution."""
    if not (config_actions.save or config_actions.deploy):
        return
    if state_machine.check_mode:
        changed_pairs = chain(state_machine.plan.creates, state_machine.plan.deletes)
    else:
        changed_pairs = chain(state_machine.sent, state_machine.removed)
    affected_switch_ids = tuple(sorted({switch_id for pair in changed_pairs for switch_id in pair.peers}))
    if not affected_switch_ids:
        return
    config_actions_result = orchestrator.run_pair_config_actions(config_actions, affected_switch_ids, check_mode=state_machine.check_mode)
    state_machine.output.assign(config_actions_result=config_actions_result.to_result())
    if config_actions_result.status == "failed":
        failed_step = next(step for step in config_actions_result.actions if step.status == "failed")
        raise NDStateMachineError(f"Config action {failed_step.action!r} failed for fabric {failed_step.target!r}: {failed_step.error}")


# Ansible module entry point


def main() -> None:
    """Run the HA pair reconciliation for one fabric."""
    argument_spec = nd_argument_spec()
    argument_spec.update(SmartSwitchHaPairModel.get_argument_spec())
    argument_spec.update(config_actions_spec(FABRIC_CONFIG_ACTIONS))
    argument_spec.update(fabric_name={"type": "str", "required": True}, cluster_name={"type": "str"})
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[["state", state, ["config"]] for state in ("replaced", "overridden", "deleted")],
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_manage_smart_switches_ha_pair")
    state_machine = None
    try:
        state = module.params["state"]
        try:
            _validate_ha_pair_config(module.params["config"], state)
            config_actions = parse_config_actions(params=module.params, raw_args=get_raw_module_args(), policy=FABRIC_CONFIG_ACTIONS, state=state)
        except ValueError as error:
            raise NDStateMachineError(str(error)) from error
        sender = Sender()
        sender.ansible_module = module
        rest_send = RestSend({**module.params, "check_mode": module.check_mode})
        rest_send.sender = sender
        rest_send.response_handler = ResponseHandler()
        orchestrator = SmartSwitchHaPairOrchestrator(
            rest_send=rest_send, fabric_name=module.params["fabric_name"], cluster_name=module.params.get("cluster_name")
        )
        state_machine = NDStateMachine(module, orchestrator)
        state_machine.manage_state()
        _run_config_actions_for_changed_peers(state_machine, orchestrator, config_actions)
        module.exit_json(**state_machine.output.format_with_verbosity(getattr(module, "_verbosity", 0), state_machine.results))
    except Exception as error:  # pylint: disable=broad-except
        fail_from_exception(module, module_log, state_machine, error)


if __name__ == "__main__":
    main()
