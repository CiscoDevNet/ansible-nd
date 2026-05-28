#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_fabric_prepare_update
version_added: "2.0.0"
short_description: Prepare (stage and validate) fabric update groups on Cisco Nexus Dashboard
description:
- Prepare one or more fabric update groups under O(fabric_name) for a software upgrade on Cisco Nexus Dashboard (ND).
- This runs the Fabric Software Management I(Prepare) step, which Nexus Dashboard implements as the
  C(softwareUpdatePlan/actions/stage) action - it stages (copies) each update group's configured image to the
  member switches, runs C(show install all impact), and generates pre-upgrade reports.
- Before staging, the module performs a pre-flight check and fails if any update group contains a mix of switch
  roles (for example, leaf and spine). Nexus Dashboard does not permit preparing a mixed-role update group.
- Preparing is a long-running, asynchronous operation. By default the module waits for staging to complete on
  every switch before returning.
- If every switch in every requested update group is already staged and validated for the update group's
  configured image, the module reports no change and does not stage again.
author:
- Allen Robel (@allenrobel)
options:
  fabric_name:
    description:
    - The name of the fabric that contains the update groups to prepare.
    type: str
    required: true
  update_groups:
    description:
    - The list of update group names to prepare.
    - Each named update group must already exist in O(fabric_name). Create update groups with M(cisco.nd.nd_fabric_update_group).
    type: list
    elements: str
    required: true
  wait:
    description:
    - Whether to wait for staging to complete on every switch before returning.
    - When V(true), the module polls Nexus Dashboard until every switch has staged and validated, or until O(wait_timeout) is reached.
    - When V(false), the module returns as soon as Nexus Dashboard accepts the stage action; staging continues on Nexus Dashboard.
    type: bool
    default: true
  wait_timeout:
    description:
    - The maximum time, in seconds, to wait for staging to complete when O(wait=true).
    - The task fails if staging has not completed for every switch within this time.
    type: int
    default: 1800
  wait_interval:
    description:
    - The interval, in seconds, between staging-status polls when O(wait=true).
    - Keep this comfortably below the persistent connection idle timeout (Ansible's
      C(persistent_command_timeout), default V(30)). If the module is idle between polls for
      longer than that timeout, the persistent connection is closed and the task fails.
    type: int
    default: 10
  state:
    description:
    - The desired state.
    - Use O(state=merged) to prepare the requested update groups.
    - Only V(merged) is currently supported. A V(gathered) state will be added in a future release.
    type: str
    default: merged
    choices: [ merged ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard 4.2.1 or higher.
- The target image, whether the upgrade is disruptive or non-disruptive, maintenance mode, and the report checks
  are properties of the update group itself, not of this module. Configure them with M(cisco.nd.nd_fabric_update_group)
  before preparing. This module only selects which update groups to prepare.
- In check mode, when staging is required, the module reports a change but does not stage, because the stage
  action cannot be previewed.
- When O(wait=true), the module holds the persistent connection for the whole staging wait. Keep O(wait_interval)
  below the persistent connection idle timeout (C(persistent_command_timeout)), and for long O(wait_timeout)
  values raise C(ansible_command_timeout) for the host so the connection is not reaped mid-wait.
"""

EXAMPLES = r"""
- name: Prepare a single update group and wait for staging to complete
  cisco.nd.nd_fabric_prepare_update:
    fabric_name: SITE1
    update_groups:
      - SITE1_N9K_leaf
    state: merged

- name: Prepare multiple update groups with a longer timeout
  cisco.nd.nd_fabric_prepare_update:
    fabric_name: SITE1
    update_groups:
      - SITE1_N9K_leaf
      - SITE1_N9K_spine
    wait: true
    wait_timeout: 3600
    wait_interval: 60
    state: merged

- name: Start preparing an update group without waiting for completion
  cisco.nd.nd_fabric_prepare_update:
    fabric_name: SITE1
    update_groups:
      - SITE1_N9K_leaf
    wait: false
    state: merged
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.fabric_prepare_update import FabricPrepareUpdateOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


def _run_prepare(module: AnsibleModule) -> dict:
    """
    # Summary

    Run the fabric prepare-update (stage) workflow: pre-flight role check, idempotency check,
    stage action, and - when `wait` is set - poll until staging completes. `changed` is derived
    directly from whether staging was required (the stage action's effect is deterministic, so no
    before/after diff is needed). In check mode the stage action is skipped (it cannot be
    previewed) but a required change is still reported.

    ## Raises

    ### Exception

    - Propagated from the orchestrator if the pre-flight check fails, a request fails, a switch
      reports a staging failure, or the wait times out.
    """
    output = NDOutput(output_level=module.params.get("output_level", "normal"))

    sender = Sender()
    sender.ansible_module = module
    rest_send_params = dict(module.params)
    rest_send_params["check_mode"] = module.check_mode
    rest_send = RestSend(rest_send_params)
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()

    orchestrator = FabricPrepareUpdateOrchestrator(rest_send=rest_send, results=Results())
    update_groups = module.params["update_groups"]

    # Pre-flight: ND will not prepare an update group that spans more than one switch role.
    # Fetch the summary once and reuse it for both the role check and the `before` snapshot,
    # so startup costs a single GET instead of two.
    summary = orchestrator.get_summary()
    orchestrator.preflight_role_check(update_groups, summary=summary)

    before = orchestrator.status_snapshot(update_groups, summary=summary)

    if FabricPrepareUpdateOrchestrator.snapshot_fully_prepared(before):
        # Every switch is already staged and validated for the update group's configured image.
        return output.format(changed=False, before=before, after=before)

    if module.check_mode:
        # The stage action cannot be previewed; report the pending change without acting.
        return output.format(changed=True, before=before, after=before)

    orchestrator.stage(update_groups)
    if module.params["wait"]:
        orchestrator.wait_for_completion(
            update_groups,
            timeout=module.params["wait_timeout"],
            interval=module.params["wait_interval"],
        )

    after = orchestrator.status_snapshot(update_groups)
    return output.format(changed=True, before=before, after=after)


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        fabric_name=dict(type="str", required=True),
        update_groups=dict(type="list", elements="str", required=True),
        wait=dict(type="bool", default=True),
        wait_timeout=dict(type="int", default=1800),
        wait_interval=dict(type="int", default=10),
        state=dict(type="str", default="merged", choices=["merged"]),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    require_pydantic(module)

    try:
        result = _run_prepare(module)
        module.exit_json(**result)
    except Exception as e:
        module.fail_json(msg=f"Module execution failed: {str(e)}")


if __name__ == "__main__":
    main()
