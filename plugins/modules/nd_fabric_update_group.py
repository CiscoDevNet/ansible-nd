#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_fabric_update_group
version_added: "2.0.0"
short_description: Manage fabric update groups (Fabric Software Management) on Cisco Nexus Dashboard
description:
- Manage fabric update groups under O(fabric_name) on Cisco Nexus Dashboard (ND).
- A fabric update group ties together a set of switches with an image / package install plan and orchestration knobs
  (execution mode, contingency, analysis, maintenance, reports) used by the Fabric Software Management workflow.
- This is the ND 4.2 successor to image policies in ND 3.x.
author:
- Allen Robel (@allenrobel)
options:
  fabric_name:
    description:
    - The name of the fabric in which to manage update groups.
    type: str
    required: true
  config:
    description:
    - The list of fabric update groups to configure.
    type: list
    elements: dict
    suboptions:
      update_group_name:
        description:
        - The name of the update group.
        - The O(config.update_group_name) must be defined when creating, updating or deleting an update group.
        type: str
        required: true
      execution:
        description:
        - The execution strategy for the upgrade run.
        - V(serial) upgrades switches one at a time. V(parallel) upgrades them concurrently.
        type: str
        choices: [ parallel, serial ]
      contingency:
        description:
        - The contingency behavior on per-switch failure during the upgrade run.
        - V(continue) skips the failed switch and proceeds. V(pause) halts the run for operator intervention.
        type: str
        choices: [ continue, pause ]
      analysis:
        description:
        - The pre / post analysis level.
        - V(snapshot) captures a snapshot only.
        - V(noAnalysis) skips analysis entirely.
        - V(fullAnalysis) runs the full analysis pipeline.
        - V(usePreExistingAnalysis) reuses prior analysis results.
        type: str
        choices: [ snapshot, noAnalysis, fullAnalysis, usePreExistingAnalysis ]
      is_maintenance:
        description:
        - Whether to place switches in maintenance mode before upgrading.
        type: bool
      is_disruptive_update:
        description:
        - Whether the upgrade is allowed to be disruptive.
        type: bool
      update_group_switches:
        description:
        - The list of switches that belong to this update group.
        - Each entry is a switch fabric management IP address (IPv4 or IPv6). Switch serial numbers are not accepted.
        - Switch IP addresses are resolved to switchIds via the fabric inventory before the request is sent.
        - An update group must contain at least one switch; ND does not permit a zero-switch group.
        type: list
        elements: str
      force_created:
        description:
        - Whether to force creation of the update group past ND pre-flight switch warnings.
        - When V(false), an ND warning (for example, that upgrading the selected switches would impact all
          roles in the fabric) fails the task. Set V(true) to acknowledge such warnings and apply anyway.
        type: bool
        default: false
      installation_order_devices:
        description:
        - The order in which switches are upgraded when O(config.execution=serial).
        - Each entry is a switch fabric management IP address (IPv4 or IPv6). Switch serial numbers are not accepted.
        - Switch IP addresses are resolved to switchIds via the fabric inventory before the request is sent.
        - Nexus Dashboard accepts this field on write but never returns it on read, so the module cannot detect
          drift on it. A change to O(config.installation_order_devices) alone is therefore not reported as changed
          and is not sent; set it alongside another changed field to ensure it is applied.
        type: list
        elements: str
      recommended_version:
        description:
        - The recommended target software version for this group.
        - Nexus Dashboard accepts this field on write but never returns it on read, so, like
          O(config.installation_order_devices), a change to it alone is not reported as changed and is not sent.
        type: str
      latest_recommended_version:
        description:
        - The latest available recommended software version for this group.
        - Nexus Dashboard accepts this field on write but never returns it on read, so, like
          O(config.installation_order_devices), a change to it alone is not reported as changed and is not sent.
        type: str
      report_selection:
        description:
        - The report detail level.
        type: str
        choices: [ noReport, basic, advanced ]
      reports:
        description:
        - The report generation strategy.
        type: str
        choices: [ noReport, usePreExistingReports, useDefaultPreAndPostReports, useAdvancePreAndPostReports ]
      install_image_data:
        description:
        - The image / package install specification for this group.
        type: dict
        suboptions:
          nos_image_name:
            description:
            - The NXOS image filename to install.
            type: str
          epld_image_name:
            description:
            - The EPLD image filename to install.
            type: str
          install_package_names:
            description:
            - The list of SMU / patch package filenames to install.
            type: list
            elements: str
          uninstall_package:
            description:
            - Whether to uninstall existing SMUs before installing the new packages.
            type: bool
      update_report_checks:
        description:
        - The list of named pre / post upgrade report checks to run.
        type: list
        elements: dict
        suboptions:
          report_check_name:
            description:
            - The name of the report check to run.
            type: str
            required: true
  auto_assign:
    description:
    - Auto-generate fabric update groups by algorithm instead of listing them explicitly in O(config).
    - V(roleBased) groups switches by their role. V(evenOdd) splits switches into an odd and an even group.
    - This triggers the Nexus Dashboard fabric-wide auto-assign action, which generates the update
      groups and applies them immediately. Nexus Dashboard names the generated groups itself, in the
      form C(fabric_platform_role) for V(roleBased) or C(fabric_platform_OddGroup) /
      C(fabric_platform_EvenGroup) for V(evenOdd).
    - O(auto_assign) is mutually exclusive with O(config), and is only valid with O(state=merged).
    - O(state=overridden) is not supported with O(auto_assign) - the auto-assign action already regroups every
      switch in the fabric, so it inherently enforces a complete state, and the per-group delete semantics of
      O(state=overridden) do not apply to a single fabric-wide action.
    - In check mode no change is reported, because the auto-assign action cannot be previewed.
    type: str
    choices: [ roleBased, evenOdd ]
  state:
    description:
    - The desired state of the fabric update groups on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new update groups and update existing ones to match the provided configuration.
      Update groups on ND that are not specified in the configuration will be left unchanged.
    - Use O(state=replaced) to replace the update groups specified in the configuration. Fields not provided are reset.
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
      Update groups on ND but not in the configuration will be deleted. Use with caution.
    - Use O(state=deleted) to delete the update groups specified in the configuration.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard 4.2.1 or higher.
"""

EXAMPLES = r"""
- name: Create a fabric update group
  cisco.nd.nd_fabric_update_group:
    fabric_name: SITE1
    config:
      - update_group_name: leaf_group
        execution: serial
        contingency: continue
        analysis: snapshot
        is_maintenance: true
        is_disruptive_update: true
        update_group_switches:
          # Switches are specified as fabric management IP addresses.
          - 192.168.7.11
          - 192.168.7.12
        install_image_data:
          nos_image_name: nxos.9.3.13.bin
          epld_image_name: n9000-epld.9.3.13.img
          install_package_names:
            - nxos.CSCwh77779-n9k_ALL-1.0.0-9.3.13.lib32_n9000.rpm
          uninstall_package: true
        report_selection: advanced
        reports: useDefaultPreAndPostReports
        update_report_checks:
          - report_check_name: sh_version
    state: merged

- name: Delete an update group
  cisco.nd.nd_fabric_update_group:
    fabric_name: SITE1
    config:
      - update_group_name: leaf_group
    state: deleted

- name: Auto-assign update groups by switch role
  cisco.nd.nd_fabric_update_group:
    fabric_name: SITE1
    auto_assign: roleBased
    state: merged
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.fabric_update_group.fabric_update_group import FabricUpdateGroupModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.fabric_update_group import FabricUpdateGroupOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


def _run_auto_assign(module: AnsibleModule, output: NDOutput) -> None:
    """
    # Summary

    Run the fabric-wide auto-assign (`propose`) action, bypassing `NDStateMachine` whose per-group
    config-diff state model does not apply to a single fabric-level action. The update groups are
    snapshotted before and after so `changed` reflects whether the regrouping altered the fabric.
    In check mode the `propose` action is skipped (it cannot be previewed) and no change is reported.

    The supplied `output` is populated in place. The `before` snapshot is assigned as soon as it is
    taken (with `after` seeded to it) so that if `propose` or the post-snapshot query fails, the
    caller's error path still surfaces the captured `before`/`after` context instead of an empty result.

    ## Raises

    ### Exception

    - Propagated from the orchestrator if a query or the `propose` request fails.
    """
    sender = Sender()
    sender.ansible_module = module
    rest_send_params = dict(module.params)
    rest_send_params["check_mode"] = module.check_mode
    rest_send = RestSend(rest_send_params)
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()

    orchestrator = FabricUpdateGroupOrchestrator(rest_send=rest_send, results=Results())

    before = NDConfigCollection.from_api_response(response_data=orchestrator.query_all(), model_class=FabricUpdateGroupModel)
    # Seed before/after now: if propose or the after-snapshot raises, the caller's except path still
    # has the before context (after == before reflects "nothing applied yet").
    output.assign(before=before, after=before)
    if not module.check_mode:
        orchestrator.propose(module.params["auto_assign"])
    after = NDConfigCollection.from_api_response(response_data=orchestrator.query_all(), model_class=FabricUpdateGroupModel)

    output.assign(before=before, after=after)


def _validate_report_analysis_exclusion(module: AnsibleModule) -> None:
    """
    # Summary

    Fail with a clear message if any config item selects both `analysis` and a report type. Nexus
    Dashboard rejects `analysis` set together with `reports` / `report_selection` at a value other than
    `noReport` (400 "Both Analysis and Report type can not be selected togather"), and even
    `analysis: noAnalysis` counts as analysis being selected. Enforcing it here turns a raw ND 400 into
    an actionable validation error. Skipped for O(state=deleted), where settings fields are ignored.

    ## Raises

    None

    Calls `module.fail_json` (which raises) on a conflicting config item.
    """
    if module.params.get("state") == "deleted":
        return
    for item in module.params.get("config") or []:
        if not isinstance(item, dict):
            continue
        analysis_selected = item.get("analysis") is not None
        report_selected = item.get("reports") not in (None, "noReport") or item.get("report_selection") not in (None, "noReport")
        if analysis_selected and report_selected:
            module.fail_json(
                msg=(
                    f"update_group_name '{item.get('update_group_name')}': analysis cannot be combined with a report type. "
                    "Nexus Dashboard rejects 'analysis' set together with 'reports' or 'report_selection' at any value other "
                    "than 'noReport' (even analysis: noAnalysis counts as analysis being selected). "
                    "Specify analysis or a report type, but not both."
                )
            )


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(FabricUpdateGroupModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[["config", "auto_assign"]],
    )
    require_pydantic(module)

    _validate_report_analysis_exclusion(module)

    auto_assign = module.params.get("auto_assign")
    if auto_assign is not None:
        state = module.params["state"]
        if state != "merged":
            module.fail_json(
                msg=f"auto_assign is only valid with state 'merged', got '{state}'. "
                "The auto-assign action already regroups every switch in the fabric, so it cannot be combined with any other state."
            )

        output = NDOutput(output_level=module.params.get("output_level", "normal"))
        try:
            _run_auto_assign(module, output)
            module.exit_json(**output.format())
        except Exception as e:
            module.fail_json(msg=f"Module execution failed: {str(e)}", **output.format())
        return

    nd_state_machine = NDStateMachine(
        module=module,
        model_orchestrator=FabricUpdateGroupOrchestrator,
    )

    try:
        nd_state_machine.manage_state()
        module.exit_json(**nd_state_machine.output.format())
    except Exception as e:
        module.fail_json(msg=f"Module execution failed: {str(e)}", **nd_state_machine.output.format())


if __name__ == "__main__":
    main()
