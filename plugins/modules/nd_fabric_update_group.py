#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_fabric_update_group
version_added: "1.4.0"
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
        - Each entry may be a switch fabric management IP address or a switch serial number (switchId).
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
        - Each entry may be a switch fabric management IP address or a switch serial number (switchId).
        - Switch IP addresses are resolved to switchIds via the fabric inventory before the request is sent.
        type: list
        elements: str
      recommended_version:
        description:
        - The recommended target software version for this group.
        type: str
      latest_recommended_version:
        description:
        - The latest available recommended software version for this group.
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
          # Either IP addresses or switch serial numbers may be used.
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
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.fabric_update_group.fabric_update_group import FabricUpdateGroupModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.fabric_update_group import FabricUpdateGroupOrchestrator


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(FabricUpdateGroupModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

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
