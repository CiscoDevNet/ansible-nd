#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing switch maintenance mode on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_maintenance_mode
version_added: "2.0.0"
short_description: Manage the system mode (normal or maintenance) of switches in a fabric on Cisco Nexus Dashboard
description:
- Manage the system mode of one or more switches in a fabric on Cisco Nexus Dashboard.
- Wraps the C(POST /api/v1/manage/fabrics/{fabric_name}/switchActions/changeSystemMode) endpoint, which sets a single
  C(mode) (C(normal) or C(maintenance)) for a batch of switches in one request.
- For idempotency the module reads every switch's current C(intendedSystemMode) from a single bulk
  C(GET /api/v1/manage/fabrics/{fabric_name}/switches) and only POSTs the subset of switches whose intent differs from the requested mode.
- If any requested switch is currently in C(migration) mode, the module fails before any change is made and asks the
  operator to clear the migration state via the ND UI's "Recalculate and Deploy" workflow.
- This module currently supports O(state=merged) only. A future O(state=gathered) will report current per-switch system
  mode as runnable playbook configuration once the underlying framework support lands.
author:
- Allen Robel (@allenrobel)
options:
  fabric_name:
    description:
    - The name of the fabric containing the target switches.
    type: str
    required: true
  config:
    description:
    - The system mode change to apply.
    - The structure mirrors the ND C(changeSystemMode) API body plus its query parameters.
    type: dict
    required: true
    suboptions:
      mode:
        description:
        - The desired system mode for every switch in O(config.switches).
        type: str
        required: true
        choices: [ maintenance, normal ]
      deploy:
        description:
        - When V(true), the new system mode is deployed to the switches.
        - When V(false) (default), the new mode is recorded in ND's intent only. A subsequent deploy is required.
        type: bool
        default: false
      blocking:
        description:
        - When V(true) and O(config.deploy=true), the API blocks until the deploy operation completes or the
          server-configured timeout expires (see the ND server setting "Maintenance mode deploy wait time in minutes").
        - Has no effect when O(config.deploy=false).
        type: bool
        default: false
      ticket_id:
        description:
        - Optional Change Control ticket ID associated with the mode change.
        - Must start with a letter and contain only letters, digits, underscores, or hyphens (max 64 characters).
        type: str
      switches:
        description:
        - The switches on which to apply the requested mode.
        - All switches must be members of O(fabric_name); the module pre-resolves each O(config.switches.switch_ip)
          to its switch serial number via the fabric inventory before posting.
        type: list
        elements: dict
        required: true
        suboptions:
          switch_ip:
            description:
            - The management IP address of the switch.
            - Resolved internally to the switch serial number used in the ND C(switchIds) array.
            type: str
            required: true
  state:
    description:
    - The desired state of the network resources on the Cisco Nexus Dashboard.
    - Use O(state=merged) to apply the requested mode to the switches that currently differ.
    type: str
    default: merged
    choices: [ merged ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard.
- The module reads C(additionalData.intendedSystemMode) per switch for idempotency. The wire's C(additionalData.systemMode)
  aggregator returns C(inconsistent) between an intent change and a deploy, so comparing against it would cause spurious
  re-POSTs on every playbook run.
- A request that includes any unknown C(switch_ip) is rejected wholesale by ND (no partial application). The module
  validates all C(switch_ip) values against the fabric inventory client-side before issuing the POST.
- When O(config.deploy=true) and O(config.blocking=true), ND holds the HTTP response open for the duration of the deploy
  (often several minutes per switch). Ansible's C(persistent_command_timeout) defaults to 30 seconds and will reap the
  C(ansible-connection) socket mid-request, surfacing as a confusing C(ConnectionError ... socket path ... does not exist).
  Raise C(ansible_command_timeout) in your inventory C([nd:vars]) section (e.g. V(3600)) AND set a generous module-level
  C(timeout) via C(module_defaults). The Examples section below shows the recommended play-level pattern.
"""

EXAMPLES = r"""
- name: Place two switches into maintenance mode and deploy
  cisco.nd.nd_maintenance_mode:
    fabric_name: SITE1
    state: merged
    config:
      mode: maintenance
      deploy: true
      blocking: true
      ticket_id: CHG12345
      switches:
        - switch_ip: 192.168.12.151
        - switch_ip: 192.168.12.155

- name: Take a switch out of maintenance mode (intent only -- caller deploys later)
  cisco.nd.nd_maintenance_mode:
    fabric_name: SITE1
    state: merged
    config:
      mode: normal
      deploy: false
      switches:
        - switch_ip: 192.168.12.151

# Recommended pattern for blocking deploys: bump the per-task timeout via module_defaults at the
# play level, and set `ansible_command_timeout=3600` in your inventory's [nd:vars] section so the
# persistent connection survives the wait.
- name: Maintenance mode with extended timeout for a blocking deploy
  hosts: nd
  module_defaults:
    cisco.nd.nd_maintenance_mode:
      timeout: 1800
  tasks:
    - name: Place switches into maintenance mode and block until ND finishes deploying
      cisco.nd.nd_maintenance_mode:
        fabric_name: SITE1
        state: merged
        config:
          mode: maintenance
          deploy: true
          blocking: true
          switches:
            - switch_ip: 192.168.12.151
            - switch_ip: 192.168.12.155
"""

RETURN = r"""
"""
# pylint: disable=wrong-import-position

import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.maintenance_mode.maintenance_mode import MaintenanceModeModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.maintenance_mode import MaintenanceModeOrchestrator


def main():
    """
    # Summary

    Entry point for the `nd_maintenance_mode` Ansible module.

    The ND `changeSystemMode` endpoint is action-shaped — one request mutates a batch of switches with a single mode.
    The Ansible-facing `config` is a dict (not a list) to mirror the API body shape. `NDStateMachine`, however, drives a
    *list* of model instances. To bridge the two, this function wraps `module.params["config"]` into a one-item list
    immediately after argspec validation. The orchestrator's `query_all` and `update` see the original dict via
    `rest_send.params["config"][0]`.

    Only `state: merged` is supported. The collection has retired `state: query`; once `state: gathered` lands in
    `NDStateMachine`, this module will gain it with no other surface changes — `query_all` already produces a per-switch
    snapshot.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(MaintenanceModeModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_maintenance_mode")

    # Wrap the dict-shaped `config` into a 1-item list so NDStateMachine's
    # collection iterator can treat it as a singleton.
    config = module.params.get("config")
    if isinstance(config, dict):
        module.params["config"] = [config]

    nd_state_machine = None

    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=MaintenanceModeOrchestrator,
        )

        module_log.debug("manage_state begin state=%s check_mode=%s", module.params.get("state"), module.check_mode)
        nd_state_machine.manage_state()
        module_log.debug("manage_state end")

        module.exit_json(**nd_state_machine.output.format())

    except NDStateMachineError as e:
        module_log.exception("NDStateMachineError during module execution")
        output = nd_state_machine.output.format() if nd_state_machine else {}
        error_msg = f"Module execution failed: {str(e)}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)

    except Exception as e:  # pylint: disable=broad-except
        module_log.exception("Unhandled exception during module execution")
        output = nd_state_machine.output.format() if nd_state_machine else {}
        error_msg = f"Module failed: {str(e)}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)


if __name__ == "__main__":
    main()
