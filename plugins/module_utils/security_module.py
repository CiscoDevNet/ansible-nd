# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared Ansible module runner for security and segmentation modules."""

from __future__ import annotations

import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.security.base import validate_config_actions_dict
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine


def run_security_module(model_class, orchestrator_class, logger_name: str) -> None:
    """Run a security resource module through the NDStateMachine architecture."""
    argument_spec = nd_argument_spec()
    argument_spec.update(model_class.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger(logger_name)

    try:
        validate_config_actions_dict(module.params.get("config_actions"))
    except Exception as e:  # pylint: disable=broad-except
        module.fail_json(msg=f"Invalid config_actions: {e}")

    nd_state_machine = None

    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=orchestrator_class,
        )
        module_log.debug(
            "manage_state begin state=%s check_mode=%s",
            module.params.get("state"),
            module.check_mode,
        )
        nd_state_machine.manage_state()
        module_log.debug("manage_state end")

        action_results = {}
        if not module.check_mode:
            action_results = nd_state_machine.model_orchestrator.flush_pending_actions()

        output = nd_state_machine.output.format()
        if action_results:
            output["security_actions_result"] = action_results
        if output.get("changed"):
            output["config_actions_result"] = nd_state_machine.model_orchestrator.apply_config_actions(changed=True)

        module.exit_json(**output)

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

