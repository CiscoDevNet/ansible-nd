# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Shared failure handler for the `main()` of `NDStateMachine`-based modules (issue #556).

Every module's `main()` wraps state management in a single `except Exception` clause that delegates to `fail_from_exception`,
so logging, the module output merged into the failure result, the interface finalizer, and the debug traceback all follow one
standard shape instead of a per-module copy of the block.
"""

from __future__ import annotations

import logging
import traceback
from typing import TYPE_CHECKING, Any, NoReturn

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import finalize_accepted_intent

if TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule
    from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine

# `NDStateMachineError` is a controller- or validation-reported failure; anything else is a bug in our code, and the two
# wordings are the maintainer's grep for telling them apart in logs and task output.
STATE_MACHINE_ERROR_LOG = "NDStateMachineError during module execution"
STATE_MACHINE_ERROR_PREFIX = "Module execution failed"
UNHANDLED_ERROR_LOG = "Unhandled exception during module execution"
UNHANDLED_ERROR_PREFIX = "Module failed"
FORMAT_FAILURE_LOG = "Formatting module output for the failure result failed; reporting the original error without it"


def fail_from_exception(module: AnsibleModule, module_log: logging.Logger, nd_state_machine: NDStateMachine | None, error: BaseException) -> NoReturn:
    """
    # Summary

    Log `error`, then call `module.fail_json` with the standard failure message and the state machine's formatted output.

    Must be called from inside the `except` clause that caught `error`, so `module_log.exception` and the debug traceback see the
    active exception. The tier is inferred from the exception type: an `NDStateMachineError` is reported as
    `Module execution failed: ...` (controller- or validation-reported), anything else as `Module failed: ...` (unhandled).

    The message also carries the `finalize_accepted_intent` note when the state machine's orchestrator is an
    `NDBaseInterfaceOrchestrator` with controller-accepted mutations to deploy, and the traceback when `output_level` is `debug`.
    A failure inside `output.format()` is logged and the result is reported without the output, so it cannot mask `error`.

    ## Raises

    ### AssertionError

    - If `module.fail_json` returns instead of exiting the module (unreachable with a real `AnsibleModule`; guards the `NoReturn` contract)
    """
    if isinstance(error, NDStateMachineError):
        module_log.exception(STATE_MACHINE_ERROR_LOG)
        prefix = STATE_MACHINE_ERROR_PREFIX
    else:
        module_log.exception(UNHANDLED_ERROR_LOG)
        prefix = UNHANDLED_ERROR_PREFIX

    output: dict[str, Any] = {}
    if nd_state_machine is not None:
        try:
            output = nd_state_machine.output.format()
        except Exception:  # pylint: disable=broad-except
            module_log.exception(FORMAT_FAILURE_LOG)
            output = {}

    error_msg = f"{prefix}: {str(error)}"
    error_msg += finalize_accepted_intent(nd_state_machine.model_orchestrator if nd_state_machine else None, module.check_mode, module_log)
    if module.params.get("output_level") == "debug":
        error_msg += f"\nTraceback:\n{traceback.format_exc()}"
    module.fail_json(msg=error_msg, **output)
    raise AssertionError("module.fail_json returned instead of exiting the module")
