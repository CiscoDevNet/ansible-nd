# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared Ansible module runner for security and segmentation modules."""

from __future__ import annotations

import logging

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.argument_spec import config_actions_spec
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.parser import parse_config_actions
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import SECURITY_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.raw_args import get_raw_module_args
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActionsExecutionError
from ansible_collections.cisco.nd.plugins.module_utils.module_failure import fail_from_exception
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine


def _reconcile_accepted_mutations(nd_state_machine: NDStateMachine) -> None:
    """Replace speculative state with the exact subset accepted before failure."""
    orchestrator = nd_state_machine.model_orchestrator
    existing = nd_state_machine.before.copy()
    sent = NDConfigCollection(model_class=nd_state_machine.model_class)
    removed = NDConfigCollection(model_class=nd_state_machine.model_class)

    for model_instance in orchestrator.accepted_upserts:
        identifier = model_instance.get_identifier_value()
        if existing.get(identifier) is None:
            existing.add(model_instance)
        else:
            existing.replace(model_instance)
        sent.add(model_instance.model_copy(deep=True))

    for model_instance in orchestrator.accepted_deletes:
        identifier = model_instance.get_identifier_value()
        current = existing.get(identifier)
        removed.add((current if current is not None else model_instance).model_copy(deep=True))
        existing.delete(identifier)

    nd_state_machine.existing = existing
    nd_state_machine.sent = sent
    nd_state_machine.removed = removed
    nd_state_machine.output.assign(after=existing)


def _run_final_actions(
    nd_state_machine: NDStateMachine,
    config_actions,
    state: str,
    check_mode: bool,
    accepted_only: bool,
) -> list[BaseException]:
    """Run queued security and config actions, collecting errors after every finalizer."""
    errors: list[BaseException] = []
    orchestrator = nd_state_machine.model_orchestrator

    try:
        action_results = orchestrator.flush_pending_actions(check_mode=check_mode, accepted_only=accepted_only)
        if action_results:
            nd_state_machine.output.assign(security_actions_result=action_results)
        errors.extend(RuntimeError(message) for message in orchestrator.pending_action_errors)
    except Exception as e:  # pylint: disable=broad-except
        errors.append(e)

    # CRUD payloads deliberately omit ``attach``.  Refresh the state-machine
    # collections after the action endpoints have established the actual state,
    # including exact-success members of a mixed HTTP 207 response.
    if not check_mode and orchestrator.has_accepted_mutations:
        try:
            _reconcile_accepted_mutations(nd_state_machine)
        except Exception as e:  # pylint: disable=broad-except
            errors.append(e)

    if len(nd_state_machine.sent) > 0 or len(nd_state_machine.removed) > 0 or orchestrator.has_accepted_mutations:
        try:
            config_actions_result = orchestrator.run_config_actions(
                actions=config_actions,
                fabric_names=[nd_state_machine.module.params["fabric_name"]],
                state=state,
                check_mode=check_mode,
            )
            if config_actions_result is not None:
                nd_state_machine.output.assign(config_actions_result=config_actions_result.to_result())
        except ConfigActionsExecutionError as e:
            nd_state_machine.output.assign(config_actions_result=e.result.to_result())
            errors.append(e)
        except Exception as e:  # pylint: disable=broad-except
            errors.append(e)
    return errors


def _aggregate_workflow_errors(errors: list[BaseException]) -> NDStateMachineError:
    """Build one failure after all accepted intent has been finalized."""
    primary = str(errors[0])
    if len(errors) == 1:
        return NDStateMachineError(primary)
    follow_up = "; ".join(str(error) for error in errors[1:])
    return NDStateMachineError(f"{primary} Finalization failure(s): {follow_up}")


def run_security_module(model_class, orchestrator_class, logger_name: str) -> None:
    """Run a security resource module through the NDStateMachine architecture."""
    argument_spec = nd_argument_spec()
    argument_spec.update(model_class.get_argument_spec())
    argument_spec.update(config_actions_spec(SECURITY_CONFIG_ACTIONS))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("state", "merged", ["config"]),
            ("state", "replaced", ["config"]),
            ("state", "overridden", ["config"]),
            ("state", "deleted", ["config"]),
        ],
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger(logger_name)

    state = module.params.get("state", "merged")
    try:
        config_actions = parse_config_actions(
            params=module.params,
            raw_args=get_raw_module_args(),
            policy=SECURITY_CONFIG_ACTIONS,
            state=state,
        )
    except ValueError as e:
        module.fail_json(msg=str(e))

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
        workflow_errors: list[BaseException] = []
        manage_failed = False
        try:
            nd_state_machine.manage_state()
            module_log.debug("manage_state end")
        except Exception as e:  # pylint: disable=broad-except
            manage_failed = True
            workflow_errors.append(e)
            try:
                _reconcile_accepted_mutations(nd_state_machine)
            except Exception as reconcile_error:  # pylint: disable=broad-except
                workflow_errors.append(reconcile_error)

        workflow_errors.extend(
            _run_final_actions(
                nd_state_machine=nd_state_machine,
                config_actions=config_actions,
                state=state,
                check_mode=module.check_mode,
                accepted_only=manage_failed,
            )
        )
        if workflow_errors:
            raise _aggregate_workflow_errors(workflow_errors)

        verbosity = getattr(module, "_verbosity", 0)
        module.exit_json(**nd_state_machine.output.format_with_verbosity(verbosity, nd_state_machine.results))

    except Exception as e:  # pylint: disable=broad-except
        fail_from_exception(module, module_log, nd_state_machine, e)
