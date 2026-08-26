# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

import time
from typing import Any, Callable

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_plan import (
    NDStatePlan,
    NDStatePlanner,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_reconciliation import (
    DeferredMutation,
    MutationCheckpoint,
    MutationEffect,
    MutationJournal,
    MutationOperation,
    MutationOutcome,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    FinalizationContext,
    ResponseType,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


class NDStateMachine:
    """
    Generic State Machine for Nexus Dashboard (Bulk Support).
    """

    def __init__(
        self,
        module: AnsibleModule,
        model_orchestrator: type[NDBaseOrchestrator] | NDBaseOrchestrator,
    ):
        """
        Initialize the ND State Machine.
        """
        self.module = module

        # REST infrastructure
        sender = Sender()
        sender.ansible_module = self.module
        rest_send_params = dict(self.module.params)
        rest_send_params["check_mode"] = self.module.check_mode
        self.rest_send = RestSend(rest_send_params)
        self.rest_send.sender = sender
        self.rest_send.response_handler = ResponseHandler()

        # Operation tracking
        self.output = NDOutput(output_level=module.params.get("output_level", "normal"))
        self.results = Results()
        self.results.state = self.module.params.get("state", "")
        self.results.check_mode = self.module.check_mode

        # Configuration
        # Accept either an orchestrator instance or a class.
        if isinstance(model_orchestrator, type) and issubclass(
            model_orchestrator, NDBaseOrchestrator
        ):
            self.model_orchestrator = model_orchestrator(
                rest_send=self.rest_send, results=self.results
            )
        elif isinstance(model_orchestrator, NDBaseOrchestrator):
            self.model_orchestrator = model_orchestrator
            self.model_orchestrator.results = self.results
        else:
            raise NDStateMachineError(
                f"model_orchestrator must be an NDBaseOrchestrator class or instance. Got: {type(model_orchestrator)}"
            )

        self.model_class = self.model_orchestrator.model_class
        self.state = self.module.params["state"]

        # Cached flags
        self.check_mode = self.module.check_mode
        self.ignore_errors = self.module.params.get("ignore_errors", False)
        self.supports_bulk_create = self.model_orchestrator.supports_bulk_create
        self.supports_bulk_delete = self.model_orchestrator.supports_bulk_delete
        self.journal = MutationJournal()
        self.plan: NDStatePlan | None = None
        self.observed: NDConfigCollection | None = None
        self._finalized = False
        self._verify_settings = self._verification_settings()

        # Initialize collections
        try:
            response_data = self.model_orchestrator.query_all()
            # State of configuration objects in ND before change execution
            self.before = NDConfigCollection.from_api_response(
                response_data=response_data, model_class=self.model_class
            )
            # Planned and confirmed state must never alias each other.  The
            # legacy ``existing`` name remains a compatibility alias for the
            # evidence-backed confirmed collection.
            self.planned = self.before.copy()
            self.confirmed = self.before.copy()
            self.existing = self.confirmed
            # Ongoing collection of configuration objects that were changed
            self.sent = NDConfigCollection(model_class=self.model_class)
            # Collection of configuration objects given by user.
            # ``context={"state": ...}`` is threaded into pydantic validation so models can apply
            # state-aware validation (e.g. require certain fields for write states while accepting
            # identifier-only items for ``deleted``). Models that do not read the context ignore it.
            self.proposed = NDConfigCollection.from_ansible_config(
                data=self.module.params.get("config", []),
                model_class=self.model_class,
                context={"state": self.state},
            )

            self.output.assign(before=self.before, proposed=self.proposed)
            self.output.set_after_state(self.confirmed, status="confirmed")

        except Exception as e:
            raise NDStateMachineError(f"Initialization failed: {str(e)}") from e

    # State Management (core function)
    def manage_state(self) -> None:
        """Plan first, then apply only controller effects supported by evidence."""
        if self.state not in {"merged", "replaced", "overridden", "deleted"}:
            raise NDStateMachineError(f"Invalid state: {self.state}")

        if self.state in {"merged", "replaced", "overridden"}:
            proposed_items = list(self.proposed)
            items_to_create = [
                item
                for item in proposed_items
                if self.before.get(item.get_identifier_value()) is None
            ]
            try:
                self.model_orchestrator.preflight_create(items_to_create)
                self.model_orchestrator.preflight(proposed_items)
            except NDStateMachineError:
                raise
            except Exception as e:
                raise NDStateMachineError(f"Preflight failed: {e}") from e

        try:
            self.plan = NDStatePlanner.plan(
                state=self.state,
                before=self.before,
                proposed=self.proposed,
                ignore_errors=self.ignore_errors,
            )
        except Exception as e:
            raise NDStateMachineError(f"Planning failed: {e}") from e

        self.planned = self.plan.after
        if self.check_mode:
            self._preview_plan()
            return

        self._execute_plan()
        self._update_output_from_journal()

    def _preview_plan(self) -> None:
        """Expose the prospective plan without executing controller writes."""
        if self.plan is None:
            raise NDStateMachineError("State plan is not available")
        for item in (*self.plan.updates, *self.plan.creates, *self.plan.deletes):
            self._add_sent(item)
        self.output.set_changed(self.plan.changed)
        self.output.set_after_state(self.planned, status="planned")

    def _effect(
        self, operation: MutationOperation, item: NDBaseModel
    ) -> MutationEffect:
        """Build a resource transition from one planned operation model."""
        identifier = item.get_identifier_value()
        before = self.before.get(identifier)
        after = None if operation is MutationOperation.DELETE else item
        return MutationEffect(
            operation=operation, identifier=identifier, before=before, after=after
        )

    def _execute_plan(self) -> None:
        """Execute the plan in the state machine's established operation order."""
        if self.plan is None:
            raise NDStateMachineError("State plan is not available")

        execution_steps: list[
            tuple[
                MutationCheckpoint,
                Callable[..., ResponseType | DeferredMutation],
                tuple[Any, ...],
                str,
            ]
        ] = []

        for item in self.plan.updates:
            checkpoint = self.journal.open(
                phase="update", effects=(self._effect(MutationOperation.UPDATE, item),)
            )
            execution_steps.append(
                (
                    checkpoint,
                    self.model_orchestrator.update,
                    (item,),
                    f"Failed to update {item.get_identifier_value()}",
                )
            )

        creates = list(self.plan.creates)
        if creates and self.supports_bulk_create:
            checkpoint = self.journal.open(
                phase="create",
                effects=(
                    self._effect(MutationOperation.CREATE, item) for item in creates
                ),
            )
            execution_steps.append(
                (
                    checkpoint,
                    self.model_orchestrator.create_bulk,
                    (creates,),
                    "Failed to create in bulk",
                )
            )
        else:
            for item in creates:
                checkpoint = self.journal.open(
                    phase="create",
                    effects=(self._effect(MutationOperation.CREATE, item),),
                )
                execution_steps.append(
                    (
                        checkpoint,
                        self.model_orchestrator.create,
                        (item,),
                        f"Failed to create {item.get_identifier_value()}",
                    )
                )

        deletes = list(self.plan.deletes)
        if deletes and self.supports_bulk_delete:
            checkpoint = self.journal.open(
                phase="delete",
                effects=(
                    self._effect(MutationOperation.DELETE, item) for item in deletes
                ),
            )
            execution_steps.append(
                (
                    checkpoint,
                    self.model_orchestrator.delete_bulk,
                    (deletes,),
                    "Failed to delete in bulk",
                )
            )
        else:
            for item in deletes:
                checkpoint = self.journal.open(
                    phase="delete",
                    effects=(self._effect(MutationOperation.DELETE, item),),
                )
                execution_steps.append(
                    (
                        checkpoint,
                        self.model_orchestrator.delete,
                        (item,),
                        f"Failed to delete {item.get_identifier_value()}",
                    )
                )

        for checkpoint, operation, args, error_msg_prefix in execution_steps:
            self._execute_operation(
                checkpoint,
                operation,
                *args,
                error_msg_prefix=error_msg_prefix,
            )

    @staticmethod
    def _is_write_verb(verb: str) -> bool:
        return verb.upper() in {"POST", "PUT", "PATCH", "DELETE"}

    @staticmethod
    def _proves_no_change(call) -> bool:
        """Require explicit endpoint certainty; aggregate changed=False is insufficient."""
        return call.failed and call.result.get("outcome_certainty") == "no_change"

    def _classify_operation(
        self,
        *,
        result_sequence: int,
        attempt_sequence: int,
        raised: bool,
        returned: ResponseType | DeferredMutation,
    ) -> tuple[MutationOutcome, bool, bool, tuple[int, ...]]:
        """Classify one logical operation from request-attempt and response evidence."""
        calls = self.results.calls_since(result_sequence)
        attempts = self.results.attempts_since(attempt_sequence)
        write_calls = tuple(call for call in calls if self._is_write_verb(call.verb))
        write_attempts = tuple(
            attempt for attempt in attempts if self._is_write_verb(attempt.verb)
        )
        incomplete_attempt = any(not attempt.completed for attempt in write_attempts)
        failed_calls = tuple(
            call
            for call in write_calls
            if call.failed or call.result.get("success") is False
        )
        successful_calls = tuple(
            call
            for call in write_calls
            if not call.failed and call.result.get("success") is True
        )
        changed = bool(successful_calls) or any(
            call.changed or call.result.get("changed") is True for call in write_calls
        )
        call_sequences = tuple(call.sequence_number for call in calls)

        if isinstance(returned, DeferredMutation) and not raised:
            return MutationOutcome.QUEUED, False, False, call_sequences

        if incomplete_attempt:
            return MutationOutcome.UNKNOWN, changed, not changed, call_sequences

        if failed_calls:
            no_change_is_proven = not successful_calls and all(
                self._proves_no_change(call) for call in failed_calls
            )
            if no_change_is_proven:
                return MutationOutcome.FAILED, False, False, call_sequences
            return MutationOutcome.UNKNOWN, changed, not changed, call_sequences

        if raised:
            if write_calls or write_attempts:
                return MutationOutcome.UNKNOWN, changed, not changed, call_sequences
            return MutationOutcome.FAILED, False, False, call_sequences

        return MutationOutcome.SUCCEEDED, True, False, call_sequences

    def _execute_operation(
        self,
        checkpoint: MutationCheckpoint,
        operation: Callable[..., ResponseType | DeferredMutation],
        *args: Any,
        error_msg_prefix: str = "Operation failed",
        **kwargs: Any,
    ) -> MutationOutcome:
        """Execute, classify, journal, and reconcile one logical mutation."""
        result_sequence = self.results.task_sequence_number
        attempt_sequence = self.results.api_attempt_sequence_number
        returned: ResponseType | DeferredMutation = None
        caught: Exception | None = None

        try:
            returned = operation(*args, **kwargs)
        except Exception as e:  # outcome must be journaled before propagation
            caught = e

        outcome, changed, may_have_changed, call_sequences = self._classify_operation(
            result_sequence=result_sequence,
            attempt_sequence=attempt_sequence,
            raised=caught is not None,
            returned=returned,
        )
        error_msg = f"{error_msg_prefix}: {caught}" if caught is not None else None
        if error_msg is None and outcome in {
            MutationOutcome.FAILED,
            MutationOutcome.UNKNOWN,
        }:
            error_msg = f"{error_msg_prefix}: controller outcome is {outcome.value}"
        checkpoint.resolve(
            outcome,
            changed=changed,
            may_have_changed=may_have_changed,
            error=error_msg,
            api_call_sequences=call_sequences,
        )

        if outcome is MutationOutcome.SUCCEEDED:
            self._apply_confirmed_effects(checkpoint.effects)
        self._update_output_from_journal()

        if caught is not None and not self.ignore_errors:
            raise NDStateMachineError(error_msg or error_msg_prefix) from caught
        if (
            outcome in {MutationOutcome.FAILED, MutationOutcome.UNKNOWN}
            and not self.ignore_errors
        ):
            raise NDStateMachineError(error_msg or error_msg_prefix)
        return outcome

    def _apply_confirmed_effects(self, effects: tuple[MutationEffect, ...]) -> None:
        """Apply proven transitions immediately and populate sent from them only."""
        for effect in effects:
            if effect.operation is MutationOperation.DELETE:
                self.confirmed.delete(effect.identifier)
                if effect.before is not None:
                    self._add_sent(effect.before)
                continue

            if effect.after is None:
                raise NDStateMachineError(
                    f"Missing final model for {effect.operation.value} {effect.identifier}"
                )
            if self.confirmed.get(effect.identifier) is None:
                self.confirmed.add(effect.after)
            else:
                self.confirmed.replace(effect.after)
            self._add_sent(effect.after)

    def _add_sent(self, item: NDBaseModel) -> None:
        """Upsert one confirmed or check-mode-preview item into sent."""
        identifier = item.get_identifier_value()
        if self.sent.get(identifier) is None:
            self.sent.add(item)
        else:
            self.sent.replace(item)

    def _update_output_from_journal(self) -> None:
        """Keep output truthful after every checkpoint, including failures."""
        self.output.set_changed(self.journal.changed)
        if self.journal.has_unknown:
            self.output.mark_after_unknown(
                affected_identifiers=list(self.journal.unknown_identifiers),
                may_have_changed=self.journal.may_have_changed,
            )
            return
        self.output.set_after_state(self.confirmed, status="confirmed")

    @staticmethod
    def _positive_int_setting(settings: dict[str, Any], name: str, default: int) -> int:
        value = settings.get(name, default)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise NDStateMachineError(f"verify.{name} must be a positive integer")
        return value

    def _verification_settings(self) -> dict[str, int] | None:
        """Validate the opt-in unknown-state readback settings before writes."""
        raw_verify = self.module.params.get("verify")
        if raw_verify in (None, False):
            return None
        if raw_verify is True:
            raw_verify = {}
        if not isinstance(raw_verify, dict):
            raise NDStateMachineError("verify must be a boolean or dictionary")
        enabled = raw_verify.get("enabled", True)
        if not isinstance(enabled, bool):
            raise NDStateMachineError("verify.enabled must be a boolean")
        if not enabled:
            return None
        delay = raw_verify.get("delay", 1)
        if isinstance(delay, bool) or not isinstance(delay, int) or delay < 0:
            raise NDStateMachineError("verify.delay must be a non-negative integer")
        return {
            "retries": self._positive_int_setting(raw_verify, "retries", 5),
            "timeout": self._positive_int_setting(raw_verify, "timeout", 10),
            "delay": delay,
        }

    def finalize(self, *, primary_error: Exception | None = None) -> None:
        """Resolve output once at the outer workflow boundary."""
        if self._finalized:
            return
        if self.check_mode:
            self.output.set_changed(bool(self.plan and self.plan.changed))
            self.output.set_after_state(self.planned, status="planned")
            self._finalized = True
            return
        if not self.journal.has_unknown:
            self._update_output_from_journal()
            self._finalized = True
            return
        if self._verify_settings is None:
            self._update_output_from_journal()
            self._finalized = True
            return

        context = FinalizationContext(
            state=self.state,
            affected_identifiers=self.journal.unknown_identifiers,
            confirmed_identifiers=tuple(self.confirmed.keys()),
        )
        settings = self._verify_settings
        rest_send = self.model_orchestrator.rest_send
        original_timeout = rest_send.timeout
        errors: list[str] = []
        try:
            rest_send.timeout = settings["timeout"]
            for attempt in range(1, settings["retries"] + 1):
                try:
                    response_data = self.model_orchestrator.query_final_state(context)
                    self.observed = NDConfigCollection.from_api_response(
                        response_data=response_data, model_class=self.model_class
                    )
                    self.existing = self.confirmed
                    self.output.set_changed(self.journal.changed)
                    self.output.set_after_state(
                        self.observed, status="observed", verification_performed=True
                    )
                    self._finalized = True
                    return
                except Exception as e:
                    errors.append(str(e))
                    if attempt < settings["retries"] and settings["delay"]:
                        time.sleep(settings["delay"])
        finally:
            rest_send.timeout = original_timeout

        verification_error = f"Final-state verification failed after {settings['retries']} attempts: {'; '.join(errors)}"
        self.output.set_changed(self.journal.changed)
        self.output.mark_after_unknown(
            affected_identifiers=list(self.journal.unknown_identifiers),
            may_have_changed=self.journal.may_have_changed,
            verification_performed=True,
            verification_error=verification_error,
        )
        self._finalized = True
        if primary_error is None:
            raise NDStateMachineError(verification_error)
