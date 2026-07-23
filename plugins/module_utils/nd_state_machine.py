# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

import logging
from collections.abc import Sequence
from copy import deepcopy
from dataclasses import replace
from typing import Any, Callable

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import (
    filter_gathered_response,
    validate_gathered_filters,
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
    MutationEffect,
    MutationJournal,
    MutationOperation,
    MutationOutcome,
    MutationResult,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    ResponseType,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender

log = logging.getLogger(__name__)


class NDStateMachine:
    """
    Generic State Machine for Nexus Dashboard (Bulk Support).
    """

    def __init__(
        self,
        module: AnsibleModule,
        model_orchestrator: type[NDBaseOrchestrator] | NDBaseOrchestrator,
        config: list | None = None,
    ):
        """
        Initialize the ND State Machine.

        ``config``: optional caller-prepared config list used to build the
        proposed collection. When omitted, ``module.params["config"]`` is used.
        Callers that need ``prepare_config_data`` transforms (switch-id backfill,
        payload nesting) must run it themselves and pass the result here (or write
        it back to ``module.params["config"]``); the state machine no longer calls
        ``prepare_config_data`` so non-idempotent orchestrators are not run twice.
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
        self.output = NDOutput(
            output_level=module.params.get("output_level", "normal"),
            state=module.params.get("state", ""),
        )
        self.results = Results()
        self.results.state = self.module.params.get("state", "")
        self.results.check_mode = self.module.check_mode

        # Configuration
        # Accept either an orchestrator instance or a class.
        if isinstance(model_orchestrator, type) and issubclass(model_orchestrator, NDBaseOrchestrator):
            self.model_orchestrator = model_orchestrator(rest_send=self.rest_send, results=self.results)
        elif isinstance(model_orchestrator, NDBaseOrchestrator):
            self.model_orchestrator = model_orchestrator
            self.model_orchestrator.results = self.results
        else:
            raise NDStateMachineError(f"model_orchestrator must be an NDBaseOrchestrator class or instance. Got: {type(model_orchestrator)}")

        self.model_class = self.model_orchestrator.model_class
        self.state = self.module.params["state"]

        # Cached flags
        self.check_mode = self.module.check_mode
        self.ignore_errors = self.module.params.get("ignore_errors", False)
        self.supports_bulk_create = self.model_orchestrator.supports_bulk_create
        self.supports_bulk_delete = self.model_orchestrator.supports_bulk_delete

        # Mask secret input values in the invocation echo. Ansible auto-masks
        # ``no_log`` argument-spec params, but secrets in free-form/nested dicts
        # have no static suboption to flag; the model declares them via
        # ``collect_secret_values`` and we register them here, generically for
        # every module rather than per-module boilerplate. ``no_log_values`` is
        # always present on a real AnsibleModule; guard for module stubs.
        if hasattr(self.module, "no_log_values"):
            for config_item in self.module.params.get("config") or []:
                self.module.no_log_values |= self.model_class.collect_secret_values(config_item)

        # Initialize collections
        try:
            raw_config = config if config is not None else (self.module.params.get("config") or [])
            gathered_filtering_enabled = self.state == "gathered" and getattr(
                self.model_class,
                "supports_gathered_filtering",
                False,
            )
            lucene_candidate_filtering_enabled = gathered_filtering_enabled and getattr(
                self.model_orchestrator,
                "supports_gathered_lucene_filtering",
                False,
            )
            query_kwargs = {}
            if lucene_candidate_filtering_enabled:
                query_kwargs["gathered_filters"] = raw_config

            if gathered_filtering_enabled and raw_config:
                validate_gathered_filters(
                    filters=raw_config,
                    normalize_filter=self.model_class.normalize_gathered_filter,
                )

            response_data = self.model_orchestrator.query_all(**query_kwargs)

            # Always retain the generic final filter. The server query only
            # reduces candidate resources.
            if gathered_filtering_enabled:
                response_data = filter_gathered_response(
                    response_data=response_data,
                    filters=raw_config,
                    model_class=self.model_class,
                    normalize_filter=self.model_class.normalize_gathered_filter,
                )

            # State of configuration objects in ND before change execution
            self.before = NDConfigCollection.from_api_response(response_data=response_data, model_class=self.model_class)
            # Opaque authentication settings are discovered only in the
            # controller response, so the argument specification cannot mark
            # their values no_log. Register each model-declared value now so
            # Ansible scrubs it from verbose API responses and replacement
            # payloads as well as the ordinary module result.
            if hasattr(self.module, "no_log_values"):
                for existing_item in self.before:
                    self.module.no_log_values |= existing_item.collect_replacement_secret_values()
            # Surface controller objects whose type this module does not model. They
            # are preserved as opaque read-only records (see the links tolerant read
            # path) and are protected from implicit/explicit modification below.
            self._warn_unsupported(self.before)
            # State of current configuration objects in ND during change execution
            self.existing = self.before.copy()
            # Ongoing collection of configuration objects that were changed
            self.sent = NDConfigCollection(model_class=self.model_class)
            # Configuration objects removed from ND this run. Kept separate from
            # ``sent`` (created/updated) because a delete stages pending config that
            # some modules must still save/deploy, while others must not treat a
            # deleted object as a save/deploy target.
            self.removed = NDConfigCollection(model_class=self.model_class)
            # Collection of configuration objects given by user. Coalesce None to
            # an empty list so read-only states (e.g. gathered) with no config work.
            # ``context={"state": ...}`` is threaded into pydantic validation so models can apply
            # state-aware validation (e.g. require certain fields for write states while accepting
            # identifier-only items for ``deleted``). Models that do not read the context ignore it.
            #
            # ``prepare_config_data`` (switch-id backfill, payload transforms) is
            # the caller's responsibility. Workflow coordinators already run it and
            # write the result back to ``module.params["config"]``; ``nd_manage_links``
            # passes its prepared copy via ``config=``. Running it here as well would
            # double-transform non-idempotent orchestrators (e.g. nd_vrf/nd_network),
            # reverting user-supplied fields to their hardcoded defaults.
            #
            # For opted-in gathered filtering, config contains query criteria,
            # not complete desired resources. Keep those criteria out of the
            # proposed collection and therefore out of write-state processing.
            proposed_config = [] if gathered_filtering_enabled else raw_config
            self.proposed = NDConfigCollection.from_ansible_config(
                data=proposed_config,
                model_class=self.model_class,
                context={"state": self.state},
            )

            # Argument-spec ``config.options`` drives pruning of gathered output
            # so it round-trips cleanly as ``config``. Derived from the model,
            # so it is generic across modules and needs no per-module wiring.
            gathered_spec = {}
            get_argument_spec = getattr(self.model_class, "get_argument_spec", None)
            if callable(get_argument_spec):
                gathered_spec = get_argument_spec().get("config", {}).get("options", {}) or {}

            self.output.assign(
                after=self.existing,
                before=self.before,
                proposed=self.proposed,
                gathered_spec=gathered_spec,
            )

            if self.model_orchestrator.supports_mutation_outcomes:
                self.confirmed = self.before.copy()
                self.journal = MutationJournal()
                self._update_output_from_journal()

        except Exception as e:
            raise NDStateMachineError(f"Initialization failed: {str(e)}") from e

    # State Management (core function)
    def manage_state(self) -> None:
        """
        Manage state according to desired configuration.
        """
        if self.state == "gathered":
            # Read-only state: __init__ already queried the existing objects and
            # assigned them as ``after`` in the output, so no plan or mutation is needed.
            return

        if self.model_orchestrator.supports_mutation_outcomes:
            self._manage_outcome_state()
            return

        plan = self._build_plan()
        if self.state in ["merged", "replaced", "overridden"]:
            proposed_items = list(self.proposed)

            # Policy-required-on-create guard (issue #350) runs FIRST: it is local-only (self.existing is
            # already in memory), so it fails before the API-backed capability preflight below and before
            # _manage_create_update_state mutates self.existing, which NDOutput aliases as `after`. The shared
            # planner supplies the exact create subset used by standalone and aggregate workflows.
            items_to_create = list(plan.creates)

            # Normalize preflight failures to NDStateMachineError (PR #362 review, gmicol). Both preflight
            # hooks raise a bare RuntimeError (base_interface.preflight_create / the capability preflight),
            # but nd_interface_svi and nd_interface_subinterface_managed/_unmanaged catch only
            # NDStateMachineError at their entrypoint. Without this wrap a policy-less (or capability) preflight
            # failure in those modules escapes as an unhandled RuntimeError, bypassing fail_json and losing the
            # structured before/after/changed output the guard exists to provide. This wrap deliberately does
            # NOT route through _execute_operation: both preflights must run in check mode too, and
            # _execute_operation skips execution during a dry-run.
            try:
                self.model_orchestrator.preflight_create(items_to_create)

                # Capability preflight runs here -- before _manage_create_update_state, whose mutations are
                # skipped in check mode -- so dry-runs surface incapable switches (PR #275 / issue #273).
                self.model_orchestrator.preflight(proposed_items)
            except NDStateMachineError:
                raise
            except Exception as e:
                raise NDStateMachineError(f"Preflight failed: {e}") from e

            # Some resources require an ordered prerequisite mutation after
            # every validation has passed but before their final updates.
            # The default hook is a no-op. Interface Groups use it to remove
            # a member from its current group before adding it to another.
            # Keep this outside the preflight exception wrapper because an
            # implementation can issue a real controller mutation here.
            try:
                self.model_orchestrator.prepare_mutations(
                    existing=self.existing,
                    proposed=self.proposed,
                    check_mode=self.check_mode,
                )
            except NDStateMachineError:
                raise
            except Exception as e:
                raise NDStateMachineError(f"Failed to prepare mutations: {e}") from e

            self._manage_create_update_state(plan)

            if self.state == "overridden":
                self._manage_override_deletions(plan)

        elif self.state == "deleted":
            # Capability preflight intentionally NOT run for deletes: removing configuration does not
            # depend on a switch's capability to host the interface type (PR #275 scope decision).
            # The delete-specific guards run via preflight_delete inside _manage_delete_state.
            self._manage_delete_state(plan)

        else:
            raise NDStateMachineError(f"Invalid state: {self.state}")

    def _manage_outcome_state(self) -> None:
        """Plan without mutating confirmed state; preflight every write first."""
        try:
            plan = self._build_plan()
            # The common planner is shallowly frozen. Own execution evidence
            # before callbacks can enrich or mutate any of its resource models.
            # Collection copies occur once per boundary, never per resource.
            self.plan = replace(
                plan,
                before=plan.before.copy(),
                proposed=plan.proposed.copy(),
                after=plan.after.copy(),
                creates=deepcopy(plan.creates),
                updates=deepcopy(plan.updates),
                deletes=deepcopy(plan.deletes),
            )
            self.planned = self.plan.after.copy()
            if self.state in ("merged", "replaced", "overridden"):
                self.model_orchestrator.preflight_create(list(deepcopy(self.plan.creates)))
                self.model_orchestrator.preflight(list(deepcopy(self.plan.proposed)))
            self.model_orchestrator.preflight_delete(list(deepcopy(self.plan.deletes)))
        except Exception as error:
            self._finalize_outcome_failure(error)
            self.output.assign(failed=True)
            raise NDStateMachineError(f"Planning/preflight failed: {error}") from error

        if self.check_mode:
            self._update_output_from_journal()
            self.output.set_changed(self.plan.changed)
            self.output.set_after_state(self.planned, status="planned")
            self._assign_snapshot_diff(self.planned)
            return

        try:
            # TODO: Merge this opt-in bridge into PR #525's unified executor.
            for item in self.plan.updates:
                self._execute_outcome_request(MutationOperation.UPDATE, (item,), self.model_orchestrator.update, item)
            if self.plan.creates:
                if self.supports_bulk_create:
                    self._execute_outcome_request(MutationOperation.CREATE, self.plan.creates, self.model_orchestrator.create_bulk, list(self.plan.creates))
                else:
                    for item in self.plan.creates:
                        self._execute_outcome_request(MutationOperation.CREATE, (item,), self.model_orchestrator.create, item)
            if self.plan.deletes:
                if self.supports_bulk_delete:
                    self._execute_outcome_request(MutationOperation.DELETE, self.plan.deletes, self.model_orchestrator.delete_bulk, list(self.plan.deletes))
                else:
                    for item in self.plan.deletes:
                        self._execute_outcome_request(MutationOperation.DELETE, (item,), self.model_orchestrator.delete, item)
        except Exception as error:
            self._finalize_outcome_failure(error)
            raise
        # Effects advance per request; public output is materialized only at exit.
        self._update_output_from_journal()

    def _finalize_outcome_failure(self, error: Exception) -> None:
        """Publish partial evidence without hiding an earlier execution failure."""
        try:
            self._update_output_from_journal()
        except Exception as output_error:
            # The complete projection is unavailable. Preserve proven change,
            # but do not let initialized output advertise a safe final snapshot.
            self.output.set_changed(self.journal.changed)
            self.output.mark_after_unknown()
            self.output.assign(
                failed=True,
                reconciliation_complete=False,
                may_have_changed=self.journal.may_have_changed,
                unknown_identifiers=list(self.journal.unknown_identifiers),
                mutation_errors=[str(error), f"Failed to finalize mutation output: {output_error}"],
            )
            raise NDStateMachineError(f"{error}; Failed to finalize mutation output: {output_error}") from error

    def _execute_outcome_request(self, operation: MutationOperation, items, method, *args) -> None:
        """Reconcile resource evidence before propagating task failure."""
        effects = tuple(
            MutationEffect(
                operation,
                item.get_identifier_value(),
                self.confirmed.get(item.get_identifier_value()),
                None if operation is MutationOperation.DELETE else item,
            )
            for item in items
        )
        checkpoint = self.journal.open(phase=operation.value, effects=effects)
        request_transport = self.model_orchestrator.rest_send
        previous_max_attempts = request_transport.max_attempts
        request_transport.max_attempts = 1
        try:
            response = method(*deepcopy(args))
            if not isinstance(response, MutationResult):
                raise TypeError("Outcome-aware mutation must return MutationResult")
            checkpoint.resolve_resources(response)
        except Exception as error:
            if checkpoint.outcome is MutationOutcome.NOT_ATTEMPTED:
                checkpoint.resolve(MutationOutcome.UNKNOWN, may_have_changed=True, error=str(error))
        finally:
            request_transport.max_attempts = previous_max_attempts

        self._apply_confirmed_effects(checkpoint)
        if checkpoint.outcome is not MutationOutcome.SUCCEEDED:
            raise NDStateMachineError(f"{operation.value} failed: {checkpoint.error or checkpoint.outcome.value}")

    def _apply_confirmed_effects(self, checkpoint) -> None:
        """Apply a successful subset even when its enclosing request failed."""
        deletion_effects: list[MutationEffect] = []
        for effect in checkpoint.confirmed_effects:
            if effect.operation is MutationOperation.DELETE:
                deletion_effects.append(effect)
            else:
                item = effect.after
                if self.confirmed.get(effect.identifier) is None:
                    self.confirmed.add(item)
                else:
                    self.confirmed.replace(item)
                self.sent.add(item)
        if deletion_effects:
            self.confirmed.delete_many([effect.identifier for effect in deletion_effects])
            self.removed.add_many([effect.before for effect in deletion_effects])
        self.existing = self.confirmed

    def _assign_snapshot_diff(self, after) -> None:
        diff = {"before": self.before.to_ansible_config(), "after": after.to_ansible_config()} if self.before.get_diff_collection(after) else []
        self.output.assign(diff=diff)

    def _update_output_from_journal(self) -> None:
        """Publish proven change and preserve per-resource failure evidence."""
        action_results = []
        for checkpoint in self.journal.checkpoints:
            outcomes = {item.identifier: item for item in checkpoint.resource_outcomes}
            confirmed_identifiers = {effect.identifier for effect in checkpoint.confirmed_effects}
            for effect in checkpoint.effects:
                outcome = outcomes.get(effect.identifier)
                record = {
                    "identifier": effect.identifier,
                    "operation": effect.operation.value,
                    "outcome": outcome.outcome.value if outcome else checkpoint.outcome.value,
                    "effect_confirmed": effect.identifier in confirmed_identifiers,
                    "statuses": list(outcome.statuses) if outcome else [],
                    "messages": list(outcome.messages) if outcome else [checkpoint.error] if checkpoint.error else [],
                    "correlation": list(outcome.evidence) if outcome else [],
                }
                action_results.append(record)
        self.output.set_changed(self.journal.changed)
        self.output.assign(
            failed=self.journal.has_failed,
            action_results=action_results,
            may_have_changed=self.journal.may_have_changed,
            reconciliation_complete=not self.journal.has_unknown,
            unknown_identifiers=list(self.journal.unknown_identifiers),
            mutation_errors=[checkpoint.error for checkpoint in self.journal.checkpoints if checkpoint.error],
        )
        plan = getattr(self, "plan", None)
        if plan is not None:
            attempted = {(item["operation"], item["identifier"]): item["outcome"] for item in action_results}
            self.output.assign(
                planned_operations=[
                    {
                        "identifier": item.get_identifier_value(),
                        "operation": operation.value,
                        "outcome": attempted.get((operation.value, item.get_identifier_value()), MutationOutcome.NOT_ATTEMPTED.value),
                    }
                    for operation, items in (
                        (MutationOperation.UPDATE, plan.updates),
                        (MutationOperation.CREATE, plan.creates),
                        (MutationOperation.DELETE, plan.deletes),
                    )
                    for item in items
                ]
            )
        if self.journal.has_unknown:
            self.output.mark_after_unknown()
        else:
            self.output.set_after_state(self.confirmed)
            self._assign_snapshot_diff(self.confirmed)

    def _execute_operation(
        self,
        operation: Callable[..., ResponseType],
        *args: Any,
        error_msg_prefix: str = "Operation failed",
        **kwargs: Any,
    ) -> bool:
        """
        # Summary

        Execute an API operation with standardized error handling. Returns `True` when the operation returned, or was skipped because
        the module runs in check mode (a dry run reports intended state), and `False` when it raised and `ignore_errors` swallowed the
        failure. Callers apply an `existing` mutation only on `True`, so a failed request never appears in `after` (issue #597).

        ## Raises

        ### NDStateMachineError

        - If the operation raises and `ignore_errors` is false.
        """
        try:
            if not self.check_mode:
                operation(*args, **kwargs)
            return True
        except Exception as e:
            error_msg = f"{error_msg_prefix}: {e}"
            if not self.ignore_errors:
                raise NDStateMachineError(error_msg) from e
        return False

    def _build_plan(self, state: str | None = None) -> NDStatePlan:
        """Calculate all operations without invoking an orchestrator mutation method."""
        try:
            before = getattr(self, "before", None)
            if before is None:
                before = self.existing
            return NDStatePlanner.plan(
                state=state or self.state,
                before=before,
                proposed=self.proposed,
                ignore_errors=getattr(self, "ignore_errors", False),
            )
        except Exception as e:
            raise NDStateMachineError(str(e)) from e

    def _manage_create_update_state(self, plan: NDStatePlan | None = None) -> None:
        """
        # Summary

        Execute the create/update portion of a precomputed state plan (merged/replaced/overridden). Classification reads `existing` but
        never mutates it; each item is applied to `existing` (which `NDOutput` reports as `after`) only after its request is accepted,
        or in check mode, so a failed run reports `after` and `changed` that describe controller state (issue #597). Qualified updates
        are sent in ND 4.3.1 bulk modify batches; a partial 207 applies only the accepted subset.

        ## Raises

        ### NDStateMachineError

        - If classifying a proposed item fails and `ignore_errors` is false.
        - If an update or create request fails and `ignore_errors` is false.
        """
        plan = plan or self._build_plan()
        execution_baseline = self.existing.copy()
        items_to_create: list[NDBaseModel] = []
        items_to_update: list[NDBaseModel] = []
        items_with_no_diff: list[NDBaseModel] = []

        for proposed_item in self.proposed:
            identifier = None
            try:
                # Extract identifier
                identifier = proposed_item.get_identifier_value()
                # Never modify an existing object this module preserves read-only
                # (unsupported policy type); fail with a focused message instead of
                # silently converting it via replace/override.
                existing_match = self.existing.get(identifier)
                if existing_match is not None and getattr(existing_match, "is_unsupported_policy", False):
                    raise NDStateMachineError(existing_match.describe_unsupported_policy() + "; this module cannot modify it.")

                # Full replacement PUTs must retain only those existing values
                # the model explicitly declares as dynamic or intentionally
                # unsupported-but-writable. Prepare the same candidate for the
                # diff and eventual update so an omitted controller-assigned
                # value cannot cause a perpetual diff or an accidental reset.
                # Merged state already starts from the existing object.
                final_candidate = proposed_item
                if self.state != "merged" and existing_match is not None:
                    final_candidate = proposed_item.prepare_for_replacement(existing_match)

                # Determine diff status
                # For merged state, only compare fields explicitly provided by
                # the user so that Pydantic default values do not trigger false
                # diffs or overwrite existing configuration.
                exclude_unset = self.state == "merged"
                diff_status = self.existing.get_diff_config(final_candidate, exclude_unset=exclude_unset)

                # No changes needed
                if diff_status == "no_diff":
                    # Prefer the complete controller model over a sparse merged
                    # proposal.  Interface deploy reconciliation needs the full
                    # parent/member context to validate any derived 207 rows.
                    items_with_no_diff.append(existing_match or final_candidate)
                    continue

                # Build the item to send WITHOUT touching self.existing (issue #597). `NDBaseModel.merge`
                # mutates self in place, so merged state merges into a deep copy of the existing match;
                # the copy is applied to `existing` only once the controller accepts it.
                if self.state == "merged" and existing_match is not None:
                    final_item = existing_match.model_copy(deep=True).merge(proposed_item)
                elif self.state == "merged":
                    final_item = proposed_item
                else:
                    final_item = final_candidate

                # Categorize by operation type
                if diff_status == "changed":
                    items_to_update.append(final_item)
                elif diff_status == "new":
                    items_to_create.append(final_item)

            except Exception as e:
                if identifier:
                    error_msg = f"Failed to process {identifier}: {e}"
                else:
                    error_msg = f"Failed to process: {e}"
                if not self.ignore_errors:
                    raise NDStateMachineError(error_msg) from e

        # The policy-required-on-create guard (issue #350) runs in manage_state, before the capability
        # preflight and before this method applies anything to self.existing (PR #362 review).

        # ``deploy: true`` is an execution-state request, not merely an intent
        # mutation request.  A previous run can have accepted the PUT/POST and
        # then failed to prove deployment convergence.  On a fresh retry the
        # intent is ``no_diff`` and would otherwise never be deployed again.
        # The base hook is a no-op; interface orchestrators preview these exact
        # resources and queue only those whose convergence is not proven.
        if items_with_no_diff:
            try:
                if self.model_orchestrator.reconcile_no_diff(items_with_no_diff):
                    self.output.mark_changed()
            except Exception as e:
                # Reconciliation is the first runtime action. Planning never applies anything to ``self.existing``
                # (issue #597), so on failure ``after`` already describes the execution baseline; only the
                # error needs normalizing.
                self.output.assign(after=self.existing)
                raise NDStateMachineError(f"Failed to reconcile unchanged resources: {e}") from e

        # Execute updates: guarded description-only updates and family-qualified full policy updates go out in ND 4.3.1
        # bulk modify batches, everything else singular. Each item is applied to ``self.existing`` only once accepted
        # (issue #597): a failed singular update may still have been accepted by the controller before a later step failed
        # (the orchestrator reports it as ``_accepted_post_write_model``), and a failed bulk request answered with a 207 names
        # the accepted subset. Nothing is applied before acceptance, so no rollback is needed. ``previous_model`` is read
        # from the baseline so the orchestrator always sees the pre-run controller model, independent of apply order.
        pending_bulk: list[tuple[NDBaseModel, NDBaseModel | None, dict[str, Any], str]] = []

        def apply_accepted_post_write(item: NDBaseModel) -> None:
            # The orchestrator reports a PUT the controller accepted before a later step (member preview) failed. Honour it whether the
            # failure propagates or ``ignore_errors`` swallows it (PR #608 review); otherwise the accepted write vanishes from ``after``.
            post_write = getattr(self.model_orchestrator, "_accepted_post_write_model", None)
            if (
                post_write is not None
                and getattr(post_write, "switch_ip", None) == getattr(item, "switch_ip", None)
                and str(getattr(post_write, "interface_name", "")).casefold() == str(getattr(item, "interface_name", "")).casefold()
            ):
                self._apply_accepted([post_write])

        def run_singular_update(item: NDBaseModel, previous: NDBaseModel | None) -> None:
            try:
                accepted = self._execute_operation(
                    self.model_orchestrator.update,
                    item,
                    previous_model=previous,
                    error_msg_prefix=f"Failed to update {item.get_identifier_value()}",
                )
            except Exception:
                apply_accepted_post_write(item)
                raise
            if accepted:
                self._apply_accepted([item])
            else:
                apply_accepted_post_write(item)

        def flush_bulk() -> None:
            if not pending_bulk:
                return
            batch = list(pending_bulk)
            pending_bulk.clear()
            if len(batch) == 1:
                item, previous, _payload, _mode = batch[0]
                run_singular_update(item, previous)
                return
            orchestrator = self.model_orchestrator
            for item, previous, _payload, _mode in batch:
                orchestrator.prepare_bulk_modify_context(item, previous)
            recorded = orchestrator.rest_send.response_count
            try:
                accepted = self._execute_operation(
                    orchestrator.modify_bulk_prepared,
                    [payload for _item, _previous, payload, _mode in batch],
                    payload_orchestrators=[orchestrator for _item, _previous, _payload, _mode in batch],
                    payload_models=[item for item, _previous, _payload, _mode in batch],
                    payload_modes=[mode for _item, _previous, _payload, mode in batch],
                    error_msg_prefix=f"Failed to update {len(batch)} interfaces in bulk",
                )
            except Exception:
                if orchestrator.rest_send.response_count > recorded and orchestrator.rest_send.return_code == 207:
                    names = {
                        (payload["switchId"].casefold(), item.interface_name.casefold()): (payload["switchId"], item.interface_name)
                        for item, _previous, payload, _mode in batch
                    }
                    peer_switch_ids = {
                        (payload["switchId"].casefold(), item.interface_name.casefold()): payload["configData"]["networkOS"]["policy"]["peerSwitchId"]
                        for item, _previous, payload, _mode in batch
                        if str(payload.get("interfaceType") or "").casefold() == "vpc"
                    }
                    accepted_pairs, _exact = orchestrator._bulk_modify_classify_result_pairs(names, peer_switch_ids=peer_switch_ids)
                    self._apply_accepted(
                        [
                            item
                            for item, _previous, payload, _mode in batch
                            if (payload["switchId"].casefold(), item.interface_name.casefold()) in accepted_pairs
                        ]
                    )
                raise
            if accepted:
                self._apply_accepted([item for item, _previous, _payload, _mode in batch])

        for item in items_to_update:
            previous = execution_baseline.get(item.get_identifier_value())
            payload = None
            mode = "description"
            prepare = getattr(self.model_orchestrator, "prepare_bulk_description_update", None)
            if not self.check_mode and not self.ignore_errors and callable(prepare):
                payload = prepare(item, previous)
            if payload is None and not self.check_mode and not self.ignore_errors:
                prepare_full = getattr(self.model_orchestrator, "prepare_bulk_full_update", None)
                if callable(prepare_full):
                    payload = prepare_full(item, previous)
                    mode = "full"
            if payload is not None:
                if pending_bulk and (
                    len(pending_bulk) >= 10000
                    or any(
                        previous_payload["switchId"] == payload["switchId"] and previous_item.interface_name.casefold() == item.interface_name.casefold()
                        for previous_item, _old, previous_payload, _mode in pending_bulk
                    )
                ):
                    flush_bulk()
                pending_bulk.append((item, previous, payload, mode))
                continue
            flush_bulk()
            run_singular_update(item, previous)
        flush_bulk()

        # Execute creates (bulk or individual); apply each only once accepted.
        if items_to_create:
            if self.supports_bulk_create:
                self._create_bulk_deferred(items_to_create)
            else:
                for item in items_to_create:
                    if self._execute_operation(self.model_orchestrator.create, item, error_msg_prefix=f"Failed to create {item.get_identifier_value()}"):
                        self._apply_accepted([item])

        # Log operation
        self.output.assign(after=self.existing)

    def _apply_accepted(self, items: Sequence[NDBaseModel]) -> None:
        """
        # Summary

        Record controller-accepted create/update items: apply each to `existing` (replace when the identifier is already present,
        else add) and add it to `sent`. Called only after an item's request succeeded, in check mode (a dry run reports intended
        state), or for the accepted subset of a failed bulk create (issue #597).

        ## Raises

        None
        """
        for item in items:
            if self.existing.get(item.get_identifier_value()) is not None:
                self.existing.replace(item)
            else:
                self.existing.add(item)
        if items:
            self.sent.add_many(list(items))

    def _create_bulk_deferred(self, items: list[NDBaseModel]) -> list[NDBaseModel]:
        """
        # Summary

        Send one bulk create and apply to `existing` only the items the controller accepted (issue #597). On success that is every
        item. On a failed request, whether it propagates or `ignore_errors` swallows it, the orchestrator's `accepted_mutations` hook
        names the accepted subset (interface orchestrators read their deploy queue; the base default is none), which is applied before
        the error propagates so `after` and `changed` describe controller state. Returns the applied items.

        ## Raises

        ### NDStateMachineError

        - If the bulk create fails and `ignore_errors` is false; re-raised after the accepted subset is applied.
        """
        try:
            succeeded = self._execute_operation(self.model_orchestrator.create_bulk, items, error_msg_prefix="Failed to create in bulk")
        except NDStateMachineError:
            self._apply_accepted(self._hook_result("accepted_mutations", items) or [])
            raise
        accepted = list(items) if succeeded else (self._hook_result("accepted_mutations", items) or [])
        self._apply_accepted(accepted)
        return accepted

    def _warn_unsupported(self, collection) -> None:
        """Warn once per object whose type this module preserves read-only."""
        if not hasattr(self.module, "warn"):
            return
        for item in collection:
            if getattr(item, "is_unsupported_policy", False):
                self.module.warn(item.describe_unsupported_policy() + "; it is read-only and will not be modified or deleted by this module.")

    def _manage_override_deletions(self, plan: NDStatePlan | None = None) -> None:
        """Delete items not in proposed config for overridden state."""
        plan = plan or self._build_plan("overridden")
        self._delete_items(list(plan.deletes))

    def _manage_delete_state(self, plan: NDStatePlan | None = None) -> None:
        """Handle deleted state."""
        items_to_delete = []
        absent_items = []
        for proposed_item in self.proposed:
            existing_item = self.existing.get(proposed_item.get_identifier_value())
            if existing_item is None:
                absent_items.append(proposed_item)
                continue
            # An explicit delete that resolves to an unsupported object fails with a
            # focused message rather than blindly removing something we cannot model.
            if getattr(existing_item, "is_unsupported_policy", False):
                raise NDStateMachineError(existing_item.describe_unsupported_policy() + "; this module cannot delete it.")
            items_to_delete.append(existing_item)
        # Delete preflight also covers absent targets before deploy-recovery preview: a type-filtered
        # inventory must not let a named member or fabric-owned interface bypass the delete guards.
        # This runs before _delete_items, whose mutation is skipped in check mode.
        # Same error normalization as the create/update preflights in manage_state.
        try:
            self.model_orchestrator.preflight_delete([*items_to_delete, *absent_items])
        except NDStateMachineError:
            raise
        except Exception as e:
            raise NDStateMachineError(f"Preflight failed: {e}") from e
        if absent_items:
            try:
                if self.model_orchestrator.reconcile_absent_deletes(absent_items):
                    self.output.mark_changed()
            except Exception as e:
                raise NDStateMachineError(f"Failed to reconcile absent deleted resources: {e}") from e
        self._delete_items(items_to_delete)

    def _delete_items(self, items: list[NDBaseModel]) -> None:
        """
        # Summary

        Delete `items` in bulk or one at a time, applying to `removed` and `existing` (reported as `after`) only the removals the
        controller accepted (issue #597, final review). A bulk delete is all-or-nothing from the state machine's view: every item on
        success, none when `ignore_errors` swallows the failure. Per-item deletes are applied per accepted item: a swallowed failure is
        not recorded as removed, and when a failure propagates the items deleted before it are applied first, so `after` and `changed`
        describe controller state.

        ## Raises

        ### NDStateMachineError

        - If a delete request fails and `ignore_errors` is false; re-raised after the removals accepted before it are applied.
        """
        if not items:
            return

        if self.supports_bulk_delete:
            succeeded = self._execute_operation(self.model_orchestrator.delete_bulk, items, error_msg_prefix="Failed to delete in bulk")
            self._apply_removed(items if succeeded else [])
            return

        accepted: list[NDBaseModel] = []
        try:
            for item in items:
                if self._execute_operation(self.model_orchestrator.delete, item, error_msg_prefix=f"Failed to delete {item.get_identifier_value()}"):
                    accepted.append(item)
        except NDStateMachineError:
            self._apply_removed(accepted)
            raise
        self._apply_removed(accepted)

    def _apply_removed(self, accepted: Sequence[NDBaseModel]) -> None:
        """
        # Summary

        Record controller-accepted removals: add them to `removed` and drop them from `existing` (one index rebuild), then refresh
        `after`. Marks items as removed only after their API operation succeeded, mirroring `sent` (issue #597, final review).

        ## Raises

        None
        """
        self.removed.add_many(list(accepted))
        self.existing.delete_many([item.get_identifier_value() for item in accepted])
        self.output.assign(after=self.existing)

    def _hook_result(self, name: str, items: Sequence[NDBaseModel]) -> list[NDBaseModel] | None:
        """
        # Summary

        Call the orchestrator failure-path hook `name` (`accepted_mutations` or `unaccepted_removals`) with `items` and return its result
        as a list, or `None` when the hook itself raised. The hook failure is logged, never replaces the original error, and never raises
        from `reconcile_after_failure`; each caller decides what `None` means for its side (issue #597, final review): a failed
        `accepted_mutations` lookup applies nothing, a failed `unaccepted_removals` lookup restores every removal, so an uncertain
        controller state is always reported as the smaller change rather than claimed as done.

        ## Raises

        None
        """
        try:
            return list(getattr(self.model_orchestrator, name)(list(items)))
        except Exception:  # pylint: disable=broad-exception-caught
            log.exception("%s.%s hook failed; its answer is unknown", type(self.model_orchestrator).__name__, name)
            return None

    def reconcile_after_failure(self) -> None:
        """
        # Summary

        Restore to `existing` (reported as `after`) the removed items whose delete-side request the controller has not accepted, so a
        failure after `manage_state` (an interface orchestrator's `remove_pending`, whose `delete_bulk` only queues) does not report
        interfaces the controller still holds as gone (issue #597). The orchestrator's `unaccepted_removals` hook names them (interface
        orchestrators read their delete-side queues; the base default is none). Each is re-added from `before` and dropped from
        `removed`. When the hook raises, which removals the controller accepted is unknown, so every recorded removal is restored:
        a removal that did happen then reads as still present and a retry simply finds it gone, whereas reporting an unsent removal
        as done would mislead the caller. Idempotent and safe to call when nothing failed or nothing was removed. Called by
        `fail_from_exception`.

        ## Raises

        None
        """
        if len(self.removed) == 0:
            return
        unaccepted = self._hook_result("unaccepted_removals", list(self.removed))
        if unaccepted is None:
            unaccepted = list(self.removed)
        if not unaccepted:
            return
        unaccepted_keys = {item.get_identifier_value() for item in unaccepted}
        for key in unaccepted_keys:
            before_item = self.before.get(key)
            if before_item is not None and self.existing.get(key) is None:
                self.existing.add(deepcopy(before_item))
        still_removed = [item for item in self.removed if item.get_identifier_value() not in unaccepted_keys]
        self.removed = NDConfigCollection(model_class=self.model_class)
        self.removed.add_many(still_removed)
        self.output.assign(after=self.existing)
