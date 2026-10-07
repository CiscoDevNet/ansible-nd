# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

import logging
from collections.abc import Sequence
from copy import deepcopy
from typing import Any, Callable

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
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
            response_data = self.model_orchestrator.query_all()
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
            raw_config = config if config is not None else (self.module.params.get("config") or [])
            self.proposed = NDConfigCollection.from_ansible_config(data=raw_config, model_class=self.model_class, context={"state": self.state})

            # Argument-spec ``config.options`` drives pruning of gathered output
            # so it round-trips cleanly as ``config``. Derived from the model,
            # so it is generic across modules and needs no per-module wiring.
            gathered_spec = {}
            get_argument_spec = getattr(self.model_class, "get_argument_spec", None)
            if callable(get_argument_spec):
                gathered_spec = get_argument_spec().get("config", {}).get("options", {}) or {}

            self.output.assign(after=self.existing, before=self.before, proposed=self.proposed, gathered_spec=gathered_spec)

        except Exception as e:
            raise NDStateMachineError(f"Initialization failed: {str(e)}") from e

    # State Management (core function)
    def manage_state(self) -> None:
        """
        Manage state according to desired configuration.
        """
        if self.state in ["merged", "replaced", "overridden"]:
            proposed_items = list(self.proposed)

            # Policy-required-on-create guard (issue #350) runs FIRST: it is local-only (self.existing is
            # already in memory), so it fails before the API-backed capability preflight below and before
            # _manage_create_update_state mutates self.existing, which NDOutput aliases as `after`. Create
            # subset = proposed items not present in the existing inventory -- the same key-membership
            # criterion get_diff_config uses to classify "new" (PR #362 review).
            items_to_create = [item for item in proposed_items if self.existing.get(item.get_identifier_value()) is None]

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

            self._manage_create_update_state()

            if self.state == "overridden":
                self._manage_override_deletions()

        elif self.state == "deleted":
            # Capability preflight intentionally NOT run for deletes: removing configuration does not
            # depend on a switch's capability to host the interface type (PR #275 scope decision).
            # The delete-specific guards run via preflight_delete inside _manage_delete_state.
            self._manage_delete_state()

        elif self.state == "gathered":
            # Read-only state: __init__ already queried the existing objects and
            # assigned them as ``after`` in the output, so no changes are made.
            pass

        else:
            raise NDStateMachineError(f"Invalid state: {self.state}")

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

    def _manage_create_update_state(self) -> None:
        """
        # Summary

        Handle merged/replaced/overridden states. Classification reads `existing` but never mutates it; each item is applied to
        `existing` (which `NDOutput` reports as `after`) only after its request is accepted, or in check mode, so a failed run reports
        `after` and `changed` that describe controller state (issue #597).

        ## Raises

        ### NDStateMachineError

        - If classifying a proposed item fails and `ignore_errors` is false.
        - If an update or create request fails and `ignore_errors` is false.
        """
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

        # Execute updates (always individual); apply each only once accepted (issue #597). Nothing is applied
        # before acceptance, so when an update fails ``self.existing`` already equals the execution baseline plus
        # the accepted updates and no rollback is needed. ``previous_model`` is read from the baseline so the
        # orchestrator always sees the pre-run controller model, independent of apply order.
        for item in items_to_update:
            if self._execute_operation(
                self.model_orchestrator.update,
                item,
                previous_model=execution_baseline.get(item.get_identifier_value()),
                error_msg_prefix=f"Failed to update {item.get_identifier_value()}",
            ):
                self._apply_accepted([item])

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
            self._apply_accepted(self._hook_result("accepted_mutations", items))
            raise
        accepted = list(items) if succeeded else self._hook_result("accepted_mutations", items)
        self._apply_accepted(accepted)
        return accepted

    def _warn_unsupported(self, collection) -> None:
        """Warn once per object whose type this module preserves read-only."""
        if not hasattr(self.module, "warn"):
            return
        for item in collection:
            if getattr(item, "is_unsupported_policy", False):
                self.module.warn(item.describe_unsupported_policy() + "; it is read-only and will not be modified or deleted by this module.")

    def _manage_override_deletions(self) -> None:
        """
        Delete items not in proposed config (for overridden state).
        """
        diff_identifiers = self.before.get_diff_identifiers(self.proposed)
        # Never implicitly delete an unsupported (opaque) object during reconciliation;
        # it is absent from the user's proposed config only because it cannot be modeled.
        items_to_delete = [
            existing_item
            for identifier in diff_identifiers
            if (existing_item := self.existing.get(identifier)) is not None and not getattr(existing_item, "is_unsupported_policy", False)
        ]
        self._delete_items(items_to_delete)

    def _manage_delete_state(self) -> None:
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

    def _hook_result(self, name: str, items: Sequence[NDBaseModel]) -> list[NDBaseModel]:
        """
        # Summary

        Call the orchestrator failure-path hook `name` (`accepted_mutations` or `unaccepted_removals`) with `items` and return its result
        as a list. A hook that raises is logged and treated as naming nothing, so a defective hook never replaces the original error and
        never raises from `reconcile_after_failure` (issue #597, final review).

        ## Raises

        None
        """
        try:
            return list(getattr(self.model_orchestrator, name)(list(items)))
        except Exception:  # pylint: disable=broad-exception-caught
            log.exception("%s.%s hook failed; treating it as naming no items", type(self.model_orchestrator).__name__, name)
            return []

    def reconcile_after_failure(self) -> None:
        """
        # Summary

        Restore to `existing` (reported as `after`) the removed items whose delete-side request the controller has not accepted, so a
        failure after `manage_state` (an interface orchestrator's `remove_pending`, whose `delete_bulk` only queues) does not report
        interfaces the controller still holds as gone (issue #597). The orchestrator's `unaccepted_removals` hook names them (interface
        orchestrators read their delete-side queues; the base default is none). Each is re-added from `before` and dropped from
        `removed`. Idempotent and safe to call when nothing failed or nothing was removed. Called by `fail_from_exception`.

        ## Raises

        None
        """
        if len(self.removed) == 0:
            return
        unaccepted = self._hook_result("unaccepted_removals", list(self.removed))
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
