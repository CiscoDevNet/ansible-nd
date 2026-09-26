# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from typing import Any, Callable

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_plan import NDStatePlan, NDStatePlanner
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
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
        if self.state == "gathered":
            # Read-only state: __init__ already queried the existing objects and
            # assigned them as ``after`` in the output, so no plan or mutation is needed.
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

    def _execute_operation(
        self,
        operation: Callable[..., ResponseType],
        *args: Any,
        error_msg_prefix: str = "Operation failed",
        **kwargs: Any,
    ) -> ResponseType | None:
        """Execute an API operation with standardized error handling."""
        try:
            if not self.check_mode:
                return operation(*args, **kwargs)
            return None
        except Exception as e:
            error_msg = f"{error_msg_prefix}: {e}"
            if not self.ignore_errors:
                raise NDStateMachineError(error_msg) from e
        return None

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
        """Execute the create/update portion of a precomputed state plan."""
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

                # Prepare final config based on state
                if self.state == "merged":
                    # Merge with existing
                    final_item = self.existing.merge(proposed_item)
                else:
                    # Replace or creates
                    if diff_status == "changed":
                        self.existing.replace(final_candidate)
                    else:
                        self.existing.add(final_candidate)
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
        # preflight and before this method mutates self.existing (PR #362 review).

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
                # Planning above mutates ``self.existing`` before any I/O so
                # check mode can expose the intended result. Reconciliation is
                # the first runtime action; if its read-only preview is
                # contradictory or otherwise fails, no proposed mutation has
                # been accepted and failure output must retain the execution
                # baseline rather than advertise every planned create/update.
                self.existing = execution_baseline.copy()
                self.output.assign(after=self.existing)
                raise NDStateMachineError(f"Failed to reconcile unchanged resources: {e}") from e

        # Execute updates (always individual). Planning above mutates
        # ``self.existing`` before I/O so check mode can expose the intended
        # result. If a real update fails, rebuild ``after`` from the execution
        # baseline plus only the preceding updates the controller accepted;
        # otherwise a rejected and every not-yet-attempted update appear as
        # successful in changed/after output.
        accepted_updates: list[NDBaseModel] = []
        try:
            for item in items_to_update:
                self._execute_operation(
                    self.model_orchestrator.update,
                    item,
                    previous_model=execution_baseline.get(item.get_identifier_value()),
                    error_msg_prefix=f"Failed to update {item.get_identifier_value()}",
                )
                accepted_updates.append(item)
        except Exception:
            self.existing = execution_baseline.copy()
            for item in accepted_updates:
                if not self.existing.replace(item):
                    self.existing.add(item)
            if accepted_updates:
                self.sent.add_many(accepted_updates)
            self.output.assign(after=self.existing)
            raise

        # Execute creates (bulk or individual)
        if items_to_create:
            if self.supports_bulk_create:
                self._execute_operation(self.model_orchestrator.create_bulk, items_to_create, error_msg_prefix="Failed to create in bulk")
            else:
                for item in items_to_create:
                    self._execute_operation(self.model_orchestrator.create, item, error_msg_prefix=f"Failed to create {item.get_identifier_value()}")

        # Mark as sent only after successful API operations
        successfully_sent = items_to_update + items_to_create
        if successfully_sent:
            self.sent.add_many(successfully_sent)

        # Log operation
        self.output.assign(after=self.existing)

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
        """Delete a list of items individually or in bulk."""
        if not items:
            return

        # Execute deletes (bulk or individual)
        if self.supports_bulk_delete:
            self._execute_operation(self.model_orchestrator.delete_bulk, items, error_msg_prefix="Failed to delete in bulk")
        else:
            for item in items:
                self._execute_operation(self.model_orchestrator.delete, item, error_msg_prefix=f"Failed to delete {item.get_identifier_value()}")

        # Mark as removed only after successful API operations, mirroring ``sent``.
        self.removed.add_many(items)

        # Batch remove from collection (single index rebuild)
        keys_to_delete = [item.get_identifier_value() for item in items]
        self.existing.delete_many(keys_to_delete)

        # Log deletion
        self.output.assign(after=self.existing)
