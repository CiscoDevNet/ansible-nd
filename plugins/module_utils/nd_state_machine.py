# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from typing import Any, Callable

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import filter_gathered_response, validate_gathered_filters
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


class NDStateMachine:
    """
    Generic State Machine for Nexus Dashboard (Bulk Support).
    """

    def __init__(self, module: AnsibleModule, model_orchestrator: type[NDBaseOrchestrator] | NDBaseOrchestrator):
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
        self.output = NDOutput(output_level=module.params.get("output_level", "normal"), state=module.params.get("state", ""), )
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
        # every module rather than per-module boilerplate.
        for config_item in self.module.params.get("config") or []:
            self.module.no_log_values |= self.model_class.collect_secret_values(config_item)

        # Initialize collections
        try:
            raw_config = self.module.params.get("config") or []
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
            # State of current configuration objects in ND during change execution
            self.existing = self.before.copy()
            # Ongoing collection of configuration objects that were changed
            self.sent = NDConfigCollection(model_class=self.model_class)
            # Collection of configuration objects given by user.
            # ``context={"state": ...}`` is threaded into pydantic validation so models can apply
            # state-aware validation (e.g. require certain fields for write states while accepting
            # identifier-only items for ``deleted``). Models that do not read the context ignore it.


            # For opted-in gathered filtering, config contains query criteria,
            # not complete desired resources. Preserve the original proposed
            # config flow for every state/model that has not opted in.
            proposed_config = [] if gathered_filtering_enabled else raw_config
            proposed_config = self.model_orchestrator.prepare_config_data(proposed_config)
            self.proposed = NDConfigCollection.from_ansible_config(data=proposed_config, model_class=self.model_class, context={"state": self.state})


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
            self._manage_delete_state()

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

    def _manage_create_update_state(self) -> None:
        """
        Handle merged/replaced/overridden states.
        """
        items_to_create: list[NDBaseModel] = []
        items_to_update: list[NDBaseModel] = []

        for proposed_item in self.proposed:
            identifier = None
            try:
                # Extract identifier
                identifier = proposed_item.get_identifier_value()
                # Determine diff status
                # For merged state, only compare fields explicitly provided by
                # the user so that Pydantic default values do not trigger false
                # diffs or overwrite existing configuration.
                exclude_unset = self.state == "merged"
                diff_status = self.existing.get_diff_config(proposed_item, exclude_unset=exclude_unset)

                # No changes needed
                if diff_status == "no_diff":
                    continue

                # Prepare final config based on state
                if self.state == "merged":
                    # Merge with existing
                    final_item = self.existing.merge(proposed_item)
                else:
                    # Replace or creates
                    if diff_status == "changed":
                        self.existing.replace(proposed_item)
                    else:
                        self.existing.add(proposed_item)
                    final_item = proposed_item

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

        # Execute updates (always individual)
        for item in items_to_update:
            self._execute_operation(self.model_orchestrator.update, item, error_msg_prefix=f"Failed to update {item.get_identifier_value()}")

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

    def _manage_override_deletions(self) -> None:
        """
        Delete items not in proposed config (for overridden state).
        """
        diff_identifiers = self.before.get_diff_identifiers(self.proposed)
        items_to_delete = [existing_item for identifier in diff_identifiers if (existing_item := self.existing.get(identifier)) is not None]
        self._delete_items(items_to_delete)

    def _manage_delete_state(self) -> None:
        """Handle deleted state."""
        items_to_delete = [
            existing_item for proposed_item in self.proposed if (existing_item := self.existing.get(proposed_item.get_identifier_value())) is not None
        ]
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

        # Batch remove from collection (single index rebuild)
        keys_to_delete = [item.get_identifier_value() for item in items]
        self.existing.delete_many(keys_to_delete)

        # Log deletion
        self.output.assign(after=self.existing)
