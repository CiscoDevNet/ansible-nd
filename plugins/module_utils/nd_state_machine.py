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

    WRITE_STATES_REQUIRING_CONFIG = frozenset({"merged", "replaced", "overridden"})

    @classmethod
    def validate_config_presence(cls, state: str, config: Any) -> None:
        """
        Reject omitted or null config before production wrappers normalize it.

        An explicit empty list remains valid because it can represent an
        intentional empty desired set.
        """
        if state in cls.WRITE_STATES_REQUIRING_CONFIG and config is None:
            raise NDStateMachineError(
                f"config must be provided and cannot be null for state '{state}'. "
                "Use config: [] only when intentionally managing an explicit empty set."
            )

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
        self.output = NDOutput(output_level=module.params.get("output_level", "normal"))
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
        raw_config = self.module.params.get("config")
        self.validate_config_presence(self.state, raw_config)

        # Cached flags
        self.check_mode = self.module.check_mode
        self.ignore_errors = self.module.params.get("ignore_errors", False)
        self.supports_bulk_create = self.model_orchestrator.supports_bulk_create
        self.supports_bulk_delete = self.model_orchestrator.supports_bulk_delete

        # Initialize collections
        try:
            response_data = self.model_orchestrator.query_all()
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
            self.proposed = NDConfigCollection.from_ansible_config(data=raw_config, model_class=self.model_class, context={"state": self.state})

            self.output.assign(after=self.existing, before=self.before, proposed=self.proposed)

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
    ) -> bool:
        """Execute an API operation with standardized error handling.

        Returns True if the operation completed without raising. In check mode
        the API call is skipped but still reported as completed (True) so that
        the previewed 'after' state can be built. Returns False only when the
        operation raised and the error was suppressed via ``ignore_errors``.

        The orchestrator's return value is deliberately not used as the success
        signal: some orchestrators defer the actual API call (queue-and-deploy)
        and legitimately return None on success.
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
                # diffs or overwrite existing configuration. Merged also matches
                # list elements one-directionally (allow_superset) so an
                # existing item with extra list entries is not seen as changed.
                exclude_unset = self.state == "merged"
                diff_status = self.existing.get_diff_config(proposed_item, exclude_unset=exclude_unset, allow_superset=exclude_unset)

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

        # Execute updates (always individual). An operation that does not fail
        # is counted as sent; check mode skips the API call but returns True.
        successfully_sent: list[NDBaseModel] = []
        for item in items_to_update:
            if self._execute_operation(self.model_orchestrator.update, item, error_msg_prefix=f"Failed to update {item.get_identifier_value()}"):
                successfully_sent.append(item)

        # Execute creates (bulk or individual)
        if items_to_create:
            if self.supports_bulk_create:
                if self._execute_operation(self.model_orchestrator.create_bulk, items_to_create, error_msg_prefix="Failed to create in bulk"):
                    successfully_sent.extend(items_to_create)
            else:
                for item in items_to_create:
                    if self._execute_operation(self.model_orchestrator.create, item, error_msg_prefix=f"Failed to create {item.get_identifier_value()}"):
                        successfully_sent.append(item)

        # Mark as sent only for items actually pushed to the controller. In
        # check mode no API call is made, so nothing is marked as sent (avoids
        # false deploy triggers); the previewed 'after' state is still reflected
        # in self.existing (mutated above), which is what drives 'changed'.
        if not self.check_mode and successfully_sent:
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

        # Execute deletes (bulk or individual). An item is counted as deleted
        # when the operation does not fail; check mode skips the API call but
        # returns True so the deletion is still previewed. Items whose delete
        # failed under ignore_errors are left in 'existing' so the reported
        # 'after' state stays accurate.
        deleted: list[NDBaseModel] = []
        if self.supports_bulk_delete:
            if self._execute_operation(self.model_orchestrator.delete_bulk, items, error_msg_prefix="Failed to delete in bulk"):
                deleted.extend(items)
        else:
            for item in items:
                if self._execute_operation(self.model_orchestrator.delete, item, error_msg_prefix=f"Failed to delete {item.get_identifier_value()}"):
                    deleted.append(item)

        # Batch remove from collection (single index rebuild).
        self.existing.delete_many([item.get_identifier_value() for item in deleted])

        # Mark as sent only for items actually pushed to the controller. In
        # check mode no API call is made, so nothing is marked as sent (avoids
        # false deploy triggers).
        if not self.check_mode and deleted:
            self.sent.add_many(deleted)

        # Log deletion
        self.output.assign(after=self.existing)
