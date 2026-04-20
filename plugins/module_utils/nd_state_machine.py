# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Any, Callable, List, Optional, Type, Union

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


class NDStateMachine:
    """
    Generic State Machine for Nexus Dashboard (Bulk Support).
    """

    def __init__(self, module: AnsibleModule, model_orchestrator: Union[Type[NDBaseOrchestrator], NDBaseOrchestrator]):
        """
        Initialize the ND State Machine.
        """
        self.module = module

        # REST infrastructure
        sender = Sender()
        sender.ansible_module = self.module

        self.rest_send = RestSend(
            {
                "check_mode": self.module.check_mode,
                "state": self.module.params.get("state"),
            }
        )
        self.rest_send.sender = sender
        self.rest_send.response_handler = ResponseHandler()
        # Disable the retry loop inherited from RestSend (designed for NDFC
        # eventual-consistency).  ND orchestrator CRUD operations should fail
        # immediately rather than retrying for 300 seconds.
        self.rest_send.timeout = self.rest_send.send_interval

        # Operation tracking
        self.output = NDOutput(output_level=module.params.get("output_level", "normal"))

        # Configuration
        # Accept either an orchestrator instance or a class.
        if isinstance(model_orchestrator, type) and issubclass(model_orchestrator, NDBaseOrchestrator):
            self.model_orchestrator = model_orchestrator(rest_send=self.rest_send)
        elif isinstance(model_orchestrator, NDBaseOrchestrator):
            self.model_orchestrator = model_orchestrator
        else:
            raise NDStateMachineError(f"model_orchestrator must be an NDBaseOrchestrator class or instance. Got: {type(model_orchestrator)}")

        self.model_class = self.model_orchestrator.model_class
        self.state = self.module.params["state"]

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
            # Collection of configuration objects given by user
            self.proposed = NDConfigCollection.from_ansible_config(data=self.module.params.get("config", []), model_class=self.model_class)

            self.output.assign(after=self.existing, before=self.before, proposed=self.proposed)

        except Exception as e:
            raise NDStateMachineError(f"Initialization failed: {str(e)}") from e

    # State Management (core function)
    def manage_state(self) -> None:
        """
        Manage state according to desired configuration.
        """
        if self.state in ["merged", "replaced", "overridden"]:
            self._manage_create_update_state()

            if self.state == "overridden":
                self._manage_override_deletions()

        elif self.state == "deleted":
            self._manage_delete_state()

        else:
            raise NDStateMachineError(f"Invalid state: {self.state}")

    def _execute_operation(
        self,
        operation: Callable[..., ResponseType],
        *args: Any,
        error_msg_prefix: str = "Operation failed",
        **kwargs: Any,
    ) -> Optional[ResponseType]:
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
        items_to_create: List[NDBaseModel] = []
        items_to_update: List[NDBaseModel] = []

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

    def _delete_items(self, items: List[NDBaseModel]) -> None:
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
