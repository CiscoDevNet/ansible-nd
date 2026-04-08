# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Type
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError


class NDStateMachine:
    """
    Generic State Machine for Nexus Dashboard (Bulk Support).
    """

    def __init__(self, module: AnsibleModule, model_orchestrator: Type[NDBaseOrchestrator]):
        """
        Initialize the ND State Machine.
        """
        self.module = module
        self.nd_module = NDModule(self.module)

        # Operation tracking
        self.output = NDOutput(output_level=module.params.get("output_level", "normal"))

        # Configuration
        # Accept either an orchestrator instance or a class.
        if isinstance(model_orchestrator, type):
            self.model_orchestrator = model_orchestrator(sender=self.nd_module)
        else:
            self.model_orchestrator = model_orchestrator

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
        # Execute state operations
        if self.state in ["merged", "replaced", "overridden"]:
            self._manage_create_update_state()

            if self.state == "overridden":
                self._manage_override_deletions()

        elif self.state == "deleted":
            self._manage_delete_state()

        else:
            raise NDStateMachineError(f"Invalid state: {self.state}")

    def _manage_create_update_state(self) -> None:
        """
        Handle merged/replaced/overridden states.
        """
        items_to_create_bulk = []

        for proposed_item in self.proposed:
            # Extract identifier
            identifier = proposed_item.get_identifier_value()
            try:
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
                    # Replace or create
                    if diff_status == "changed":
                        self.existing.replace(proposed_item)
                    else:
                        self.existing.add(proposed_item)
                    final_item = proposed_item

                # Execute API operation
                if diff_status == "changed":
                    if not self.check_mode:
                        self.model_orchestrator.update(final_item)
                elif diff_status == "new":
                    if not self.check_mode:
                        if self.supports_bulk_create:
                            items_to_create_bulk.append(final_item)
                        else:
                            self.model_orchestrator.create(final_item)
                self.sent.add(final_item)

            except Exception as e:
                error_msg = f"Failed to process {identifier}: {e}"
                if not self.ignore_errors:
                    raise NDStateMachineError(error_msg) from e

        # Execute API bulk create operation
        if items_to_create_bulk:
            try:
                self.model_orchestrator.create_bulk(items_to_create_bulk)
            except Exception as e:
                error_msg = f"Failed to create in bulk: {e}"
                if not self.ignore_errors:
                    raise NDStateMachineError(error_msg) from e

        # Log operation
        self.output.assign(after=self.existing)

    def _manage_override_deletions(self) -> None:
        """
        Delete items not in proposed config (for overridden state).
        """
        diff_identifiers = self.before.get_diff_identifiers(self.proposed)
        items_to_delete = []

        for identifier in diff_identifiers:
            existing_item = self.existing.get(identifier)
            if existing_item:
                items_to_delete.append(existing_item)

        self._delete_items(items_to_delete)

    def _manage_delete_state(self) -> None:
        """Handle deleted state."""
        items_to_delete = []

        for proposed_item in self.proposed:
            identifier = proposed_item.get_identifier_value()
            existing_item = self.existing.get(identifier)
            if existing_item:
                items_to_delete.append(existing_item)

        self._delete_items(items_to_delete)

    def _delete_items(self, items) -> None:
        """Delete a list of items individually or in bulk."""
        items_to_delete_bulk = []

        for item in items:
            try:
                identifier = item.get_identifier_value()

                if not self.check_mode:
                    if self.supports_bulk_delete:
                        items_to_delete_bulk.append(item)
                    else:
                        self.model_orchestrator.delete(item)

                # Remove from collection
                self.existing.delete(identifier)

            except Exception as e:
                error_msg = f"Failed to delete {identifier}: {e}"
                if not self.ignore_errors:
                    raise NDStateMachineError(error_msg) from e

        if items_to_delete_bulk:
            try:
                self.model_orchestrator.delete_bulk(items_to_delete_bulk)
            except Exception as e:
                error_msg = f"Failed to delete in bulk: {e}"
                if not self.ignore_errors:
                    raise NDStateMachineError(error_msg) from e

        # Log deletion
        self.output.assign(after=self.existing)
