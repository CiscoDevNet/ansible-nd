# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import List, Dict, Any, Type
from ansible_collections.cisco.nd.plugins.module_utils.pydantic_compat import ValidationError
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator


class NDStateMachine:
    """
    Generic Network Resource Module for Nexus Dashboard.
    """

    def __init__(self, module: AnsibleModule, model_orchestrator: Type[NDBaseOrchestrator]):
        """
        Initialize the Network Resource Module.
        """
        # TODO: Revisit Module initialization and configuration with rest_send
        self.module = module
        self.nd_module = NDModule(self.module)

        # Operation tracking
        self.output = NDOutput(self.module)

        # Configuration
        self.model_orchestrator = model_orchestrator(sender=self.nd_module)
        self.model_class = self.model_orchestrator.model_class
        # TODO: Revisit these class variables when udpating Module intialization and configuration (low priority)
        self.state = self.module.params["state"]

        # Initialize collections
        self.nd_config_collection = NDConfigCollection[self.model_class]
        try:
            response_data = self.model_orchestrator.query_all()
            # State of configuration objects in ND before change execution
            self.before = self.nd_config_collection.from_api_response(response_data=response_data, model_class=self.model_class)
            # State of current configuration objects in ND during change execution
            self.existing = self.before.copy()
            # Ongoing collection of configuration objects that were changed
            self.sent = self.nd_config_collection(model_class=self.model_class)
            # Collection of configuration objects given by user
            self.proposed = self.nd_config_collection(model_class=self.model_class)
            for config in self.module.params.get("config", []):
                try:
                    # Parse config into model
                    item = self.model_class.from_config(config)
                    self.proposed.add(item)
                except ValidationError as e:
                    self.fail_json(msg=f"Invalid configuration: {e}", config=config, validation_errors=e.errors())
                    return
            self.output.assign(after=self.existing, before=self.before, proposed=self.proposed)
        except Exception as e:
            self.fail_json(msg=f"NDStateMachine initialization failed: {str(e)}", error=str(e))

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

        # TODO: boil down an Exception instead of using `fail_json` method
        else:
            self.fail_json(msg=f"Invalid state: {self.state}")

    def _manage_create_update_state(self) -> None:
        """
        Handle merged/replaced/overridden states.
        """
        for proposed_item in self.proposed:
            # Extract identifier
            identifier = proposed_item.get_identifier_value()
            try:
                # Determine diff status
                diff_status = self.existing.get_diff_config(proposed_item)

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
                    if not self.module.check_mode:
                        self.model_orchestrator.update(final_item)
                        self.sent.add(final_item)
                elif diff_status == "new":
                    if not self.module.check_mode:
                        self.model_orchestrator.create(final_item)
                        self.sent.add(final_item)

                # Log operation
                self.output.assign(after=self.existing)

            except Exception as e:
                error_msg = f"Failed to process {identifier}: {e}"
                if not self.module.params.get("ignore_errors", False):
                    self.fail_json(msg=error_msg, identifier=str(identifier), error=str(e))
                    return

    def _manage_override_deletions(self) -> None:
        """
        Delete items not in proposed config (for overridden state).
        """
        diff_identifiers = self.before.get_diff_identifiers(self.proposed)

        for identifier in diff_identifiers:
            try:
                existing_item = self.existing.get(identifier)
                if not existing_item:
                    continue

                # Execute delete
                if not self.module.check_mode:
                    self.model_orchestrator.delete(existing_item)

                # Remove from collection
                self.existing.delete(identifier)

                # Log deletion
                self.output.assign(after=self.existing)

            except Exception as e:
                error_msg = f"Failed to delete {identifier}: {e}"

                if not self.module.params.get("ignore_errors", False):
                    self.fail_json(msg=error_msg, identifier=str(identifier), error=str(e))
                    return

    def _manage_delete_state(self) -> None:
        """Handle deleted state."""
        for proposed_item in self.proposed:
            try:
                identifier = proposed_item.get_identifier_value()

                existing_item = self.existing.get(identifier)
                if not existing_item:
                    continue

                # Execute delete
                if not self.module.check_mode:
                    self.model_orchestrator.delete(existing_item)

                # Remove from collection
                self.existing.delete(identifier)

                # Log deletion
                self.output.assign(after=self.existing)

            except Exception as e:
                error_msg = f"Failed to delete {identifier}: {e}"

                if not self.module.params.get("ignore_errors", False):
                    self.fail_json(msg=error_msg, identifier=str(identifier), error=str(e))
                    return

    # Module Exit Methods

    def fail_json(self, msg: str, **kwargs) -> None:
        """
        Exit module with failure.
        """
        self.module.fail_json(msg=msg)
