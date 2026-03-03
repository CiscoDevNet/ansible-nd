# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from copy import deepcopy
from typing import Optional, List, Dict, Any, Literal, Type
from pydantic import ValidationError
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey
from ansible_collections.cisco.nd.plugins.module_utils.constants import ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED


# TODO: Revisit StateMachine when there is more arguments than config (e.g., "fabric" and "config" for switches config)
# TODO:
class NDStateMachine(NDModule):
    """
    Generic Network Resource Module for Nexus Dashboard.
    """

    def __init__(self, module: AnsibleModule, model_orchestrator: Type[NDBaseOrchestrator]):
        """
        Initialize the Network Resource Module.
        """
        # TODO: Revisit Module initialization and configuration with rest_send
        self.module = module
        self.nd_module = NDModule(module)

        # Operation tracking
        self.nd_logs: List[Dict[str, Any]] = []
        self.result: Dict[str, Any] = {"changed": False}

        # Configuration
        self.model_orchestrator = model_orchestrator(sender=self.nd_module)
        self.model_class = self.model_orchestrator.model_class
        # TODO: Revisit these class variables when udpating Module intialization and configuration (medium priority)
        self.state = self.module.params["state"]
        self.ansible_config = self.module.params.get("config", [])

        # Initialize collections
        # TODO: Revisit class variables `previous`, `existing`, etc... (medium priority)
        self.nd_config_collection = NDConfigCollection[self.model_class]
        try:
            init_all_data = self.model_orchestrator.query_all()

            self.existing = self.nd_config_collection.from_api_response(response_data=init_all_data, model_class=self.model_class)
            # Save previous state
            self.previous = self.existing.copy()
            self.proposed = self.nd_config_collection(model_class=self.model_class)
            self.sent = self.nd_config_collection(model_class=self.model_class)

            for config in self.ansible_config:
                try:
                    # Parse config into model
                    item = self.model_class.from_config(config)
                    self.proposed.add(item)
                except ValidationError as e:
                    self.fail_json(msg=f"Invalid configuration: {e}", config=config, validation_errors=e.errors())
                    return

        except Exception as e:
            self.fail_json(msg=f"Initialization failed: {str(e)}", error=str(e))

    # Logging
    # NOTE: format log placeholder
    # TODO: use a proper logger (low priority)
    def format_log(
        self,
        identifier: IdentifierKey,
        operation_status: Literal["no_change", "created", "updated", "deleted"],
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Create and append a log entry.
        """
        log_entry = {
            "identifier": identifier,
            "operation_status": operation_status,
            "before": before,
            "after": after,
            "payload": payload,
        }

        # Add HTTP details if not in check mode
        if not self.module.check_mode and self.nd_module.url is not None:
            log_entry.update(
                {"method": self.nd_module.method, "response": self.nd_module.response, "status": self.nd_module.status, "url": self.nd_module.url}
            )

        self.nd_logs.append(log_entry)

    # State Management (core function)
    # TODO: adapt all `manage` functions to endpoint/orchestrator strategies (Top priority)
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

        # TODO: not needed with Ansible `argument_spec` validation. Keep it for now but needs to be removed (low priority)
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
            existing_config = self.existing.get(identifier).to_config() if self.existing.get(identifier) else {}
            try:
                # Determine diff status
                diff_status = self.existing.get_diff_config(proposed_item)

                # No changes needed
                if diff_status == "no_diff":
                    self.format_log(
                        identifier=identifier,
                        operation_status="no_change",
                        before=existing_config,
                        after=existing_config,
                    )
                    continue

                # Prepare final config based on state
                if self.state == "merged":
                    # Merge with existing
                    merged_item = self.existing.merge(proposed_item)
                    final_item = merged_item
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
                        response = self.model_orchestrator.update(final_item)
                        self.sent.add(final_item)
                    operation_status = "updated"
                elif diff_status == "new":
                    if not self.module.check_mode:
                        response = self.model_orchestrator.create(final_item)
                        self.sent.add(final_item)
                    operation_status = "created"

                # Log operation
                self.format_log(
                    identifier=identifier,
                    operation_status=operation_status,
                    before=existing_config,
                    after=self.model_class.model_validate(response).to_config() if not self.module.check_mode else final_item.to_config(),
                    payload=final_item.to_payload(),
                )

            except Exception as e:
                error_msg = f"Failed to process {identifier}: {e}"

                self.format_log(
                    identifier=identifier,
                    operation_status="no_change",
                    before=existing_config,
                    after=existing_config,
                )

                if not self.module.params.get("ignore_errors", False):
                    self.fail_json(msg=error_msg, identifier=str(identifier), error=str(e))
                    return

    def _manage_override_deletions(self) -> None:
        """
        Delete items not in proposed config (for overridden state).
        """
        diff_identifiers = self.previous.get_diff_identifiers(self.proposed)

        for identifier in diff_identifiers:
            try:
                existing_item = self.existing.get(identifier)
                if not existing_item:
                    continue

                # Execute delete
                if not self.module.check_mode:
                    response = self.model_orchestrator.delete(existing_item)

                # Remove from collection
                self.existing.delete(identifier)

                # Log deletion
                self.format_log(
                    identifier=identifier,
                    operation_status="deleted",
                    before=existing_item.to_config(),
                    after={},
                )

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
                    # Already deleted or doesn't exist
                    self.format_log(
                        identifier=identifier,
                        operation_status="no_change",
                        before={},
                        after={},
                    )
                    continue

                # Execute delete
                if not self.module.check_mode:
                    response = self.model_orchestrator.delete(existing_item)

                # Remove from collection
                self.existing.delete(identifier)

                # Log deletion
                self.format_log(
                    identifier=identifier,
                    operation_status="deleted",
                    before=existing_item.to_config(),
                    after={},
                )

            except Exception as e:
                error_msg = f"Failed to delete {identifier}: {e}"

                if not self.module.params.get("ignore_errors", False):
                    self.fail_json(msg=error_msg, identifier=str(identifier), error=str(e))
                    return

    # Output Formatting
    # TODO: move to separate Class (results) -> align it with rest_send PR
    # TODO: return a defined ordered list of config (for integration test)
    def add_logs_and_outputs(self) -> None:
        """Add logs and outputs to module result based on output_level."""
        output_level = self.module.params.get("output_level", "normal")
        state = self.module.params.get("state")

        # Add previous state for certain states and output levels
        if state in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
            if output_level in ("debug", "info"):
                self.result["previous"] = self.previous.to_ansible_config()

            # Check if there were changes
            if self.previous.get_diff_collection(self.existing):
                self.result["changed"] = True

        # Add stdout if present
        if self.nd_module.stdout:
            self.result["stdout"] = self.nd_module.stdout

        # Add debug information
        if output_level == "debug":
            self.result["nd_logs"] = self.nd_logs

            if self.nd_module.url is not None:
                self.result["httpapi_logs"] = self.nd_module.httpapi_logs

            if state in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
                self.result["sent"] = self.sent.to_payload_list()
                self.result["proposed"] = self.proposed.to_ansible_config()

        # Always include current state
        self.result["current"] = self.existing.to_ansible_config()

    # Module Exit Methods

    def fail_json(self, msg: str, **kwargs) -> None:
        """
        Exit module with failure.
        """
        self.add_logs_and_outputs()
        self.result.update(**kwargs)
        self.module.fail_json(msg=msg, **self.result)

    def exit_json(self, **kwargs) -> None:
        """
        Exit module successfully.
        """
        self.add_logs_and_outputs()

        # Add diff if module supports it
        if self.module._diff and self.result.get("changed") is True:
            try:
                # Use diff-safe dicts (excludes sensitive fields)
                before = [item.to_diff_dict() for item in self.previous]
                after = [item.to_diff_dict() for item in self.existing]

                self.result["diff"] = dict(before=before, after=after)
            except Exception:
                pass  # Don't fail on diff generation

        self.result.update(**kwargs)
        self.module.exit_json(**self.result)
