# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from copy import deepcopy
from typing import Optional, List, Dict, Any, Literal, Type
from pydantic import ValidationError
from ansible.module_utils.basic import AnsibleModule

# TODO: To be replaced with:
# from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
# from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
# from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
# from ansible_collections.cisco.nd.plugins.module_utils.constants import ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED
from nd import NDModule
from nd_config_collection import NDConfigCollection
from models.base import NDBaseModel
from .orchestrators.base import NDBaseOrchestrator
from constants import ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED

# TODO: replace path and verbs with smart Endpoint (Top priority)
# TODO: Rename it (low priority)
# TODO: Revisit Deserialization in every method (high priority)
class NDNetworkResourceModule(NDModule):
    """
    Generic Network Resource Module for Nexus Dashboard.
    """
    
    def __init__(self, module: AnsibleModule, model_class: Type[NDBaseModel], model_orchestrator: Type[NDBaseOrchestrator]):
        """
        Initialize the Network Resource Module.
        """
        # TODO: Revisit Module initialization and configuration (medium priority). e.g., use instead:
        # nd_module = NDModule()
        super().__init__(module)
        
        # Configuration
        # TODO: make sure `model_class` is the same as the one in `model_orchestrator`. if not, error out (high priority)
        self.model_class = model_class
        self.model_orchestrator = model_orchestrator(module=module)
        # TODO: Revisit these class variables when udpating Module intialization and configuration (medium priority)
        self.state = self.params["state"]
        self.ansible_config = self.params["config"]

        
        # Initialize collections
        # TODO: Revisit collections initialization especially `init_all_data` (medium priority)
        # TODO: Revisit class variables `previous`, `existing`, etc... (medium priority)
        self.nd_config_collection = NDConfigCollection[model_class]
        try:
            init_all_data = self.model_orchestrator.query_all()
            
            self.existing = self.nd_config_collection.from_api_response(
                response_data=init_all_data,
                model_class=model_class
            )
            self.previous = self.nd_config_collection(model_class=model_class)
            self.proposed = self.nd_config_collection(model_class=model_class)
            self.sent = self.nd_config_collection(model_class=model_class)
        
        except Exception as e:
            self.fail_json(
                msg=f"Initialization failed: {str(e)}",
                error=str(e)
            )
        
        # Operation tracking
        self.nd_logs: List[Dict[str, Any]] = []

    # Logging
    # NOTE: format log placeholder
    # TODO: use a proper logger (low priority)
    def format_log(self, identifier, status: Literal["created", "updated", "deleted", "no_change"], after_data: Optional[Dict[str, Any]] = None, sent_payload_data: Optional[Dict[str, Any]] = None) -> None:
        """
        Create and append a log entry.
        """
        log_entry = {
            "identifier": identifier,
            "status": status,
            "before": deepcopy(self.existing_config),
            "after": deepcopy(after_data) if after_data is not None else self.existing_config,
            "sent_payload": deepcopy(sent_payload_data) if sent_payload_data is not None else {}
        }
        
        # Add HTTP details if not in check mode
        if not self.module.check_mode and self.url is not None:
            log_entry.update({
                "method": self.method,
                "response": self.response,
                "status": self.status,
                "url": self.url
            })
        
        self.nd_logs.append(log_entry)
    
    # State Management (core function)
    # TODO: adapt all `manage` functions to endpoint/orchestrator strategies (Top priority)
    def manage_state(self) -> None:
        """
        Manage state according to desired configuration.
        """
        unwanted_keys = unwanted_keys or []
        
        # Parse and validate configs
        # TODO: move it to init() (top priority)
        # TODO: Modify it if NDConfigCollection becomes a Pydantic RootModel (low priority)
        try:
            parsed_items = []
            for config in self.ansible_config:
                try:
                    # Parse config into model
                    item = self.model_class.model_validate(config)
                    parsed_items.append(item)
                except ValidationError as e:
                    self.fail_json(
                        msg=f"Invalid configuration: {e}",
                        config=config,
                        validation_errors=e.errors()
                    )
                    return
            
            # Create proposed collection
            self.proposed = self.nd_config_collection(
                model_class=self.model_class,
                items=parsed_items
            )
            
            # Save previous state
            self.previous = self.existing.copy()
        
        except Exception as e:
            self.fail_json(
                msg=f"Failed to prepare configurations: {e}",
                error=str(e)
            )
            return
        
        # Execute state operations
        if self.state in ["merged", "replaced", "overridden"]:
            self._manage_create_update_state()
            
            if self.state == "overridden":
                self._manage_override_deletions()
        
        elif self.state == "deleted":
            self._manage_delete_state()
        
        # TODO: not needed with Ansible `argument_spec` validation. Keep it for now but needs to be removed (low priority)
        else:
            self.fail_json(msg=f"Invalid state: {self.state}")
    

    def _manage_create_update_state(self) -> None:
        """
        Handle merged/replaced/overridden states.
        """
        for proposed_item in self.proposed:
            try:
                # Extract identifier
                # TODO: Remove self.current_identifier, get it directly into the action functions
                identifier = proposed_item.get_identifier_value()
                
                existing_item = self.existing.get(identifier)
                self.existing_config = (
                    existing_item.model_dump(by_alias=True, exclude_none=True)
                    if existing_item
                    else {}
                )
                
                # Determine diff status
                diff_status = self.existing.get_diff_config(proposed_item)
                
                # No changes needed
                if diff_status == "no_diff":
                    self.format_log(
                        identifier=identifier,
                        status="no_change",
                        after_data=self.existing_config
                    )
                    continue
                
                # Prepare final config based on state
                if self.state == "merged" and existing_item:
                    # Merge with existing
                    merged_item = self.existing.merge(proposed_item)
                    final_item = merged_item
                else:
                    # Replace or create
                    if existing_item:
                        self.existing.replace(proposed_item)
                    else:
                        self.existing.add(proposed_item)
                    final_item = proposed_item
                
                # Convert to API payload
                self.proposed_config = final_item.to_payload()
                
                # Execute API operation
                if diff_status == "changed":
                    response = self.model_orchestrator.update(final_item)
                    operation_status = "updated"
                else:
                    response = self.model_orchestrator.create(final_item)
                    operation_status = "created"
                
                # Track sent payload
                if not self.module.check_mode:
                    self.sent.add(final_item)
                    sent_payload = final_item
                else:
                    sent_payload = None
                
                # Log operation
                self.format_log(
                    identifier=identifier,
                    status=operation_status,
                    after_data=(
                        response if not self.module.check_mode
                        else final_item.model_dump(by_alias=True, exclude_none=True)
                    ),
                    sent_payload_data=sent_payload
                )
            
            except Exception as e:
                error_msg = f"Failed to process {identifier}: {e}"
                
                self.format_log(
                    identifier=identifier,
                    status="no_change",
                    after_data=self.existing_config
                )
                
                if not self.params.get("ignore_errors", False):
                    self.fail_json(
                        msg=error_msg,
                        identifier=str(identifier),
                        error=str(e)
                    )
                    return
    
    # TODO: Refactor with orchestrator (Top priority)
    def _manage_override_deletions(self, override_exceptions: List) -> None:
        """
        Delete items not in proposed config (for overridden state).
        """
        diff_identifiers = self.previous.get_diff_identifiers(self.proposed)
        
        for identifier in diff_identifiers:
            if identifier in override_exceptions:
                continue
            
            try:
                self.current_identifier = identifier
                
                existing_item = self.existing.get(identifier)
                if not existing_item:
                    continue
                
                self.existing_config = existing_item.model_dump(
                    by_alias=True,
                    exclude_none=True
                )
                
                # Execute delete
                self._delete()
                
                # Remove from collection
                self.existing.delete(identifier)
                
                # Log deletion
                self.format_log(
                    identifier=identifier,
                    status="deleted",
                    after_data={}
                )
            
            except Exception as e:
                error_msg = f"Failed to delete {identifier}: {e}"
                
                if not self.module.params.get("ignore_errors", False):
                    self.fail_json(
                        msg=error_msg,
                        identifier=str(identifier),
                        error=str(e)
                    )
                    return
    
    # TODO: Refactor with orchestrator (Top priority)
    def _manage_delete_state(self) -> None:
        """Handle deleted state."""
        for proposed_item in self.proposed:
            try:
                identifier = proposed_item.get_identifier_value()
                self.current_identifier = identifier
                
                existing_item = self.existing.get(identifier)
                if not existing_item:
                    # Already deleted or doesn't exist
                    self.format_log(
                        identifier=identifier,
                        status="no_change",
                        after_data={}
                    )
                    continue
                
                self.existing_config = existing_item.model_dump(
                    by_alias=True,
                    exclude_none=True
                )
                
                # Execute delete
                self._delete()
                
                # Remove from collection
                self.existing.delete(identifier)
                
                # Log deletion
                self.format_log(
                    identifier=identifier,
                    status="deleted",
                    after_data={}
                )
            
            except Exception as e:
                error_msg = f"Failed to delete {identifier}: {e}"
                
                if not self.module.params.get("ignore_errors", False):
                    self.fail_json(
                        msg=error_msg,
                        identifier=str(identifier),
                        error=str(e)
                    )
                    return
    
    # Output Formatting
    # TODO: move to separate Class (results) -> align it with rest_send PR
    def add_logs_and_outputs(self) -> None:
        """Add logs and outputs to module result based on output_level."""
        output_level = self.params.get("output_level", "normal")
        state = self.params.get("state")
        
        # Add previous state for certain states and output levels
        if state in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
            if output_level in ("debug", "info"):
                self.result["previous"] = self.previous.to_list()
            
            # Check if there were changes
            if not self.has_modified and self.previous.get_diff_collection(self.existing):
                self.result["changed"] = True
        
        # Add stdout if present
        if self.stdout:
            self.result["stdout"] = self.stdout
        
        # Add debug information
        if output_level == "debug":
            self.result["nd_logs"] = self.nd_logs
            
            if self.url is not None:
                self.result["httpapi_logs"] = self.httpapi_logs
            
            if state in ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED:
                self.result["sent"] = self.sent.to_payload_list()
                self.result["proposed"] = self.proposed.to_list()
        
        # Always include current state
        self.result["current"] = self.existing.to_list()
    
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
                
                self.result["diff"] = dict(
                    before=before,
                    after=after
                )
            except Exception:
                pass  # Don't fail on diff generation
        
        self.result.update(**kwargs)
        self.module.exit_json(**self.result)
