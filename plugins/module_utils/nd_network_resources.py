# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from copy import deepcopy
from typing import Optional, List, Dict, Any, Callable, Literal
from pydantic import ValidationError

# TODO: To be replaced with:
# from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
# from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
# from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
# from ansible_collections.cisco.nd.plugins.module_utils.constants import ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED
from nd import NDModule
from nd_config_collection import NDConfigCollection
from models.base import NDBaseModel
from constants import ALLOWED_STATES_TO_APPEND_SENT_AND_PROPOSED


class NDNetworkResourceModule(NDModule):
    """
    Generic Network Resource Module for Nexus Dashboard.
    """
    
    def __init__(self, module, path: str, model_class: type[NDBaseModel], actions_overwrite_map: Optional[Dict[str, Callable]] = None):
        """
        Initialize the Network Resource Module.
        """
        super().__init__(module)
        
        # Configuration
        self.path = path
        self.model_class = model_class
        self.actions_overwrite_map = actions_overwrite_map or {}
        
        # Initialize collections
        try:
            init_all_data = self._query_all()
            
            self.existing = NDConfigCollection.from_api_response(
                response_data=init_all_data,
                model_class=model_class
            )
            self.previous = NDConfigCollection(model_class=model_class)
            self.proposed = NDConfigCollection(model_class=model_class)
            self.sent = NDConfigCollection(model_class=model_class)
        
        except Exception as e:
            self.fail_json(
                msg=f"Initialization failed: {str(e)}",
                error=str(e)
            )
        
        # Operation tracking
        self.nd_logs: List[Dict[str, Any]] = []
        
        # Current operation context
        self.current_identifier = None
        self.existing_config: Dict[str, Any] = {}
        self.proposed_config: Dict[str, Any] = {}
    
    # Action Decorator
    
    @staticmethod
    def actions_overwrite(action: str):
        """
        Decorator to allow overriding default action operations.
        """
        def decorator(func):
            def wrapper(self, *args, **kwargs):
                overwrite_action = self.actions_overwrite_map.get(action)
                if callable(overwrite_action):
                    return overwrite_action(self, *args, **kwargs)
                else:
                    return func(self, *args, **kwargs)
            return wrapper
        return decorator
    
    # Action Operations
    
    @actions_overwrite("create")
    def _create(self) -> Optional[Dict[str, Any]]:
        """
        Create a new configuration object.
        """
        if self.module.check_mode:
            return self.proposed_config
        
        try:
            return self.request(path=self.path, method="POST", data=self.proposed_config)
        except Exception as e:
            raise Exception(f"Create failed for {self.current_identifier}: {e}") from e
    
    @actions_overwrite("update")
    def _update(self) -> Optional[Dict[str, Any]]:
        """
        Update an existing configuration object.
        """
        if self.module.check_mode:
            return self.proposed_config
        
        try:
            object_path = f"{self.path}/{self.current_identifier}"
            return self.request(path=object_path, method="PUT", data=self.proposed_config)
        except Exception as e:
            raise Exception(f"Update failed for {self.current_identifier}: {e}") from e
    
    @actions_overwrite("delete")
    def _delete(self) -> None:
        """Delete a configuration object."""
        if self.module.check_mode:
            return
        
        try:
            object_path = f"{self.path}/{self.current_identifier}"
            self.request(path=object_path, method="DELETE")
        except Exception as e:
            raise Exception(f"Delete failed for {self.current_identifier}: {e}") from e
    
    @actions_overwrite("query_all")
    def _query_all(self) -> List[Dict[str, Any]]:
        """
        Query all configuration objects from device.
        """
        try:
            result = self.query_obj(self.path)
            return result or []
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e
    
    # Logging
    
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
    
    # State Management
    
    def manage_state(
        self, state: Literal["merged", "replaced", "overridden", "deleted"], new_configs: List[Dict[str, Any]], unwanted_keys: Optional[List] = None, override_exceptions: Optional[List] = None) -> None:
        """
        Manage state according to desired configuration.
        """
        unwanted_keys = unwanted_keys or []
        override_exceptions = override_exceptions or []
        
        # Parse and validate configs
        try:
            parsed_items = []
            for config in new_configs:
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
            self.proposed = NDConfigCollection(
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
        if state in ["merged", "replaced", "overridden"]:
            self._manage_create_update_state(state, unwanted_keys)
            
            if state == "overridden":
                self._manage_override_deletions(override_exceptions)
        
        elif state == "deleted":
            self._manage_delete_state()
        
        else:
            self.fail_json(msg=f"Invalid state: {state}")
    
    def _manage_create_update_state(self,state: Literal["merged", "replaced", "overridden"], unwanted_keys: List) -> None:
        """
        Handle merged/replaced/overridden states.
        """
        for proposed_item in self.proposed:
            try:
                # Extract identifier
                identifier = proposed_item.get_identifier_value()
                self.current_identifier = identifier
                
                existing_item = self.existing.get(identifier)
                self.existing_config = (
                    existing_item.model_dump(by_alias=True, exclude_none=True)
                    if existing_item
                    else {}
                )
                
                # Determine diff status
                diff_status = self.existing.get_diff_config(
                    proposed_item,
                    unwanted_keys=unwanted_keys
                )
                
                # No changes needed
                if diff_status == "no_diff":
                    self.format_log(
                        identifier=identifier,
                        status="no_change",
                        after_data=self.existing_config
                    )
                    continue
                
                # Prepare final config based on state
                if state == "merged" and existing_item:
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
                    response = self._update()
                    operation_status = "updated"
                else:
                    response = self._create()
                    operation_status = "created"
                
                # Track sent payload
                if not self.module.check_mode:
                    self.sent.add(final_item)
                    sent_payload = self.proposed_config
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
                
                if not self.module.params.get("ignore_errors", False):
                    self.fail_json(
                        msg=error_msg,
                        identifier=str(identifier),
                        error=str(e)
                    )
                    return
    
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
