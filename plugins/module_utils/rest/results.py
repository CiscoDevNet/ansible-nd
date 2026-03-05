# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# pylint: disable=too-many-instance-attributes,too-many-public-methods,line-too-long,too-many-lines
"""
Exposes public class Results to collect results across Ansible tasks.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import copy
import logging
from typing import Any, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType


class TaskResultData(BaseModel):
    """
    # Summary

    Pydantic model for a single task result.

    Represents all data for one task including its response, result, diff,
    and metadata. Immutable after creation to prevent accidental modification
    of registered tasks.

    ## Raises

    - `ValidationError`: if field validation fails during instantiation

    ## Attributes

    - `sequence_number`: Unique sequence number for this task (required, >= 1)
    - `response`: Controller response dict (required)
    - `result`: Handler result dict (required)
    - `diff`: Changes dict (required, can be empty)
    - `metadata`: Task metadata dict (required)
    - `changed`: Whether this task resulted in changes (required)
    - `failed`: Whether this task failed (required)
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    sequence_number: int = Field(ge=1)
    response: dict[str, Any]
    result: dict[str, Any]
    diff: dict[str, Any]
    metadata: dict[str, Any]
    changed: bool
    failed: bool


class FinalResultData(BaseModel):
    """
    # Summary

    Pydantic model for the final aggregated result.

    This is the structure returned to Ansible's `exit_json`/`fail_json`.
    Contains aggregated data from all registered tasks.

    ## Raises

    - `ValidationError`: if field validation fails during instantiation

    ## Attributes

    - `changed`: Overall changed status across all tasks (required)
    - `failed`: Overall failed status across all tasks (required)
    - `diff`: List of all diff dicts (default empty list)
    - `response`: List of all response dicts (default empty list)
    - `result`: List of all result dicts (default empty list)
    - `metadata`: List of all metadata dicts (default empty list)
    """

    model_config = ConfigDict(extra="forbid")

    changed: bool
    failed: bool
    diff: list[dict[str, Any]] = Field(default_factory=list)
    response: list[dict[str, Any]] = Field(default_factory=list)
    result: list[dict[str, Any]] = Field(default_factory=list)
    metadata: list[dict[str, Any]] = Field(default_factory=list)


class CurrentTaskData(BaseModel):
    """
    # Summary

    Pydantic model for the current task data being built.

    Mutable model used to stage data for the current task before
    it's registered and converted to an immutable `TaskResultData`.
    Provides validation while allowing flexibility during the build phase.

    ## Raises

    - `ValidationError`: if field validation fails during instantiation or assignment

    ## Attributes

    - `response`: Controller response dict (default empty dict)
    - `result`: Handler result dict (default empty dict)
    - `diff`: Changes dict (default empty dict)
    - `action`: Action name for metadata (default empty string)
    - `state`: Ansible state for metadata (default empty string)
    - `check_mode`: Check mode flag for metadata (default False)
    - `operation_type`: Operation type determining if changes might occur (default QUERY)
    """

    model_config = ConfigDict(extra="allow", validate_assignment=True)

    response: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    diff: dict[str, Any] = Field(default_factory=dict)
    action: str = ""
    state: str = ""
    check_mode: bool = False
    operation_type: OperationType = OperationType.QUERY


class Results:
    """
    # Summary

    Collect and aggregate results across tasks using Pydantic data models.

    ## Raises

    -   `TypeError`: if properties are not of the correct type
    -   `ValueError`: if Pydantic validation fails or required data is missing

    ## Architecture

    This class uses a three-model Pydantic architecture for data validation:

    1.  `CurrentTaskData` - Mutable staging area for building the current task
    2.  `TaskResultData` - Immutable registered task with validation (frozen=True)
    3.  `FinalResultData` - Aggregated result for Ansible output

    The lifecycle is: **Build (Current) → Register (Task) → Aggregate (Final)**

    ## Description

    Provides a mechanism to collect results across tasks.  The task classes
    must support this Results class.  Specifically, they must implement the
    following:

    1.  Accept an instantiation of `Results()`
        -   Typically a class property is used for this
    2.  Populate the `Results` instance with the current task data
        -   Set properties: `response_current`, `result_current`, `diff_current`
        -   Set metadata properties: `action`, `state`, `check_mode`, `operation_type`
    3. Optional. Register the task result with `Results.register_task_result()`
        -   Converts current task to immutable `TaskResultData`
        -   Validates data with Pydantic
        -   Resets current task for next registration
        -   Tasks are NOT required to be registered.  There are cases where
            a task's information would not be useful to an end-user.  If this
            is the case, the task can simply not be registered.

    `Results` should be instantiated in the main Ansible Task class and
    passed to all other task classes for which results are to be collected.
    The task classes should populate the `Results` instance with the results
    of the task and then register the results with `Results.register_task_result()`.

    This may be done within a separate class (as in the example below, where
    the `FabricDelete()` class is called from the `TaskDelete()` class.
    The `Results` instance can then be used to build the final result, by
    calling `Results.build_final_result()`.

    ## Example Usage

    We assume an Ansible module structure as follows:

    -   `TaskCommon()`: Common methods used by the various ansible
        state classes.
    -   `TaskDelete(TaskCommon)`: Implements the delete state
    -   `TaskMerge(TaskCommon)`: Implements the merge state
    -   `TaskQuery(TaskCommon)`: Implements the query state
    -   etc...

    In TaskCommon, `Results` is instantiated and, hence, is inherited by all
    state classes.:

    ```python
    class TaskCommon:
        def __init__(self):
            self._results = Results()

        @property
        def results(self) -> Results:
            '''
            An instance of the Results class.
            '''
            return self._results

        @results.setter
        def results(self, value: Results) -> None:
            self._results = value
    ```

    In each of the state classes (TaskDelete, TaskMerge, TaskQuery, etc...)
    a class is instantiated (in the example below, FabricDelete) that
    supports collecting results for the Results instance:

    ```python
    class TaskDelete(TaskCommon):
        def __init__(self, ansible_module):
            super().__init__(ansible_module)
            self.fabric_delete = FabricDelete(self.ansible_module)

        def commit(self):
            '''
            delete the fabric
            '''
            ...
            self.fabric_delete.fabric_names = ["FABRIC_1", "FABRIC_2"]
            self.fabric_delete.results = self.results
            # results.register_task_result() is optionally called within the
            # commit() method of the FabricDelete class.
            self.fabric_delete.commit()
    ```

    Finally, within the main() method of the Ansible module, the final result
    is built by calling Results.build_final_result():

    ```python
    if ansible_module.params["state"] == "deleted":
        task = TaskDelete(ansible_module)
        task.commit()
    elif ansible_module.params["state"] == "merged":
        task = TaskDelete(ansible_module)
        task.commit()
    # etc, for other states...

    # Build the final result
    task.results.build_final_result()

    # Call fail_json() or exit_json() based on the final result
    if True in task.results.failed:
        ansible_module.fail_json(**task.results.final_result)
    ansible_module.exit_json(**task.results.final_result)
    ```

    results.final_result will be a dict with the following structure

    ```json
    {
        "changed": True, # or False
        "failed": True,  # or False
        "diff": {
            [{"diff1": "diff"}, {"diff2": "diff"}, {"etc...": "diff"}],
        }
        "response": {
            [{"response1": "response"}, {"response2": "response"}, {"etc...": "response"}],
        }
        "result": {
            [{"result1": "result"}, {"result2": "result"}, {"etc...": "result"}],
        }
        "metadata": {
            [{"metadata1": "metadata"}, {"metadata2": "metadata"}, {"etc...": "metadata"}],
        }
    }
    ```

    diff, response, and result dicts are per the Ansible ND Collection standard output.

    An example of a result dict would be (sequence_number is added by Results):

    ```json
    {
        "found": true,
        "sequence_number": 1,
        "success": true
    }
    ```

    An example of a metadata dict would be (sequence_number is added by Results):


    ```json
    {
        "action": "merge",
        "check_mode": false,
        "state": "merged",
        "sequence_number": 1
    }
    ```

    `sequence_number` indicates the order in which the task was registered
    with `Results`.  It provides a way to correlate the diff, response,
    result, and metadata across all tasks.

    ## Typical usage within a task class such as FabricDelete

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
    from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
    from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
    ...
    class FabricDelete:
        def __init__(self, ansible_module):
            ...
            self.action: str = "fabric_delete"
            self.operation_type: OperationType = OperationType.DELETE  # Determines if changes might occur
            self._rest_send: RestSend = RestSend(params)
            self._results: Results = Results()
            ...

        def commit(self):
            ...
            # Set current task data (no need to manually track changed/failed)
            self._results.response_current = self._rest_send.response_current
            self._results.result_current = self._rest_send.result_current
            self._results.diff_current = {}  # or actual diff if available
            # register_task_result() determines changed/failed automatically
            self._results.register_task_result()
            ...

        @property
        def results(self) -> Results:
            '''
            An instance of the Results class.
            '''
            return self._results
        @results.setter
        def results(self, value: Results) -> None:
            self._results = value
            self._results.action = self.action
            self._results.operation_type = self.operation_type
    """

    def __init__(self) -> None:
        self.class_name: str = self.__class__.__name__

        self.log: logging.Logger = logging.getLogger(f"nd.{self.class_name}")

        # Task sequence tracking
        self.task_sequence_number: int = 0

        # Registered tasks (immutable after registration)
        self._tasks: list[TaskResultData] = []

        # Current task being built (mutable)
        self._current: CurrentTaskData = CurrentTaskData()

        # Aggregated state (derived from tasks)
        self._changed: set[bool] = set()
        self._failed: set[bool] = set()

        # Final result (built on demand)
        self._final_result: Optional[FinalResultData] = None

        # Legacy: response_data list for backward compatibility
        self._response_data: list[dict[str, Any]] = []

        msg = f"ENTERED {self.class_name}():"
        self.log.debug(msg)

    def add_response_data(self, value: dict[str, Any]) -> None:
        """
        # Summary

        Add a dict to the response_data list.

        ## Raises

        -   `TypeError`: if value is not a dict

        ## See also

        `@response_data` property
        """
        method_name: str = "add_response_data"
        if not isinstance(value, dict):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"instance.add_response_data must be a dict. Got {value}"
            raise TypeError(msg)
        self._response_data.append(copy.deepcopy(value))

    def _increment_task_sequence_number(self) -> None:
        """
        # Summary

        Increment a unique task sequence number.

        ## Raises

        None
        """
        self.task_sequence_number += 1
        msg = f"self.task_sequence_number: {self.task_sequence_number}"
        self.log.debug(msg)

    def _determine_if_changed(self) -> bool:
        """
        # Summary

        Determine if the current task resulted in changes.

        This is a private helper method used during task registration.
        Checks operation type, check mode, explicit changed flag,
        and diff content to determine if changes occurred.

        ## Raises

        None

        ## Returns

        - `bool`: True if changes occurred, False otherwise
        """
        method_name: str = "_determine_if_changed"

        msg = f"{self.class_name}.{method_name}: ENTERED: "
        msg += f"action={self._current.action}, "
        msg += f"operation_type={self._current.operation_type}, "
        msg += f"state={self._current.state}, "
        msg += f"check_mode={self._current.check_mode}"
        self.log.debug(msg)

        # Early exit for read-only operations
        if self._current.check_mode or self._current.operation_type.is_read_only():
            msg = f"{self.class_name}.{method_name}: No changes (read-only operation)"
            self.log.debug(msg)
            return False

        # Check explicit changed flag in result
        changed_flag = self._current.result.get("changed")
        if changed_flag is not None:
            msg = f"{self.class_name}.{method_name}: changed={changed_flag} (from result)"
            self.log.debug(msg)
            return changed_flag

        # Check if diff has content (besides sequence_number)
        has_diff_content = any(key != "sequence_number" for key in self._current.diff)

        msg = f"{self.class_name}.{method_name}: changed={has_diff_content} (from diff)"
        self.log.debug(msg)
        return has_diff_content

    def register_task_result(self) -> None:
        """
        # Summary

        Register the current task result.

        Converts `CurrentTaskData` to immutable `TaskResultData`, increments
        sequence number, and aggregates changed/failed status. The current task
        is then reset for the next task.

        ## Raises

        - `ValueError`: if Pydantic validation fails for task result data
        - `ValueError`: if required fields are missing

        ## Description

        1.  Increment the task sequence number
        2.  Build metadata from current task properties
        3.  Determine if anything changed using `_determine_if_changed()`
        4.  Determine if task failed based on `result["success"]` flag
        5.  Add sequence_number to response, result, and diff
        6.  Create immutable `TaskResultData` with validation
        7.  Register the task and update aggregated changed/failed sets
        8.  Reset current task for next registration
        """
        method_name: str = "register_task_result"

        msg = f"{self.class_name}.{method_name}: "
        msg += f"ENTERED: action={self._current.action}, "
        msg += f"result_current={self._current.result}"
        self.log.debug(msg)

        # Increment sequence number
        self._increment_task_sequence_number()

        # Build metadata from current task
        metadata = {
            "action": self._current.action,
            "check_mode": self._current.check_mode,
            "sequence_number": self.task_sequence_number,
            "state": self._current.state,
        }

        # Determine changed status
        changed = self._determine_if_changed()

        # Determine failed status from result
        success = self._current.result.get("success")
        if success is True:
            failed = False
        elif success is False:
            failed = True
        else:
            msg = f"{self.class_name}.{method_name}: "
            msg += "result['success'] is not a boolean. "
            msg += f"result={self._current.result}. "
            msg += "Setting failed=False."
            self.log.debug(msg)
            failed = False

        # Add sequence_number to response, result, diff
        response = copy.deepcopy(self._current.response)
        response["sequence_number"] = self.task_sequence_number

        result = copy.deepcopy(self._current.result)
        result["sequence_number"] = self.task_sequence_number

        diff = copy.deepcopy(self._current.diff)
        diff["sequence_number"] = self.task_sequence_number

        # Create immutable TaskResultData with validation
        try:
            task_data = TaskResultData(
                sequence_number=self.task_sequence_number,
                response=response,
                result=result,
                diff=diff,
                metadata=metadata,
                changed=changed,
                failed=failed,
            )
        except ValidationError as error:
            msg = f"{self.class_name}.{method_name}: "
            msg += f"Validation failed for task result: {error}"
            raise ValueError(msg) from error

        # Register the task
        self._tasks.append(task_data)
        self._changed.add(changed)
        self._failed.add(failed)

        # Reset current task for next task
        self._current = CurrentTaskData()

        # Log registration
        if self.log.isEnabledFor(logging.DEBUG):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"Registered task {self.task_sequence_number}: "
            msg += f"changed={changed}, failed={failed}"
            self.log.debug(msg)

    def build_final_result(self) -> None:
        """
        # Summary

        Build the final result from all registered tasks.

        Creates a `FinalResultData` Pydantic model with aggregated
        changed/failed status and all task data. The model is stored
        internally and can be accessed via the `final_result` property.

        ## Raises

        - `ValueError`: if Pydantic validation fails for final result

        ## Description

        The final result consists of the following:

        ```json
        {
            "changed": True, # or False
            "failed": True,
            "diff": {
                [<list of dict containing changes>],
            },
            "response": {
                [<list of dict containing controller responses>],
            },
            "result": {
                [<list of dict containing results (from handle_response() functions)>],
            },
            "metadata": {
                [<list of dict containing metadata>],
            }
        ```
        """
        method_name: str = "build_final_result"

        msg = f"{self.class_name}.{method_name}: "
        msg += f"changed={self._changed}, failed={self._failed}"
        self.log.debug(msg)

        # Aggregate data from all tasks
        diff_list = [task.diff for task in self._tasks]
        response_list = [task.response for task in self._tasks]
        result_list = [task.result for task in self._tasks]
        metadata_list = [task.metadata for task in self._tasks]

        # Create FinalResultData with validation
        try:
            self._final_result = FinalResultData(
                changed=True in self._changed,
                failed=True in self._failed,
                diff=diff_list,
                response=response_list,
                result=result_list,
                metadata=metadata_list,
            )
        except ValidationError as error:
            msg = f"{self.class_name}.{method_name}: "
            msg += f"Validation failed for final result: {error}"
            raise ValueError(msg) from error

        msg = f"{self.class_name}.{method_name}: "
        msg += f"Built final result: changed={self._final_result.changed}, "
        msg += f"failed={self._final_result.failed}, "
        msg += f"tasks={len(self._tasks)}"
        self.log.debug(msg)

    @property
    def final_result(self) -> dict[str, Any]:
        """
        # Summary

        Return the final result as a dict for Ansible `exit_json`/`fail_json`.

        ## Raises

        - `ValueError`: if `build_final_result()` hasn't been called

        ## Returns

        - `dict[str, Any]`: The final result dictionary with all aggregated data
        """
        if self._final_result is None:
            msg = f"{self.class_name}.final_result: "
            msg += "build_final_result() must be called before accessing final_result"
            raise ValueError(msg)
        return self._final_result.model_dump()

    @property
    def failed_result(self) -> dict[str, Any]:
        """
        # Summary

        Return a result for a failed task with no changes

        ## Raises

        None
        """
        result: dict = {}
        result["changed"] = False
        result["failed"] = True
        result["diff"] = [{}]
        result["response"] = [{}]
        result["result"] = [{}]
        return result

    @property
    def ok_result(self) -> dict[str, Any]:
        """
        # Summary

        Return a result for a successful task with no changes

        ## Raises

        None
        """
        result: dict = {}
        result["changed"] = False
        result["failed"] = False
        result["diff"] = [{}]
        result["response"] = [{}]
        result["result"] = [{}]
        return result

    @property
    def action(self) -> str:
        """
        # Summary

        Action name for the current task.

        Used in metadata to indicate the action that was taken.

        ## Raises

        None
        """
        return self._current.action

    @action.setter
    def action(self, value: str) -> None:
        method_name: str = "action"
        if not isinstance(value, str):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"value must be a string. Got {type(value).__name__}."
            raise TypeError(msg)
        self._current.action = value

    @property
    def operation_type(self) -> OperationType:
        """
        # Summary

        The operation type for the current operation.

        Used to determine if the operation might change controller state.

        ## Raises

        None

        ## Returns

        The current operation type (`OperationType` enum value)
        """
        return self._current.operation_type

    @operation_type.setter
    def operation_type(self, value: OperationType) -> None:
        """
        # Summary

        Set the operation type for the current task.

        ## Raises

        - `TypeError`: if value is not an `OperationType` instance

        ## Parameters

        - value: The operation type to set (must be an `OperationType` enum value)
        """
        method_name: str = "operation_type"
        if not isinstance(value, OperationType):
            msg = f"{self.class_name}.{method_name}: "
            msg += "value must be an OperationType instance. "
            msg += f"Got type {type(value).__name__}, value {value}."
            raise TypeError(msg)
        self._current.operation_type = value

    @property
    def changed(self) -> set[bool]:
        """
        # Summary

        Returns a set() containing boolean values indicating whether anything changed.

        ## Raises

        None

        ## Returns

        -   A set() of boolean values indicating whether any tasks changed

        ## See also

        -  `register_task_result()` method to register tasks and update the changed set.
        """
        return self._changed

    @property
    def check_mode(self) -> bool:
        """
        # Summary

        Ansible check_mode flag for the current task.

        - `True` if check_mode is enabled, `False` otherwise.

        ## Raises

        None
        """
        return self._current.check_mode

    @check_mode.setter
    def check_mode(self, value: bool) -> None:
        method_name: str = "check_mode"
        if not isinstance(value, bool):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"value must be a bool. Got {type(value).__name__}."
            raise TypeError(msg)
        self._current.check_mode = value

    @property
    def diff(self) -> list[dict[str, Any]]:
        """
        # Summary

        A list of dicts representing the changes made across all registered tasks.

        ## Raises

        None

        ## Returns

        - `list[dict[str, Any]]`: List of diff dictionaries from all registered tasks
        """
        return [task.diff for task in self._tasks]

    @property
    def diff_current(self) -> dict[str, Any]:
        """
        # Summary

        A dict representing the current diff for the current task.

        ## Raises

        -   setter: `TypeError` if value is not a dict
        """
        return self._current.diff

    @diff_current.setter
    def diff_current(self, value: dict[str, Any]) -> None:
        method_name: str = "diff_current"
        if not isinstance(value, dict):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"value must be a dict. Got {type(value).__name__}."
            raise TypeError(msg)
        self._current.diff = value

    @property
    def failed(self) -> set[bool]:
        """
        # Summary

        A set() of boolean values indicating whether any tasks failed

        - If the set contains True, at least one task failed.
        - If the set contains only False all tasks succeeded.

        ## Raises

        None

        ## See also

        -  `register_task_result()` method to register tasks and update the failed set.
        """
        return self._failed

    @property
    def metadata(self) -> list[dict[str, Any]]:
        """
        # Summary

        A list of dicts representing the metadata for all registered tasks.

        ## Raises

        None

        ## Returns

        - `list[dict[str, Any]]`: List of metadata dictionaries from all registered tasks
        """
        return [task.metadata for task in self._tasks]

    @property
    def metadata_current(self) -> dict[str, Any]:
        """
        # Summary

        Return the current metadata which is comprised of the following properties:

        - action
        - check_mode
        - sequence_number
        - state

        ## Raises

        None
        """
        value: dict[str, Any] = {}
        value["action"] = self.action
        value["check_mode"] = self.check_mode
        value["sequence_number"] = self.task_sequence_number
        value["state"] = self.state
        return value

    @property
    def response_current(self) -> dict[str, Any]:
        """
        # Summary

        Return a `dict` containing the current response from the controller for the current task.

        ## Raises

        -   setter: `TypeError` if value is not a dict
        """
        return self._current.response

    @response_current.setter
    def response_current(self, value: dict[str, Any]) -> None:
        method_name: str = "response_current"
        if not isinstance(value, dict):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"value must be a dict. Got {type(value).__name__}."
            raise TypeError(msg)
        self._current.response = value

    @property
    def response(self) -> list[dict[str, Any]]:
        """
        # Summary

        Return the response list; `list` of `dict`, where each `dict` contains a
        response from the controller across all registered tasks.

        ## Raises

        None

        ## Returns

        - `list[dict[str, Any]]`: List of response dictionaries from all registered tasks
        """
        return [task.response for task in self._tasks]

    @property
    def response_data(self) -> list[dict[str, Any]]:
        """
        # Summary

        Return a `list` of `dict`, where each `dict` contains the contents of the DATA key
        within the responses that have been added.

        ## Raises

        None

        ## See also

        `add_response_data()` method to add to the response_data list.
        """
        return self._response_data

    @property
    def result(self) -> list[dict[str, Any]]:
        """
        # Summary

        A `list` of `dict`, where each `dict` contains a result across all registered tasks.

        ## Raises

        None

        ## Returns

        - `list[dict[str, Any]]`: List of result dictionaries from all registered tasks
        """
        return [task.result for task in self._tasks]

    @property
    def result_current(self) -> dict[str, Any]:
        """
        # Summary

        A `dict` representing the current result for the current task.

        ## Raises

        -   setter: `TypeError` if value is not a dict
        """
        return self._current.result

    @result_current.setter
    def result_current(self, value: dict[str, Any]) -> None:
        method_name: str = "result_current"
        if not isinstance(value, dict):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"value must be a dict. Got {type(value).__name__}."
            raise TypeError(msg)
        self._current.result = value

    @property
    def state(self) -> str:
        """
        # Summary

        The Ansible state for the current task.

        ## Raises

        -   setter: `TypeError` if value is not a string
        """
        return self._current.state

    @state.setter
    def state(self, value: str) -> None:
        method_name: str = "state"
        if not isinstance(value, str):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"value must be a string. Got {type(value).__name__}."
            raise TypeError(msg)
        self._current.state = value
