#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__copyright__ = "Copyright (c) 2025 Cisco and/or its affiliates."
__author__ = "Mike Wiebe"

DOCUMENTATION = """

---
module: manage_fabric
short_description: Manage fabrics in Cisco Nexus Dashboard.
version_added: "1.0.0"
author: Mike Wiebe (@mikewiebe)
description:
- Create, update, delete, override, and query fabrics in Cisco Nexus Dashboard.
- Supports Pydantic model validation for fabric configurations.
- Provides utility functions for merging models and handling default values.
- Uses state-based operations with intelligent diff calculation for optimal API calls.
options:
    state:
        choices:
        - merged
        - replaced
        - deleted
        - overridden
        - query
        default: merged
        description:
        - The state of the fabric configuration after module completion.
        type: str
    config:
        description:
        - A list of fabric configuration dictionaries.
        type: list
        elements: dict
        suboptions:
            name:
                description:
                - Name of the fabric. Must start with a letter and contain only alphanumeric characters, underscores, or hyphens.
                required: true
                type: str
            category:
                description:
                - Category of the fabric.
                type: str
                default: fabric
            securityDomain:
                description:
                - Security domain for the fabric.
                type: str
                default: all
            management:
                description:
                - Management configuration for the fabric.
                type: dict
                suboptions:
                    type:
                        description:
                        - Management type for the fabric.
                        type: str
                        choices:
                        - vxlanIbgp
                        - vxlanEbgp
                        - vxlanCampus
                        - aimlVxlanIbgp
                        - aimlVxlanEbgp
                        - aimlRouted
                        - routed
                        - classicLan
                        - classicLanEnhanced
                        - ipfm
                        - ipfmEnhanced
                        - externalConnectivity
                        - vxlanExternal
                        - aci
                        - meta
                        default: vxlanIbgp
                    bgpAsn:
                        description:
                        - BGP autonomous system number. Must be a valid ASN string (plain or dotted notation).
                        required: true
                        type: str
                    anycastGatewayMac:
                        description:
                        - Anycast gateway MAC address in Cisco format (XXXX.XXXX.XXXX).
                        type: str
                        default: 2020.0000.00aa
                    replicationMode:
                        description:
                        - Replication mode for the fabric.
                        type: str
                        choices:
                        - multicast
                        - ingress
                        default: multicast
"""

EXAMPLES = """
# Create a new fabric or update an existing one
- name: Create or update fabric
  cisco.nd.manage_fabric:
    state: merged
    config:
      - name: example-fabric
        category: fabric
        securityDomain: default
        management:
          type: vxlanIbgp
          bgpAsn: "65001"
          anycastGatewayMac: "00:00:00:00:00:01"
          replicationMode: multicast

# Replace existing fabric configuration
- name: Replace fabric configuration
  cisco.nd.manage_fabric:
    state: replaced
    config:
      - name: example-fabric
        category: fabric
        securityDomain: default
        management:
          type: vxlanIbgp
          bgpAsn: "65002"
          anycastGatewayMac: "00:00:00:00:00:02"
          replicationMode: ingress

# Delete a fabric
- name: Delete fabric
  cisco.nd.manage_fabric:
    state: deleted
    config:
      - name: example-fabric

# Query existing fabrics
- name: Query fabrics
  cisco.nd.manage_fabric:
    state: query
    config:
      - name: example-fabric
"""
import copy
import inspect
import logging
import re
from deepdiff import DeepDiff

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import (
    NDModule,
    nd_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage.fabric.model_playbook_fabric import (
    FabricModel,
)

from ..module_utils.common.log import Log


class GetHave:
    """
    Class to retrieve and process fabric state information from Nexus Dashboard (ND).

    This class handles the retrieval of fabric state information from the Nexus Dashboard
    API and processes the response into a list of FabricModel objects.

    Attributes:
        class_name (str): Name of the class.
        log (Logger): Logger instance for this class.
        path (str): API endpoint path for fabric information.
        verb (str): HTTP method used for the request (GET).
        fabric_state (dict): Raw fabric state data retrieved from ND.
        have (list): List of processed FabricModel objects.
        nd: Nexus Dashboard instance for making API requests.

    Methods:
        refresh(): Fetches the current fabric state from Nexus Dashboard.
        validate_nd_state(): Processes the fabric state data into FabricModel objects.
    """

    def __init__(self, nd, logger=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.path = "/api/v1/manage/fabrics"
        self.verb = "GET"
        self.fabric_state = {}
        self.have = []
        self.nd = nd

        msg = "ENTERED GetHave(): "
        self.log.debug(msg)

    def refresh(self):
        """
        Refreshes the fabric state by fetching the latest data from the ND API.

        This method updates the internal fabric_state attribute with fresh data
        retrieved from the network controller using the configured path and HTTP verb.

        Returns:
            None: Updates the self.fabric_state attribute directly.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        self.fabric_state = self.nd.request(self.path, method=self.verb)

    def validate_nd_state(self):
        """
        Validates the Nexus Dashboard (ND) state by extracting fabric information.

        This method processes the current fabric state data stored in self.fabric_state,
        extracts relevant attributes for each fabric, and converts them into FabricModel
        objects that are appended to the self.have list.

        The method logs its entry point for debugging purposes and creates a standardized
        representation of each fabric with the following attributes:
        - name
        - category
        - securityDomain
        - management information (type, bgpAsn, anycastGatewayMac, replicationMode)

        Returns:
            None
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for fabric in self.fabric_state.get("fabrics"):
            if not isinstance(fabric, dict):
                raise ValueError(f"Fabric data is not a dictionary: {fabric}")
            validated_fabric = FabricModel(**fabric)
            self.have.append(validated_fabric)
            # Sample Fabric Structure
            # fabric = {
            #     "name": f"{fabric['name']}",
            #     "category": f"{fabric['category']}",
            #     "securityDomain": f"{fabric['securityDomain']}",
            #     "management": {
            #         "type": f"{fabric['management']['type']}",
            #         "bgpAsn": f"{fabric['management']['bgpAsn']}",
            #         "anycastGatewayMac": f"{fabric['management']['anycastGatewayMac']}",
            #         "replicationMode": f"{fabric['management']['replicationMode']}",
            #     }
            # }


class Common:
    """
    Common utility class that provides shared functionality for all state operations in the Cisco ND fabric module.

    This class handles the core logic for processing fabric configurations across different operational states
    (merged, replaced, deleted, overridden, query) in Ansible playbooks. It manages state comparison, parameter
    validation, and payload construction for ND API operations using Pydantic models and utility functions.

    The class leverages utility functions (merge_models, model_payload_with_defaults) to intelligently handle
    fabric configuration merging and default value application based on the operation state.

    Attributes:
        result (dict): Dictionary to store operation results including changed state, diffs, API responses and warnings.
        playbook_params (dict): Parameters provided from the Ansible playbook.
        state (str): The desired state operation (merged, replaced, deleted, overridden, or query).
        payloads (dict): Container for API request payloads.
        have (list): List of FabricModel objects representing the current state of fabrics.
        query (list): List for storing query results.
        validated (list): List of validated configuration items.
        want (list): List of FabricModel objects representing the desired state of fabrics.

    Methods:
        validate_playbook_params(): Validates the playbook parameters and builds the desired state using utility functions.
        fabric_in_have(fabric_name): Checks if a fabric with the given name exists in current state.
    """

    def __init__(self, playbook, have_state, logger=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.result = dict(changed=False, diff=[], response=[], warnings=[])
        self.playbook_params = playbook
        self.state = playbook["state"]
        self.payloads = {}

        self.have = have_state
        self.query = []
        self.validated = []
        self.want = []

        self.validate_playbook_params()

        msg = "ENTERED Common(): "
        msg += f"state: {self.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

    def validate_playbook_params(self):
        """
        Validates and processes playbook parameters to create fabric model objects.

        This method iterates through each fabric configuration in the playbook parameters
        and converts them into FabricModel instances based on the current state and
        existing fabric configurations. The resulting models are stored in the want list
        for further processing.

        The method uses utility functions to handle different scenarios:
        - For 'merged' state with existing fabrics: Uses merge_models() to combine current and desired state
        - For other states or when fabrics don't exist: Uses model_payload_with_defaults() for complete configuration

        The method handles the following scenarios:
        - 'merged' state for new and existing fabrics
        - 'replaced', 'deleted', 'overridden', and 'query' states

        Returns:
            None: Updates self.want list with processed FabricModel objects
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for fabric in self.playbook_params.get("config"):
            have_fabric = self.fabric_in_have(fabric["name"])
            want_fabric = FabricModel(**fabric)
            if self.state == "merged" and have_fabric is not None:
                fabric_config_payload = merge_models(have_fabric, want_fabric)
            else:
                # This handles
                #  - Merged when the fabric does not yet exist
                #  - Replaced, Deleted, and Query states
                fabric_config_payload = model_payload_with_defaults(want_fabric)

            fabric = FabricModel(**fabric_config_payload)
            self.log.debug("Adding fabric to want list: %s", fabric.name)
            self.log.debug("Fabric model created: %s", fabric.model_dump())
            # Add the fabric model to the want list
            self.want.append(fabric)

    def fabric_in_have(self, fabric_name):
        """
        Find a fabric by name in the current state.

        This method searches through the current state (`self.have`) for a fabric
        with the specified name and returns it if found.

        Args:
            fabric_name (str): The name of the fabric to find.

        Returns:
            object: The fabric object if found, None otherwise.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name} with fabric_name: {fabric_name}"
        self.log.debug(msg)

        # return any(fabric.name == fabric_name for fabric in self.have)
        have_fabric = next((h for h in self.have if h.name == fabric_name), None)
        return have_fabric


class Merged:
    """
    A class that implements the 'merged' state strategy for Cisco ND fabric configurations.

    This class compares the desired state ('want') with the current state ('have') of
    fabrics and generates the necessary API payloads to bring the current state in line
    with the desired state. When using the 'merged' state, existing configurations are
    preserved and only the differences or additions are applied.

    The class calculates differences between configurations using DeepDiff and constructs
    appropriate REST API calls (POST for new fabrics, PUT for existing ones) with payloads
    that reflect only the changes needed.

    Attributes:
        common (Common): Common utility instance for shared functionality
        verb (str): HTTP verb for the API call (POST or PUT)
        path (str): API endpoint path for the request

    Methods:
        build_payload(): Analyzes desired state against current state and builds API payloads
        update_payload_merged(have, want): Generates a merged payload from current and desired states
        _parse_path(path): Parses DeepDiff paths into component parts
        _process_values_changed(diff, updated_payload): Updates changed values in the payload
        _process_dict_items_added(diff, updated_payload, want_dict): Adds new items to the payload
    """

    def __init__(self, playbook, have_state, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util or Common(playbook, have_state)
        self.common.have = have_state

        self.verb = ""
        self.path = ""

        self.build_payload()

        msg = "ENTERED Merged(): "
        msg += f"state: {self.common.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

    def build_payload(self):
        """
        Build API payloads for creating or updating fabrics.

        This method compares the desired fabric configurations (want) with the current
        configurations (have) and prepares appropriate payloads for API operations.
        For each fabric in the desired state:
        - If the fabric matches the current state, it is skipped
        - If the fabric doesn't exist in the current state, a POST payload is created
        - If the fabric exists but differs from desired state, a PUT payload is created

        The method populates self.common.payloads with dictionaries containing:
        - verb: HTTP method (POST or PUT)
        - path: API endpoint path
        - payload: The data to be sent to the API

        No parameters are required as it uses instance attributes for processing.

        Returns:
            None: Updates self.common.payloads with operation details
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for fabric in self.common.want:
            want_fabric = fabric
            have_fabric = self.common.fabric_in_have(want_fabric.name)

            if want_fabric == have_fabric:
                # want_fabric and have_fabric are the same, no action needed
                self.log.debug("Fabric %s is already in the desired state, skipping.", want_fabric.name)
                continue

            if not have_fabric:
                # If the fabric does not exist in the have state, we will create it
                self.path = "/api/v1/manage/fabrics"
                self.verb = "POST"
                payload = copy.deepcopy(want_fabric.model_dump())
            else:
                # If the fabric already exists in the have state, we will update it
                self.path = "/api/v1/manage/fabrics" + f"/{want_fabric.name}"
                self.verb = "PUT"
                payload = self.update_payload_merged(have_fabric, want_fabric)

            self.common.payloads[want_fabric.name] = {
                "verb": self.verb,
                "path": self.path,
                "payload": payload,
            }

    def _parse_path(self, path):
        """
        Parse a string path into a list of path segments.

        This method handles two different path format notations:
        1. Dot notation: "root.key1.key2"
        2. Bracket notation: "root['key1']['key2']"

        In both cases, if the path starts with "root", this prefix is removed from the result.

        Args:
            path (str): The path string to parse in either dot or bracket notation.

        Returns:
            list: A list of path segments/keys.

        Examples:
            >>> _parse_path("root.key1.key2")
            ['key1', 'key2']
            >>> _parse_path("root['key1']['key2']")
            ['key1', 'key2']
            >>> _parse_path("key1.key2")
            ['key1', 'key2']
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)
        # Handle paths like "root.key1.key2"
        if "." in path and "[" not in path:
            parts = path.split(".")
            if parts[0] == "root":
                parts = parts[1:]
            return parts

        # Handle paths like "root['key1']['key2']"
        parts = re.findall(r"'([^']*)'", path)
        return parts

    def _process_values_changed(self, diff, updated_payload):
        """
        Process values that have changed in the diff and update the payload accordingly.

        This method handles updating nested dictionary values based on the diff structure.
        It navigates through the payload using the path provided in the diff and updates
        the corresponding value with the new value from the diff.

        Args:
            diff (dict): Dictionary containing differences, with a 'values_changed' key
                         that maps to changes where keys are paths and values are dicts
                         with 'new_value' keys.
            updated_payload (dict): The payload to be updated with the new values.

        Returns:
            None: This method updates the updated_payload in-place.

        Notes:
            - Requires self._parse_path method to convert path strings to list of keys
            - Logs debug information using self.log
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        if "values_changed" not in diff:
            return

        # Log the values changed for debugging
        self.log.debug("Values changed: %s", diff["values_changed"])

        for path, change in diff["values_changed"].items():
            parts = self._parse_path(path)

            # Navigate to the correct nested dictionary
            current = updated_payload
            for part in parts[:-1]:
                current = current[part]

            # Update the value
            current[parts[-1]] = change["new_value"]

    def _process_dict_items_added(self, diff, updated_payload, want_dict):
        """
        Process dictionary items that have been added according to the diff.

        This method updates the payload by adding items from the 'want' dictionary
        that are identified as newly added in the diff dictionary.

        Args:
            diff (dict): Dictionary containing differences between 'want' and 'have',
                         expected to have a 'dictionary_item_added' key if there are
                         items to add.
            updated_payload (dict): The payload dictionary to update with new items.
            want_dict (dict): The source dictionary containing the desired state with
                              items to be added.

        Returns:
            None: The method modifies the updated_payload dictionary in place.

        Note:
            The method uses _parse_path() to navigate the nested dictionary structure
            and properly place the new items at their correct locations.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        if "dictionary_item_added" not in diff:
            return

        # Log the dictionary items added for debugging
        self.log.debug("Dictionary items added: %s", diff["dictionary_item_added"])

        for path in diff["dictionary_item_added"]:
            parts = self._parse_path(path)

            # Navigate to the correct nested dictionary
            current = updated_payload
            for i, part in enumerate(parts[:-1]):
                if part not in current:
                    current[part] = {}
                current = current[part]

            # Get the value from want
            value = want_dict
            for part in parts:
                value = value[part]

            # Add the new item
            current[parts[-1]] = value

    def update_payload_merged(self, have, want):
        """
        Calculate the difference between the have and want states and generate an updated payload.

        This method computes what needs to be changed to transform the current state ('have')
        into the desired state ('want'). It uses DeepDiff to identify differences and applies
        a merge strategy, keeping existing values and updating only what's different or new.

        Parameters
        ----------
        have : object
            The current state of the object as a Pydantic model
        want : object
            The desired state of the object as a Pydantic model

        Returns
        -------
        dict
            Updated payload dictionary containing the merged state that reflects
            the differences between 'have' and 'want'

        Notes
        -----
        - Changed values are processed by _process_values_changed
        - New items are added via _process_dict_items_added
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        # Use DeepDiff to calculate the difference
        diff = DeepDiff(have, want, ignore_order=True)

        # Create a copy of have as a dictionary
        updated_payload = have.model_dump()

        # If there are no differences, just return the original payload
        # NOTE: I don't think we will ever hit this condition
        if not diff:
            return updated_payload

        # Get want as dictionary for reference
        want_dict = want.model_dump()

        # Update changed values and add any new items
        self._process_values_changed(diff, updated_payload)
        self._process_dict_items_added(diff, updated_payload, want_dict)

        return updated_payload


class Replaced:
    """
    A class for handling 'replaced' state operations on Cisco ND fabric resources.

    The Replaced class implements the logic for completely replacing existing fabric configurations
    with the desired configurations. When a fabric doesn't exist, it will be created; when it exists,
    it will be fully replaced with the specified configuration regardless of current settings.

    This differs from 'merged' state which would only update changed values and add new items.

    Parameters
    ----------
    playbook : dict
        The playbook containing the desired state ('want') for the fabrics
    have_state : dict
        The current state of fabrics in the system

    Attributes
    ----------
    common : Common
        Common utility instance for shared operations
    verb : str
        The HTTP verb (POST or PUT) for the API call
    path : str
        The API endpoint path for the operation

    Methods
    -------
    build_payload()
        Processes each fabric in the desired state, compares with current state, and builds
        appropriate API payloads for creation or replacement
    """

    def __init__(self, playbook, have_state, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util or Common(playbook, have_state)
        self.common.have = have_state

        self.verb = ""
        self.path = ""

        self.build_payload()

        msg = "ENTERED Replaced(): "
        msg += f"state: {self.common.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

    def build_payload(self):
        """
        Build API payloads for fabric management operations.

        This method processes the desired fabric configurations and generates
        appropriate API payloads for creating or updating fabrics. It compares
        the desired state (want) with the current state (have) and determines
        the necessary actions.

        The method performs the following operations:
        - Iterates through all desired fabric configurations
        - Compares each desired fabric with its current state
        - Skips fabrics that are already in the desired state
        - Creates POST payloads for new fabrics that don't exist
        - Creates PUT payloads for existing fabrics that need updates
        - Uses the complete desired configuration for replaced operations

        The generated payloads are stored in self.common.payloads dictionary
        with the fabric name as the key and a dictionary containing the HTTP
        verb, API path, and payload data as the value.

        Note:
            This method implements a "replaced" strategy where the entire
            desired configuration is used, including default values, rather
            than calculating only the differences like in a "merged" strategy.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for fabric in self.common.want:
            want_fabric = fabric
            have_fabric = self.common.fabric_in_have(want_fabric.name)

            if want_fabric == have_fabric:
                # want_fabric and have_fabric are the same, no action needed
                self.log.debug("Fabric %s is already in the desired state, skipping.", want_fabric.name)
                continue

            if not have_fabric:
                # If the fabric does not exist in the have state, we will create it
                self.path = "/api/v1/manage/fabrics"
                self.verb = "POST"
            else:
                # If the fabric already exists in the have state, we will update it
                self.path = "/api/v1/manage/fabrics" + f"/{want_fabric.name}"
                self.verb = "PUT"

            # For replaced we just use the want payload "as is" including any default values
            # This is different from merged where we calculate the difference and only update
            # the changed values and add any new items
            payload = copy.deepcopy(want_fabric.model_dump())
            self.common.payloads[want_fabric.name] = {
                "verb": self.verb,
                "path": self.path,
                "payload": payload,
            }


class Deleted:
    """
    Handle deletion of fabric configurations.

    This class manages the deletion of fabrics by comparing the desired state (want)
    with the current state (have) and preparing DELETE operations for fabrics that
    exist in both lists.

    Args:
        playbook: The playbook configuration containing the desired state
        have_state: The current state of fabrics in the system

    Attributes:
        class_name (str): Name of the current class for logging purposes
        log (logging.Logger): Logger instance for this class
        common (Common): Common utilities and state management
        verb (str): HTTP verb for the operation ("DELETE")
        path (str): API endpoint template for fabric deletion
        delete_fabric_names (list): List of fabric names to be deleted

    The class identifies fabrics that exist in both the desired configuration
    and current system state, then prepares the necessary API calls to delete
    those fabrics by formatting the deletion path for each fabric and storing
    the operation details in the common payloads dictionary.
    """

    def __init__(self, playbook, have_state, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util or Common(playbook, have_state)
        self.common.have = have_state
        self.verb = "DELETE"
        self.path = "/api/v1/manage/fabrics/{fabric_name}"

        # Create a list of fabric names to be deleted that are in both self.common.want and self.have
        self.delete_fabric_names = [fabric.name for fabric in self.common.want if fabric.name in [h.name for h in self.common.have]]

        for fabric in self.delete_fabric_names:
            # Create a path for each fabric name to be deleted
            self.common.payloads[fabric] = {
                "verb": self.verb,
                "path": self.path.format(fabric_name=fabric),
                "payload": "",
            }

        msg = "ENTERED Deleted(): "
        msg += f"state: {self.common.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)


class Overridden:
    """
    Handles the 'overridden' state for fabric management operations.

    This class manages the overridden state by deleting fabrics that exist in the current
    state but are not present in the desired state, and then creating or replacing fabrics
    that are specified in the desired state.

    The overridden operation is a combination of:
    1. Deleting fabrics that exist in 'have' but not in 'want'
    2. Creating or replacing fabrics specified in 'want'

    Args:
        playbook: The Ansible playbook context containing configuration data
        have_state: Current state of fabrics in the system
        logger (optional): Logger instance for debugging. Defaults to None
        common_util (optional): Common utility instance. Defaults to None
        replaced_task (optional): Replaced task instance. Defaults to None

    Attributes:
        class_name (str): Name of the current class
        log: Logger instance for debugging operations
        common: Common utility instance for shared operations
        verb (str): HTTP verb used for delete operations ('DELETE')
        path (str): API endpoint template for fabric deletion
        delete_fabric_names (list): List of fabric names to be deleted
    """

    def __init__(self, playbook, have_state, logger=None, common_util=None, replaced_task=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util or Common(playbook, have_state)
        self.common.have = have_state
        self.verb = "DELETE"
        self.path = "/api/v1/manage/fabrics/{fabric_name}"

        # Use the Replaced() to create new fabrics or replace existing ones
        replaced_task = Replaced(playbook, have_state)

        # Create a list of fabric names to be deleted that are not in self.common.want but are in self.have
        self.delete_fabric_names = [fabric.name for fabric in self.common.have if fabric.name not in [w.name for w in self.common.want]]

        for fabric in self.delete_fabric_names:
            # Create a path for each fabric name to be deleted
            self.common.payloads[fabric] = {
                "verb": self.verb,
                "path": self.path.format(fabric_name=fabric),
                "payload": "",
            }

        # Merge replace_task.common.payloads into self.common.payloads
        for fabric, request_data in replaced_task.common.payloads.items():
            self.common.payloads[fabric] = request_data

        msg = "ENTERED Overridden(): "
        msg += f"state: {self.common.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)


class Query:
    """
    Query class for managing fabric queries in Cisco ND.

    This class handles querying operations for fabric management in the Cisco Nexus Dashboard.
    It provides functionality to retrieve and return fabric state information.

    Args:
        playbook: The Ansible playbook context containing configuration parameters
        have_state: The current state of the fabric being queried

    Attributes:
        class_name (str): The name of the current class
        log (logging.Logger): Logger instance for the Query class
        common (Common): Common utility instance for shared operations
        have: The current have state of the fabric

    Note:
        This class is part of the Cisco ND Ansible collection for fabric management
        operations and follows the standard query pattern for state retrieval.
    """

    def __init__(self, playbook, have_state, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")
        self.common = common_util or Common(playbook, have_state)
        self.have = have_state

        msg = "ENTERED Query(): "
        msg += f"state: {self.common.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)


def merge_models(have_model, want_model):
    """
    Recursively merge two Pydantic models, preferring values from want_model when present.

    This utility function combines two Pydantic model instances by taking values from the
    want_model when they are not None, otherwise preserving values from have_model.
    It handles nested Pydantic models by recursively applying the same merge logic.

    Args:
        have_model (BaseModel): The current/existing Pydantic model instance
        want_model (BaseModel): The desired Pydantic model instance with new values

    Returns:
        dict: A dictionary suitable for API payloads containing the merged configuration

    Raises:
        ValueError: If either argument is not a Pydantic model instance

    Example:
        >>> have_fabric = FabricModel(name="test", category="fabric")
        >>> want_fabric = FabricModel(name="test", category="updated")
        >>> merged = merge_models(have_fabric, want_fabric)
        >>> # Result: {"name": "test", "category": "updated", ...}
    """
    from pydantic import BaseModel

    if not isinstance(have_model, BaseModel) or not isinstance(want_model, BaseModel):
        raise ValueError("Both arguments must be Pydantic models.")
    result = {}
    for field in type(have_model).model_fields:
        have_value = getattr(have_model, field)
        new_value = getattr(want_model, field, None)
        # If the field is itself a Pydantic model, recurse
        if isinstance(have_value, BaseModel) and isinstance(new_value, BaseModel):
            result[field] = merge_models(have_value, new_value)
        else:
            # Use new_value if not None, else have_value
            result[field] = new_value if new_value is not None else have_value
    return result


def model_payload_with_defaults(want_model):
    """
    Build a payload dict from a Pydantic model, using set fields or default values if not set.

    This utility function creates a dictionary representation of a Pydantic model by using
    the actual field values when they are set, or falling back to the model's default values
    when fields are not explicitly provided. It handles nested Pydantic models recursively.

    Args:
        want_model (BaseModel): The Pydantic model instance to convert to a payload dict

    Returns:
        dict: A dictionary containing all model fields with their values or defaults,
              suitable for API payloads

    Example:
        >>> fabric = FabricModel(name="test")  # Other fields use defaults
        >>> payload = model_payload_with_defaults(fabric)
        >>> # Result: {"name": "test", "category": "fabric", "securityDomain": "all", ...}

    Note:
        This function ensures that all required fields have values by using model defaults,
        making it suitable for 'replaced' and 'overridden' operations where complete
        configuration is needed.
    """
    from pydantic import BaseModel

    model_cls = type(want_model)
    result = {}
    for field, field_info in model_cls.model_fields.items():
        value = getattr(want_model, field, None)
        default_value = field_info.default
        # If the field is itself a Pydantic model, recurse
        if isinstance(field_info.annotation, type) and issubclass(field_info.annotation, BaseModel):
            if isinstance(value, BaseModel):
                result[field] = model_payload_with_defaults(value)
            else:
                result[field] = model_payload_with_defaults(field_info.default)
        else:
            result[field] = value if value is not None else default_value
    return result


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        state=dict(
            type="str",
            default="merged",
            choices=["merged", "replaced", "deleted", "overridden", "query"],
        ),
        config=dict(required=False, type="list", elements="dict"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Logging setup
    try:
        log = Log()
        log.commit()
        mainlog = logging.getLogger("nd.main")
    except ValueError as error:
        module.fail_json(str(error))

    mainlog.info("---------------------------------------------")
    mainlog.info("Starting cisco.nd.manage_fabric module")
    mainlog.info("---------------------------------------------\n")

    nd = NDModule(module)
    playbook = nd.params
    fabrics = GetHave(nd)
    fabrics.refresh()
    fabrics.validate_nd_state()

    try:
        task = None
        if playbook.get("state") == "merged":
            task = Merged(playbook, fabrics.have)
        elif playbook.get("state") == "replaced":
            task = Replaced(playbook, fabrics.have)
        elif playbook.get("state") == "deleted":
            task = Deleted(playbook, fabrics.have)
        elif playbook.get("state") == "overridden":
            task = Overridden(playbook, fabrics.have)
        elif playbook.get("state") == "query":
            task = Query(playbook, fabrics.have)
        if task is None:
            module.fail_json(f"Invalid state: {playbook['state']}")
    except ValueError as error:
        module.fail_json(f"{error}")

    # If the task is a query, we will just return the have state
    if isinstance(task, Query):
        for fabric in fabrics.have:
            task.common.query.append(fabric.model_dump())
        task.common.result["query"] = task.common.query
        task.common.result["changed"] = False
        module.exit_json(**task.common.result)

    # Process all the payloads from task.common.payloads
    # Sample entry:
    #   {'fabric-ansible': {'verb': 'DELETE', 'path': '/api/v1/manage/fabrics/fabric-ansible', 'payload': ''}
    if task.common.payloads:
        for fabric, request_data in task.common.payloads.items():
            verb = request_data["verb"]
            path = request_data["path"]
            payload = request_data["payload"]

            mainlog.info("Calling nd.request with path: %s, verb: %s, and payload: %s", path, verb, payload)
            # Make the API request
            response = nd.request(path, method=verb, data=payload if payload else None)
            task.common.result["response"].append(response)
            task.common.result["changed"] = True
    else:
        mainlog.info("No payloads to process")

    # nd.exit_json()
    module.exit_json(**task.common.result)


if __name__ == "__main__":
    main()
