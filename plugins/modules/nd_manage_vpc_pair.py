#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Neil John (@neijohn) <neijohn@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__copyright__ = "Copyright (c) 2025 Cisco and/or its affiliates."
__author__ = "Neil John"

DOCUMENTATION = """
---
module: nd_manage_vpc_pairs
short_description: Manage vPC pairs in Nexus devices.
version_added: "1.0.0"
author: Neil John (@neijohn)
description:
- Create, update, delete, override, and query vPC pairs on Nexus devices.
- Supports state-based operations with intelligent diff calculation for optimal API calls.
- Uses Pydantic model validation for vPC pair configurations.
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
        - The state of the vPC pair configuration after module completion.
        type: str
    deploy:
        description:
        - Deploy the configuration changes to the fabric after applying them.
        - When true, automatically saves the configuration and then triggers a fabric deployment via POST to /api/v1/manage/fabrics/{fabric}/actions/deploy?forceShowRun=true
        - Configuration is saved via POST to /api/v1/manage/fabrics/{fabric}/actions/configSave before deployment.
        - Deployment only occurs if there are actual changes (diff is not empty), pending operations, or switches in transitional states.
        - Cannot be used when state is 'query'.
        - Only applicable for states that modify configuration (merged, replaced, deleted, overridden).
        type: bool
        default: false
    dry_run:
        description:
        - When true, shows what changes would be made without actually executing them.
        - Displays all API requests that would be sent, the diff of changes, and whether deployment would occur.
        - No actual configuration changes are made to the fabric.
        - Useful for validating configurations and understanding what operations would be performed.
        - Cannot be used when state is 'query'.
        type: bool
        default: false
    config:
        description:
        - A list of vPC pair configuration dictionaries.
        type: list
        elements: dict
        suboptions:
            peer1_switch_id:
                description:
                - peer1 switch serial number for the vPC pair.
                - Must be a valid switch serial number.
                required: true
                type: str
            peer2_switch_id:
                description:
                - peer2 switch serial number for the vPC pair.
                - Must be a valid switch serial number.
                required: true
                type: str
            useVirtualPeerLink:
                description:
                - Enable virtual pair link for the vPC pair.
                - When true, virtual pair link is present and configured.
                - When false, physical pair link is used.
                type: bool
                default: true
"""

EXAMPLES = """
# Create a new vPC pair with virtual pair link
- name: Create vPC pair with virtual pair link
  cisco.nd.nd_manage_vpc_pairs:
    state: merged
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        useVirtualPeerLink: true

# Create a vPC pair with physical pair link
- name: Create vPC pair with physical pair link
  cisco.nd.nd_manage_vpc_pairs:
    state: merged
    config:
      - peer1_switch_id: "FDO23040Q87"
        peer2_switch_id: "FDO23040Q88"
        useVirtualPeerLink: false

# Create multiple vPC pairs
- name: Create multiple vPC pairs
  cisco.nd.nd_manage_vpc_pairs:
    state: merged
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        useVirtualPeerLink: true
      - peer1_switch_id: "FDO23040Q87"
        peer2_switch_id: "FDO23040Q88"
        useVirtualPeerLink: false

# Replace existing vPC pair configuration
- name: Replace vPC pair configuration
  cisco.nd.nd_manage_vpc_pairs:
    state: replaced
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        useVirtualPeerLink: false

# Delete a specific vPC pair
- name: Delete vPC pair
  cisco.nd.nd_manage_vpc_pairs:
    state: deleted
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"

# Query existing vPC pairs
- name: Query all vPC pairs
  cisco.nd.nd_manage_vpc_pairs:
    state: query

# Query specific vPC pair
- name: Query specific vPC pair
  cisco.nd.nd_manage_vpc_pairs:
    state: query
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"

# Override vPC pair configurations (replace all with specified configs)
- name: Override all vPC pair configurations
  cisco.nd.nd_manage_vpc_pairs:
    state: overridden
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        useVirtualPeerLink: true
      - peer1_switch_id: "FDO23040Q89"
        peer2_switch_id: "FDO23040Q90"
        useVirtualPeerLink: false

# Override without any new vPC pairs (delete all existing)
- name: Override without any new vPC pairs
  cisco.nd.nd_manage_vpc_pairs:
    state: overridden

# Create vPC pair and deploy the configuration changes
# Note: When deploy=true, deployment only occurs if there are actual changes or pending operations
# Configuration is automatically saved before deployment
- name: Create vPC pair and deploy changes
  cisco.nd.nd_manage_vpc_pairs:
    state: merged
    deploy: true
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        useVirtualPeerLink: true

# Use dry run to preview what changes would be made without executing them
# Shows all planned API requests, diff information, and deployment decision
- name: Preview vPC pair changes with dry run
  cisco.nd.nd_manage_vpc_pairs:
    state: merged
    deploy: true
    dry_run: true
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        useVirtualPeerLink: true

# Dry run to check what deployment actions would be taken
- name: Preview deployment actions only
  cisco.nd.nd_manage_vpc_pairs:
    state: query
    deploy: true
    dry_run: true
- name: Create vPC pair with deployment
  cisco.nd.nd_manage_vpc_pairs:
    state: merged
    deploy: true
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        useVirtualPeerLink: true

# Replace vPC pair configuration and deploy changes
# Note: Configuration save and deploy happen automatically when deploy=true
- name: Replace vPC pair with deployment
  cisco.nd.nd_manage_vpc_pairs:
    state: replaced
    deploy: true
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        useVirtualPeerLink: false

# Delete vPC pair and deploy the changes
# Note: Configuration is saved automatically before deployment
- name: Delete vPC pair with deployment
  cisco.nd.nd_manage_vpc_pairs:
    state: deleted
    deploy: true
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
"""

RETURN = """
changed:
    description: Whether the module made any changes
    type: bool
    returned: always
    sample: true
diff:
    description: Dictionary of configurations grouped by operation type (POST, PUT, DELETE). Only populated with keys for operations that were actually performed.
    type: dict
    returned: always
    sample: {
        "POST": [
            {
                "peer1SwitchId": "FDO23040Q85",
                "peer2SwitchId": "FDO23040Q86",
                "useVirtualPeerLink": true
            }
        ],
        "PUT": [
            {
                "peer1SwitchId": "FDO23040Q85",
                "peer2SwitchId": "FDO23040Q86",
                "useVirtualPeerLink": false
            }
        ]
    }
response:
    description: List of API responses from the Nexus Dashboard with operation context
    type: list
    returned: always
    sample: [
        {
            "vpc_pair_key": "FDO23040Q85-FDO23040Q86",
            "operation": "POST",
            "path": "/api/v1/manage/fabrics/fabric1/vpcPairs",
            "response": {
                "status": "success",
                "message": "vPC pair created successfully"
            }
        }
    ]
warnings:
    description: List of warning messages
    type: list
    returned: when applicable
    sample: []
query:
    description: Current state of vPC pairs (only returned in query state). The pending_create_vpc_pairs and pending_delete_vpc_pairs keys are only included if there are items in those lists.
    type: dict
    returned: when state is query
    sample: {
        "vpc_pairs": [
            {
                "peer1SwitchId": "FDO23040Q85",
                "peer2SwitchId": "FDO23040Q86",
                "useVirtualPeerLink": true
            }
        ],
        "pending_create_vpc_pairs": [
            {
                "peer1SwitchId": "FDO23040Q87",
                "peer2SwitchId": "FDO23040Q88",
                "useVirtualPeerLink": false
            }
        ],
        "pending_delete_vpc_pairs": [
            {
                "peer1SwitchId": "FDO23040Q89",
                "peer2SwitchId": "FDO23040Q90",
                "useVirtualPeerLink": true
            }
        ]
    }
pending_create_pairs_not_in_delete:
    description: List of vPC pairs in pending create state that are not specified in delete wants
    type: list
    returned: when state is deleted
    sample: [
        {
            "peer1SwitchId": "FDO23040Q87",
            "peer2SwitchId": "FDO23040Q88",
            "useVirtualPeerLink": false
        }
    ]
pending_delete_pairs_not_in_delete:
    description: List of vPC pairs in pending delete state that are not specified in delete wants
    type: list
    returned: when state is deleted
    sample: [
        {
            "peer1SwitchId": "FDO23040Q89",
            "peer2SwitchId": "FDO23040Q90",
            "useVirtualPeerLink": true
        }
    ]
"""

import copy
import inspect
import logging
import re
import traceback
import sys
import json

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
from ansible.module_utils.basic import missing_required_lib

from ..module_utils.common.log import Log
from ansible_collections.cisco.nd.plugins.module_utils.manage.vpc_pair.model_playbook_vpc_pair import VpcPairModel

try:
    from deepdiff import DeepDiff
except ImportError:
    HAS_DEEPDIFF = False
    DEEPDIFF_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_DEEPDIFF = True
    DEEPDIFF_IMPORT_ERROR = None

class UpdateInventory:
    """
    Class to update the Ansible inventory with vPC pair information.

    This class is responsible for updating the Ansible inventory with the current state
    of switches retrieved from Nexus Dashboard (ND).

    Attributes:
        nd: Nexus Dashboard instance for making API requests.
        switches: List of SwitchModel objects representing the current state of switches.
        logger: Logger instance for logging debug information.
        path: API endpoint path for retrieving switch information.
        verb: HTTP method used for the request (GET).
        sw_sn_from_ip: Dictionary mapping switch IP addresses to serial numbers.
    """

    def __init__(self, nd, logger=None):
        self.class_name = self.__class__.__name__
        self.nd = nd
        self.switches = []
        self.logger = logger or logging.getLogger(f"nd.{self.class_name}")
        self.path = f"/api/v1/manage/fabrics/{self.nd.params.get('fabric')}/switches"
        self.verb = "GET"
        self.sw_sn_from_ip = {}

    def refresh(self):
        """
        Refreshes the switch state by fetching the latest data from the ND API.

        This method updates the internal switches attribute with fresh data
        retrieved from the network controller using the configured path and HTTP verb.

        Returns:
            None: Updates the self.switches attribute directly.
        """
        self.logger.debug("Fetching switch state from ND API at path: %s with verb: %s", self.path, self.verb)
        response = self.nd.request(self.path, method=self.verb)
        self.switches = response.get("switches", [])
        if not self.switches:
            self.logger.warning("No switches found in the response from ND API.")
            return
        self.logger.debug("Switch state retrieved: %s", json.dumps(self.switches, indent=2))
        # Create switch ip to serial number mapping
        self.sw_sn_from_ip = {sw["fabricManagementIp"]: sw["serialNumber"] for sw in self.switches if "fabricManagementIp" in sw and "serialNumber" in sw}
        self.logger.info("Switch IP to Serial Number mapping: %s", self.sw_sn_from_ip)

class GetHave:
    """
    Class to retrieve and process vPC pair state information from Nexus Dashboard (ND).

    This class handles the retrieval of vPC pair state information from the Nexus Dashboard
    API and processes the response into a list of VpcPairModel objects.

    Attributes:
        class_name (str): Name of the class.
        log (Logger): Logger instance for this class.
        fabric (str): Fabric name to query vPC pairs for.
        path (str): API endpoint path for vPC pair information.
        recommendation_path (str): API endpoint path for vPC pair recommendations used for virtual peer link.
        verb (str): HTTP method used for the request (GET).
        vpc_pair_state (dict): Raw vPC pair state data retrieved from ND.
        want (list): List of processed VpcPairModel objects.
        nd: Nexus Dashboard instance for making API requests.
        sw_sn_from_ip (dict): Mapping of switch IP addresses to serial numbers.

    Methods:
        refresh(): Fetches the current vPC pair state from Nexus Dashboard.
        validate_nd_state(): Processes the vPC pair state data into VpcPairModel objects.
        get_virtual_peer_link_details(): Retrieves virtual peer link details for vPC pairs.
    """

    def __init__(self, nd, inventory, logger=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")
        self.fabric = nd.params.get("fabric")
        # self.path = f"/api/v1/manage/fabrics/{self.fabric}/vpcPairs"
        self.recommendation_path = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/vpcpair/recommendation?serialNumber="
        self.verb = "GET"
        self.vpc_pair_state = {}
        self.have = []
        self.nd = nd
        self.switches = inventory.switches
        msg = "ENTERED GetHave(): "
        self.log.debug(msg)

    def refresh(self):
        """
        Refreshes the vPC pair state by analyzing switch inventory data.

        This method processes the switches from inventory to:
        1. Identify existing vPC pairs from switches with vpcConfigured=true
        2. Track switches that are pending (not in vPC pairs)  
        3. Track switch pairs that are in vPC but marked as pending

        Returns:
            None: Updates the vpc_pair_list, pending_switches, and pending_vpc_pairs attributes
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        self.pending_switches = []
        self.pending_delete_vpc_pairs = []
        self.pending_create_vpc_pairs = []
        self.pending_pairs = []
        processed_switch_ids = set()

        # Process each switch to find vPC pairs and pending switches
        for switch in self.switches:
            switch_id = switch.get("switchId")

            if switch_id in processed_switch_ids:
                self.log.warning("Switch %s already processed", switch_id)
                continue
            
            other_peer = self.get_recommendation_details(switch_id)
            self.log.debug("Other peer details: %s"% other_peer)

            processed_switch_ids.add(switch_id)

            vpc_configured = switch.get("vpcConfigured", False)
            vpc_data = switch.get("vpcData", {})
            status = switch.get("additionalData", {}).get("configSyncStatus")
            self.log.debug(f"Processing switch: {switch_id}, vPC Configured: {vpc_configured}, Status: {status}")

            if vpc_configured and vpc_data:
                peer_switch_id = vpc_data.get("peerSwitchId")
                # Mark both switches as processed to avoid duplicate entries
                processed_switch_ids.add(peer_switch_id)
                
                # Create a VpcPairModel to get consistent pair key
                temp_vpc_pair_data = {
                    "peer1SwitchId": switch_id,
                    "peer2SwitchId": peer_switch_id,
                    "useVirtualPeerLink": False,  # Default to False, will be updated later if needed
                }
                temp_vpc_pair = VpcPairModel.get_model(temp_vpc_pair_data)
                if not other_peer:
                    self.pending_delete_vpc_pairs.append(temp_vpc_pair)
                else:
                    # old 3.2 api uses useVirtualPeerlink instead of useVirtualPeerLink (case sensitive)
                    self.log.debug("useVirtualPeerLink updated: %s"%other_peer.get("useVirtualPeerlink"))
                    temp_vpc_pair.useVirtualPeerLink = other_peer.get("useVirtualPeerlink", False)
                    self.have.append(temp_vpc_pair)
            elif other_peer:

                peer_switch_id = other_peer.get("serialNumber")
                # Mark both switches as processed to avoid duplicate entries
                processed_switch_ids.add(peer_switch_id)
                
                temp_vpc_pair_data = {
                    "peer1SwitchId": switch_id,
                    "peer2SwitchId": peer_switch_id,
                    "useVirtualPeerLink": other_peer.get("useVirtualPeerLink", False)
                }
                self.pending_create_vpc_pairs.append(VpcPairModel.get_model(temp_vpc_pair_data))

            self.log.debug("have: %s" % self.have)
            self.log.debug("pending_delete: %s" % self.pending_delete_vpc_pairs)
            self.log.debug("pending_create: %s" % self.pending_create_vpc_pairs)

        
    def get_recommendation_details(self, switchId):
        """
        Helper function to get recommendation details for a switch.

        Args:
            switchId (str): The switch ID for which to retrieve recommendation details.

        Returns:
            dict: A dictionary with the peer switch ID and useVirtualPeerLink status.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        path = f"{self.recommendation_path}{switchId}"
        vpc_pair_recommendation = self.nd.request(path, method=self.verb)

        for sw in vpc_pair_recommendation:
            if sw["currentPeer"] == True:
                return sw
        return None

class Common:
    """
    Common utility class that provides shared functionality for all state operations in the Cisco ND vPC pair module.

    This class handles the core logic for processing vPC pair configurations across different operational states
    (merged, replaced, deleted, overridden, query) in Ansible tasks. It manages state comparison, parameter
    validation, and payload construction for ND API operations using Pydantic models and utility functions.

    The class leverages utility functions (merge_models, model_payload_with_defaults) to intelligently handle
    vPC pair configuration merging and default value application based on the operation state.

    Attributes:
        modiresult (dict): Dictionary to store operation results including changed state, diffs, API responses and warnings.
        task_params (dict): Parameters provided from the Ansible task.
        state (str): The desired state operation (merged, replaced, deleted, overridden, or query).
        requests (dict): Container for API request requests.
        have (list): List of VpcPairModel objects representing the current state of vPC pairs.
        query (list): List for storing query results.
        validated (list): List of validated configuration items.
        want (list): List of VpcPairModel objects representing the desired state of vPC pairs.
        inventory (obj): Inventory object that contains the state of the switches in the fabric

    Methods:
        validate_task_params(): Validates the task parameters and builds the desired state using utility functions.
        get_pair_from_switches(vpc_pair_list, switch_id_1, switch_id_2): Checks if a vPC pair with the given pairs exists in the specified list.
    """

    def __init__(self, task_params, nd_instance, inventory, logger=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.result = dict(changed=False, diff={}, response=[], warnings=[])
        self.task_params = task_params
        self.state = task_params["state"]
        self.fabric = task_params["fabric"]
        self.deploy = task_params.get("deploy", False)
        self.dry_run = task_params.get("dry_run", False)
        self.requests = {}
        self.nd = nd_instance
        self.inventory = inventory
        self.have = []
        self.query = []
        self.validated = []
        self.want = []
        self.pending_delete_vpc_pairs = []
        self.pending_create_vpc_pairs = []
        msg = "ENTERED Common(): "
        msg += f"state: {self.state}, dry_run: {self.dry_run}, "
        self.log.debug(msg)
        self.validate_task_params()



    def validate_task_params(self):
        """
        Validates and processes task parameters to create vPC pair model objects.

        This method iterates through each vPC pair configuration in the task parameters
        and converts them into VpcPairModel instances based on the provided configurations.
        The resulting models are stored in the want list for further processing.

        Returns:
            None: Updates self.want list with processed VpcPairModel objects
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]
        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        if not self.task_params.get("config"):
            return 

        # check if we need to only work with switches in the fabric
        unique_switches_want = set()
        for vpc_pair in self.task_params.get("config", []):
            try:
                validated_config = VpcPairModel.get_model(
                    vpc_pair, 
                    state=self.state, 
                    extra="forbid",
                    sw_sn_from_ip=self.inventory.sw_sn_from_ip
                )
            except ValueError as error:
                self.nd.fail_json(msg=f"Invalid vPC pair configuration: {str(error)}")
            
            # Check uniqueness after Pydantic validation
            if validated_config.peer2SwitchId and validated_config.peer2SwitchId in unique_switches_want:
                self.nd.fail_json(msg=f"Switch IDs must be unique across vPC pairs: {validated_config.peer2SwitchId}")
            if validated_config.peer2SwitchId:
                unique_switches_want.add(validated_config.peer2SwitchId)

            if validated_config.peer1SwitchId in unique_switches_want:
                self.nd.fail_json(msg=f"Switch IDs must be unique across vPC pairs: {validated_config.peer1SwitchId}")
            unique_switches_want.add(validated_config.peer1SwitchId)
            
            self.want.append(validated_config)

        self.log.debug("Processed vPC pair configurations: %s", self.want)

    def get_pair_from_switches(self, vpc_pair_list, switch_id_1, switch_id_2=None):
        """
        Find a vPC pair by pair switch IDs in the current state.

        This method searches through the current state (`self.have`) for a vPC pair
        with the specified pair switch IDs and returns it if found.

        Args:
            switch_id_1 (str): The peer1 switch ID of the vPC pair to find.
            switch_id_2 (str): The peer2 switch ID of the vPC pair to find.

        Returns:
            object: The vPC pair object if found, None otherwise.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name} with switch_id_1: {switch_id_1}, switch_id_2: {switch_id_2}"
        self.log.debug(msg)

        if not switch_id_2:
            for vpc_pair in vpc_pair_list:
                vpc_pair_dict = vpc_pair.model_dump()
                peers = [vpc_pair_dict["peer1SwitchId"], vpc_pair_dict["peer2SwitchId"]]
                if switch_id_1 in peers:
                    return vpc_pair
        else:
            for vpc_pair in vpc_pair_list:
                vpc_pair_dict = vpc_pair.model_dump()
                peers = [vpc_pair_dict["peer1SwitchId"], vpc_pair_dict["peer2SwitchId"]]
                if switch_id_1 in peers and switch_id_2 in peers:
                    return vpc_pair
        return None

    def validate_no_switch_conflicts(self):
        """
        Validate that neither switch in vpc_pair want is present in a vpc_pair with another switch in have.
        
        This ensures that switches are not being added to conflicting vPC pairs.
        A switch can only be part of one vPC pair at a time.
        
        Raises:
            ValueError: If any switches in want are already part of different vPC pairs in have.
                       Contains all conflicts found, not just the first one.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        conflicts = []  # Collect all conflicts before raising error

        for want_vpc_pair in self.want:
            want_switches = {want_vpc_pair.peer1SwitchId, want_vpc_pair.peer2SwitchId}
            
            for have_vpc_pair in self.have:
                have_switches = {have_vpc_pair.peer1SwitchId, have_vpc_pair.peer2SwitchId}
                
                # Check if the wanted vPC pair is exactly the same as an existing one
                if want_switches == have_switches:
                    # Same vPC pair exists, this is fine for all operations
                    self.log.debug("vPC pair %s already exists in have state", want_vpc_pair.get_switch_pair_key())
                    break
                
                # Check for switch conflicts - any switch overlap with different pairs
                switch_overlap = want_switches & have_switches
                if switch_overlap:
                    conflicting_switches = ', '.join(switch_overlap)
                    want_key = want_vpc_pair.get_switch_pair_key()
                    have_key = have_vpc_pair.get_switch_pair_key()
                    
                    conflict_msg = (
                        f"Switch(es) {conflicting_switches} in wanted vPC pair {want_key} "
                        f"are already part of existing vPC pair {have_key}"
                    )
                    conflicts.append(conflict_msg)
                    self.log.error("Switch conflict detected: %s", conflict_msg)
        
        # Raise a single error with all conflicts if any were found
        if conflicts:
            error_msg = (
                f"Switch conflicts detected in vPC pair configuration. "
                f"A switch can only be part of one vPC pair at a time. "
                f"Conflicts found:\n" + "\n".join(f"- {conflict}" for conflict in conflicts)
            )
            self.log.error(error_msg)
            self.nd.fail_json(msg=error_msg)
        
        self.log.debug("No switch conflicts found in vpc pairs validation")

    def save_fabric_config(self):
        """
        Save the fabric configuration before deploying changes.
        
        This method sends a POST request to the fabric config save endpoint to save
        the current configuration state. This should be called before deploying
        configuration changes.
        
        Returns:
            dict: Response from the config save API call
            
        Raises:
            Exception: If the config save operation fails
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]
        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)
        
        # Don't save if state is query
        if self.state == "query":
            self.log.debug("Skipping config save for query state")
            return None
            
        # Don't save if deploy parameter is False (no need to save if we're not deploying)
        if not self.deploy:
            self.log.debug("Deploy parameter is False, skipping config save")
            return None
            
        config_save_path = f"/api/v1/manage/fabrics/{self.fabric}/actions/configSave"
        self.log.info(f"Saving fabric configuration via: {config_save_path}")
        
        try:
            response = self.nd.request(config_save_path, method="POST", data={})
            self.log.debug("Config save response: %s", response)
            
            # Store config save response with additional context
            config_save_response_entry = {
                "operation": "CONFIG_SAVE",
                "path": config_save_path, 
                "response": response
            }
            self.result["response"].append(config_save_response_entry)
            
            return response
            
        except Exception as error:
            error_msg = f"Failed to save fabric configuration: {str(error)}"
            self.log.error(error_msg)
            self.nd.fail_json(msg=error_msg)

    def needs_deployment(self):
        """
        Determine if deployment is needed based on current state and changes.
        
        Deployment is needed if any of the following conditions are met:
        1. There are items in the diff (actual configuration changes were made)
        2. There are pending create vPC pairs (switches ready to be paired)
        3. There are pending delete vPC pairs (switches ready to be unpaired)
        4. There are any requests in the requests dictionary (operations to be performed)
        
        Returns:
            bool: True if deployment is needed, False otherwise
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]
        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)
        
        # Check if there are any changes in the diff
        has_diff_changes = any(
            self.result.get("diff", {}).get(operation, [])
            for operation in ["POST", "PUT", "DELETE"]
        )
        
        # Check if there are pending operations
        has_pending_create = bool(self.pending_create_vpc_pairs)
        has_pending_delete = bool(self.pending_delete_vpc_pairs)
        
        # Check if there are any API requests to be made
        has_requests = bool(self.requests)
        
        self.log.debug(f"Deployment needs assessment:")
        self.log.debug(f"  - Has diff changes: {has_diff_changes}")
        self.log.debug(f"  - Has pending create pairs: {has_pending_create} (count: {len(self.pending_create_vpc_pairs)})")
        self.log.debug(f"  - Has pending delete pairs: {has_pending_delete} (count: {len(self.pending_delete_vpc_pairs)})")
        self.log.debug(f"  - Has API requests: {has_requests} (count: {len(self.requests)})")
        
        deployment_needed = has_diff_changes or has_pending_create or has_pending_delete or has_requests
        
        self.log.info(f"Deployment needed: {deployment_needed}")
        return deployment_needed

    def deploy_fabric(self):
        """
        Deploy the fabric configuration changes after applying vPC pair operations.
        
        This method first checks if deployment is actually needed based on:
        - Presence of configuration changes (diff)
        - Pending create/delete vPC pairs
        - Any API requests that were made
        
        If deployment is needed, it saves the current configuration and then sends a POST request 
        to the fabric deploy endpoint. It should only be called after all other vPC pair operations 
        have been completed successfully.
        
        Returns:
            dict: Response from the deploy API call, or None if deployment is not needed
            
        Raises:
            Exception: If the config save or deploy operation fails
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]
        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)
        
        # Don't deploy if state is query
        if self.state == "query":
            self.log.debug("Skipping deploy for query state")
            return None
            
        # Don't deploy if deploy parameter is False
        if not self.deploy:
            self.log.debug("Deploy parameter is False, skipping deployment")
            return None
        
        # Check if deployment is actually needed
        if not self.needs_deployment():
            self.log.info("No configuration changes or pending operations detected, skipping deployment")
            return None
        
        # Save configuration before deploying
        self.log.info("Configuration changes detected, saving fabric configuration before deployment")
        self.save_fabric_config()
            
        deploy_path = f"/api/v1/manage/fabrics/{self.fabric}/actions/deploy?forceShowRun=true"
        self.log.info(f"Deploying fabric configuration changes via: {deploy_path}")
        
        try:
            response = self.nd.request(deploy_path, method="POST", data={})
            self.log.debug("Deploy response: %s", response)
            
            # Store deploy response with additional context
            deploy_response_entry = {
                "operation": "DEPLOY",
                "path": deploy_path, 
                "response": response
            }
            self.result["response"].append(deploy_response_entry)
            
            # Mark as changed if deploy was triggered
            self.result["changed"] = True
            
            return response
            
        except Exception as error:
            error_msg = f"Failed to deploy fabric configuration: {str(error)}"
            self.log.error(error_msg)
            self.nd.fail_json(msg=error_msg)

    def show_dry_run_deployment_info(self):
        """
        Show what deployment actions would be taken in dry run mode.
        
        This method evaluates whether deployment would occur and provides
        detailed information about the deployment decision factors without
        actually performing the deployment.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]
        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)
        
        deployment_needed = self.needs_deployment()
        
        deployment_info = {
            "would_deploy": deployment_needed,
            "deployment_decision_factors": {
                "diff_has_changes": bool(self.result.get("diff", {}).get("after") != self.result.get("diff", {}).get("before")),
                "pending_operations": bool(self.pending_create_vpc_pairs or self.pending_delete_vpc_pairs),
                "api_requests_generated": bool(self.result.get("response", []))
            }
        }
        
        if deployment_needed:
            deployment_info["planned_actions"] = [
                f"POST /api/v1/manage/fabrics/{self.fabric}/actions/configSave",
                f"POST /api/v1/manage/fabrics/{self.fabric}/actions/deploy?forceShowRun=true"
            ]
            self.log.info("DRY RUN: Would deploy fabric configuration changes")
        else:
            deployment_info["reason_skipped"] = "No changes detected (diff empty, no pending operations, no API requests)"
            self.log.info("DRY RUN: Would skip deployment - no changes detected")
        
        # Store deployment info in result
        self.result["deployment"] = deployment_info



class Merged:
    """
    A class that implements the 'merged' state strategy for Cisco ND vPC pair configurations.

    This class compares the desired state ('want') with the current state ('have') of
    vPC pairs and generates the necessary API requests to bring the current state in line
    with the desired state. When using the 'merged' state, existing configurations are
    preserved and only the differences or additions are applied.

    The class calculates differences between configurations using DeepDiff and constructs
    appropriate REST API calls (POST for new vPC pairs, PUT for existing ones) with requests
    that reflect only the changes needed.

    Attributes:
        common (Common): Common utility instance for shared functionality
        verb (str): HTTP verb for the API call (POST or PUT)
        path (str): API endpoint path for the request

    Methods:
        build_request(): Analyzes desired state against current state and builds API requests
        update_payload_merged(have, want): Generates a merged request payload from current and desired states
        _parse_path(path): Parses DeepDiff paths into component parts
        _process_values_changed(diff, updated_payload): Updates changed values in the payload
        _process_dict_items_added(diff, updated_payload, want_dict): Adds new items to the payload
    """

    def __init__(self, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")
        self.common = common_util

        msg = "ENTERED Merged(): "
        msg += f"state: {self.common.state}, "
        self.log.debug(msg)

        self.payload_request = {}
        self.build_request()
        self.log.debug("Payload request built: %s", self.payload_request)



    def build_request(self):
        """
        Build API request payloads for vPC pairs using DeepDiff.

        This method compares want vs have states using DeepDiff and creates payloads
        containing only the changed items. For new vPC pairs (not in have), the full
        payload is created. For existing pairs, only changed fields are included.

        Returns:
            None: Updates self.payload_request with diff-based payloads
        
        Raises:
            ValueError: If a switch in want is already part of a different vPC pair in have
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        # Validate switch conflicts first
        self.common.validate_no_switch_conflicts()

        for want_vpc_pair in self.common.want:
            vpc_pair_key = want_vpc_pair.get_switch_pair_key()
            
            # Start with empty payload
            payload = {}
            
            # Find corresponding vPC pair in have (if it exists)
            have_vpc_pair = self.common.get_pair_from_switches(
                self.common.have, 
                want_vpc_pair.peer1SwitchId, 
                want_vpc_pair.peer2SwitchId
            )
            
            if not have_vpc_pair:
                # New vPC pair - use full payload from want
                payload = want_vpc_pair.to_api_payload()
                path = f"/api/v1/manage/fabrics/{self.common.fabric}/vpcPairs"
                verb = "POST"
                self.log.debug("New vPC pair %s - using full payload", vpc_pair_key)
            else:
                # Existing vPC pair - use DeepDiff to find changes
                self.log.debug("Existing vPC pair %s - calculating diff payload", vpc_pair_key)
                
                # # Convert models to dicts for DeepDiff
                # have_dict = have_vpc_pair.model_dump() if hasattr(have_vpc_pair, 'model_dump') else have_vpc_pair.dict()
                # want_dict = want_vpc_pair.model_dump() if hasattr(want_vpc_pair, 'model_dump') else want_vpc_pair.dict()
                
                # Use DeepDiff to calculate differences
                diff = DeepDiff(have_vpc_pair, want_vpc_pair, ignore_order=True, view="tree")

                if not diff:
                    self.log.debug("No differences found for vPC pair %s - skipping", vpc_pair_key)
                    continue
                
                self.log.debug("DeepDiff result for %s: %s", vpc_pair_key, diff)
                payload = { "useVirtualPeerLink": want_vpc_pair.useVirtualPeerLink }
                path = f"/api/v1/manage/fabrics/{self.common.fabric}/switches/{want_vpc_pair.peer1SwitchId}/vpcPairs"
                verb = "PUT"  # Existing pair, so we use PUT
            
            # Only add to payload_request if payload is not empty
            if payload:
                self.log.debug("Adding payload for vPC pair %s: %s", vpc_pair_key, payload)
                self.common.requests[vpc_pair_key] = {
                    "verb": verb,
                    "path": path,
                    "payload": payload
                }
            else:
                self.log.debug("Empty payload for vPC pair %s as it is present in have - skipping", vpc_pair_key)


class Replaced:
    """
    A class for handling 'replaced' state operations on Cisco ND vPC pair resources.

    The Replaced class implements the same logic as Merged - it compares the desired state
    with the current state and generates the necessary API requests to bring the current
    state in line with the desired state, preserving existing configurations and only
    applying differences or additions.

    This differs from a traditional 'replaced' operation which would completely replace
    configurations. In this implementation, 'replaced' behaves the same as 'merged'.

    Attributes:
        common (Common): Common utility instance for shared functionality
        verb (str): HTTP verb for the API call (POST or PUT)
        path (str): API endpoint path for the request

    Methods:
        build_request(): Analyzes desired state against current state and builds API requests
        _validate_no_switch_conflicts(): Validates that switches aren't in conflicting vPC pairs
    """

    def __init__(self, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")
        self.common = common_util

        msg = "ENTERED Replaced(): "
        msg += f"state: {self.common.state}, "
        self.log.debug(msg)

        self.payload_request = {}
        self.build_request()
        self.log.debug("Payload request built: %s", self.payload_request)

    def build_request(self):
        """
        Build API request payloads for vPC pairs using DeepDiff.

        This method compares want vs have states using DeepDiff and creates payloads
        containing only the changed items. For new vPC pairs (not in have), the full
        payload is created. For existing pairs, only changed fields are included.

        This implementation is identical to the Merged class behavior.

        Returns:
            None: Updates self.common.requests with diff-based payloads
        
        Raises:
            ValueError: If a switch in want is already part of a different vPC pair in have
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        # Validate switch conflicts first
        self.common.validate_no_switch_conflicts()

        for want_vpc_pair in self.common.want:
            vpc_pair_key = want_vpc_pair.get_switch_pair_key()
            
            # Start with empty payload
            payload = {}
            
            # Find corresponding vPC pair in have (if it exists)
            have_vpc_pair = self.common.get_pair_from_switches(
                self.common.have, 
                want_vpc_pair.peer1SwitchId, 
                want_vpc_pair.peer2SwitchId
            )
            
            if not have_vpc_pair:
                # New vPC pair - use full payload from want
                payload = want_vpc_pair.to_api_payload()
                path = f"/api/v1/manage/fabrics/{self.common.fabric}/vpcPairs"
                verb = "POST"
                self.log.debug("New vPC pair %s - using full payload", vpc_pair_key)
            else:
                # Existing vPC pair - use DeepDiff to find changes
                self.log.debug("Existing vPC pair %s - calculating diff payload", vpc_pair_key)
                
                # Use DeepDiff to calculate differences
                diff = DeepDiff(have_vpc_pair, want_vpc_pair, ignore_order=True, view="tree")

                if not diff:
                    self.log.debug("No differences found for vPC pair %s - skipping", vpc_pair_key)
                    continue
                
                self.log.debug("DeepDiff result for %s: %s", vpc_pair_key, diff)
                payload = { "useVirtualPeerLink": want_vpc_pair.useVirtualPeerLink }
                path = f"/api/v1/manage/fabrics/{self.common.fabric}/switches/{want_vpc_pair.peer1SwitchId}/vpcPairs"
                verb = "PUT"  # Existing pair, so we use PUT
            
            # Only add to payload_request if payload is not empty
            if payload:
                self.log.debug("Adding payload for vPC pair %s: %s", vpc_pair_key, payload)
                self.common.requests[vpc_pair_key] = {
                    "verb": verb,
                    "path": path,
                    "payload": payload
                }
            else:
                self.log.debug("Empty payload for vPC pair %s as it is present in have - skipping", vpc_pair_key)


class Deleted:
    """
    Handle deletion of vPC pair configurations.

    This class manages the deletion of vPC pairs by comparing the desired state (want)
    with the current state (have) and preparing DELETE operations for vPC pairs that
    exist in both lists.

    Args:
        task_params: The task_params configuration containing the desired state
        have_state: The current state of vPC pairs in the system

    Attributes:
        class_name (str): Name of the current class for logging purposes
        log (logging.Logger): Logger instance for this class
        common (Common): Common utilities and state management
        verb (str): HTTP verb for the operation ("DELETE")
        path (str): API endpoint template for vPC pair deletion
        delete_vpc_pair_keys (list): List of vPC pair keys to be deleted

    The class identifies vPC pairs that exist in both the desired configuration
    and current system state, then prepares the necessary API calls to delete
    those vPC pairs by formatting the deletion path for each vPC pair and storing
    the operation details in the common requests dictionary.
    """

    def __init__(self, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util
        self.verb = "DELETE"
        self.path = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/vpcpair?serialNumber={peer1SwitchId}"

        # Create a list of vPC pair keys to be deleted that are in both self.common.want and self.have
        
        # self.delete_vpc_pair_keys = []
        # for want_vpc_pair in self.common.want:
        #     have_vpc_pair = self.common.vpc_pair_in_have(want_vpc_pair.peer1_switch_id, want_vpc_pair.peer2_switch_id)
        #     if have_vpc_pair:
        #         vpc_pair_key = f"{want_vpc_pair.peer1_switch_id}-{want_vpc_pair.peer2_switch_id}"
        #         self.delete_vpc_pair_keys.append((vpc_pair_key, want_vpc_pair.peer1_switch_id, want_vpc_pair.peer2_switch_id))

        # for vpc_pair_key, peer1_switch_id, peer2_switch_id in self.delete_vpc_pair_keys:
        #     # Create a path for each vPC pair to be deleted
        #     self.common.requests[vpc_pair_key] = {
        #         "verb": self.verb,
        #         "path": self.path.format(fabric=self.common.nd.params.get('fabric'), peer1_switch_id=peer1_switch_id, peer2_switch_id=peer2_switch_id),
        #         "payload": "",
        #     }

        msg = "ENTERED Deleted(): "
        msg += f"state: {self.common.state}, "
        self.log.debug(msg)
        self.collect_deletion_requests()

    def _process_vpc_pair_deletions(self, vpc_pairs_to_delete, overview_path, pending_vpc_pairs_to_delete):
        """
        Helper method to process vPC pair deletions with validation checks.
        
        Args:
            vpc_pairs_to_delete (list): List of vPC pairs to delete
            overview_path (str): API path template for overview checks
        """
        # Remove pending delete pairs (they are already being deleted)
        pending_delete_keys = {pair.get_switch_pair_key() for pair in self.common.pending_delete_vpc_pairs}
        self.log.debug("Pending create vpc pairs to be deleted: %s (inconsistent, not handled right now)", pending_vpc_pairs_to_delete)
        for vpc_pair in vpc_pairs_to_delete:
            vpc_pair_key = vpc_pair.get_switch_pair_key()
            if vpc_pair_key in pending_delete_keys:
                self.log.debug(f"Skipping vPC pair {vpc_pair_key} as it is already in pending delete state.")
                continue

            self.log.debug(f"Preparing deletion for vPC pair: {vpc_pair_key}")
            
            response = self.common.nd.request(
                overview_path.format(switchId=vpc_pair.peer1SwitchId),
                method="GET",
            )
            self.log.debug("vPC pair overview request: %s", overview_path.format(switchId=vpc_pair.peer1SwitchId))
            self.log.debug("vPC pair overview response: %s", json.dumps(response, indent=2))
            if not response.get("overlayBase"):
                self.common.nd.fail_json(
                    msg=f"vPC pair {vpc_pair_key} might not exist",
                    response=response,
                )
            self.log.debug(response["overlayBase"]["networkCount"])
            for status, count in response["overlayBase"]["networkCount"].items():
                if int(count) != 0:
                    self.common.nd.fail_json(
                        msg=f"vPC pair {vpc_pair_key} cannot be deleted because it is in use by {count} networks. Detach these networks first, maybe using the networks module.",
                    )
            for status, count in response["overlayBase"]["vrfCount"].items():
                if int(count) != 0:
                    self.common.nd.fail_json(
                        msg=f"vPC pair {vpc_pair_key} cannot be deleted because it is in use by {count} VRFs. Detach these VRFs first, maybe using the VRFs module.",
                    )
            
            self.common.requests[vpc_pair_key] = {
                "verb": self.verb,
                "path": self.path.format(peer1SwitchId=vpc_pair.peer1SwitchId)
            }

    def collect_deletion_requests(self):
        """
        Get a list of vPC pairs that need to be deleted based on the current state.

        This method compares the desired state (want) with the current state (have)
        and identifies vPC pairs that exist in both lists, preparing them for deletion.
        It also handles pending create and pending delete lists according to the following rules:
        
        1. If a pair exists in pending_create which is not in deleted wants, add that to results
        2. If a pair is pending deleted, but is not mentioned in deleted wants, add that to results in a separate list
        3. If a pair is already in the pending deleted state and is in deleted want, remove from want and add to normal result

        Returns:
            None: Updates self.common.requests and self.common.result with deletion operations
        """

        overview_path = f"/api/v1/manage/fabrics/{self.common.fabric}/switches/{{switchId}}/vpcPairsOverview?componentType=overlay"
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]
        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        # Initialize result lists for pending pairs
        if "pending_create_pairs_not_in_delete" not in self.common.result:
            self.common.result["pending_create_pairs_not_in_delete"] = []
        if "existing_pending_deletes_not_in_request" not in self.common.result:
            self.common.result["existing_pending_deletes_not_in_request"] = []

        vpc_pairs_to_delete = []
        pending_vpc_pairs_to_delete = []
        # Handle case when no specific vPC pairs are requested for deletion
        if not self.common.want:
            self.log.debug("No vPC pairs specified in want, preparing to delete all existing vPC pairs ")
            vpc_pairs_to_delete = list(self.common.have)
            pending_vpc_pairs_to_delete = list(self.common.pending_delete_vpc_pairs)
        else:
            # prints existing pending creates that do not get deleted (deploy will create these)
            for pending_create_pair in self.common.pending_create_vpc_pairs:
                found_pair = self.common.get_pair_from_switches(
                    self.common.want,
                    pending_create_pair.peer1SwitchId,
                    pending_create_pair.peer2SwitchId
                )
                if not found_pair:
                    self.log.debug(f"Pending create vPC pair {pending_create_pair.get_switch_pair_key()} not in delete wants, adding to separate results list")
                    self.common.result["pending_create_pairs_not_in_delete"].append(pending_create_pair.model_dump())
                else:
                    pending_vpc_pairs_to_delete.append(pending_create_pair)

            # prints existing pending deletes not in request (deploy will delete these)
            for pending_delete_pair in self.common.pending_delete_vpc_pairs:
                found_pair = self.common.get_pair_from_switches(
                    self.common.want, 
                    pending_delete_pair.peer1SwitchId, 
                    pending_delete_pair.peer2SwitchId
                )

                if not found_pair:
                    self.log.debug(f"Pending delete vPC pair {pending_delete_pair.get_switch_pair_key()} not in delete wants, adding to separate results list")
                    self.common.result["existing_pending_deletes_not_in_request"].append(pending_delete_pair.model_dump())

            # Find vPC pairs that exist in both filtered_want and have
            for vpc_pair in self.common.want:
                found_pair = self.common.get_pair_from_switches(
                    self.common.have, 
                    vpc_pair.peer1SwitchId, 
                    vpc_pair.peer2SwitchId
                )
                if found_pair:
                    vpc_pairs_to_delete.append(vpc_pair)
   
        # Process the deletions using the helper method
        self._process_vpc_pair_deletions(vpc_pairs_to_delete, overview_path, pending_vpc_pairs_to_delete)


class Overridden:
    """
    Handles the 'overridden' state for vPC pair management operations.

    This class manages the overridden state by:
    1. Finding all vPC pairs in 'have' but not in 'want' and sending them to delete state
    2. Sending all remaining pairs (those in 'want') to replace state

    The overridden operation ensures that the final state matches exactly what is specified
    in the desired configuration, removing any vPC pairs not explicitly defined and
    creating/updating those that are defined.

    Args:
        logger (optional): Logger instance for debugging. Defaults to None
        common_util (optional): Common utility instance. Defaults to None

    Attributes:
        class_name (str): Name of the current class
        log: Logger instance for debugging operations
        common: Common utility instance for shared operations
    """

    def __init__(self, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util

        msg = "ENTERED Overridden(): "
        msg += f"state: {self.common.state}, "
        self.log.debug(msg)

        self.build_request()

    def build_request(self):
        """
        Build API requests for overridden state operations.

        This method implements the overridden state logic by:
        1. Finding all vPC pairs in 'have' but not in 'want' and using Deleted class to handle them
        2. Processing all vPC pairs in 'want' using replace logic (same as merge)

        The method ensures that the final state exactly matches the desired configuration
        by removing unwanted vPC pairs and creating/updating the desired ones.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]
        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        # Step 1: Find all vPC pairs in 'have' but not in 'want' and send them to delete state
        vpc_pairs_to_delete = []
        for have_vpc_pair in self.common.have:
            # Check if this have_vpc_pair exists in the want list
            found_in_want = self.common.get_pair_from_switches(
                self.common.want,
                have_vpc_pair.peer1SwitchId,
                have_vpc_pair.peer2SwitchId
            )
            
            if not found_in_want:
                vpc_pairs_to_delete.append(have_vpc_pair)
                self.log.debug(f"vPC pair {have_vpc_pair.get_switch_pair_key()} found in have but not in want - marking for deletion")

        # Use Deleted class to handle the deletion of unwanted vPC pairs
        if vpc_pairs_to_delete:
            self.log.debug(f"Creating temporary want list with {len(vpc_pairs_to_delete)} vPC pairs to delete")
            
            # Create a temporary common instance with the vPC pairs to delete as 'want'
            temp_common = copy.deepcopy(self.common)
            temp_common.want = vpc_pairs_to_delete
            
            # Use Deleted class to handle the deletions
            delete_handler = Deleted(common_util=temp_common)
            
            # Merge the deletion requests from the delete_handler into our main requests
            for vpc_pair_key, request_data in delete_handler.common.requests.items():
                # Prefix deletion requests to avoid conflicts with creation/update requests
                deletion_key = f"delete_{vpc_pair_key}" if not vpc_pair_key.startswith("delete_") else vpc_pair_key
                self.common.requests[deletion_key] = request_data
                self.log.debug(f"Added deletion request for vPC pair {vpc_pair_key}")

        # Step 2: Send all remaining pairs (those in 'want') to replace state
        # Use the Replaced class for processing wanted vPC pairs
        if self.common.want:
            self.log.debug(f"Using Replaced class to process {len(self.common.want)} vPC pairs in want")
            replaced_handler = Replaced(common_util=self.common)
            # The replaced_handler will have already populated self.common.requests with the replace operations


class Query:
    """
    Query class for managing vPC pair queries in Cisco ND.

    This class handles querying operations for vPC pair management in the Cisco Nexus Dashboard.
    It provides functionality to retrieve and return vPC pair state information.

    Args:
        task_params: The Ansible task_params context containing configuration parameters
        have_state: The current state of the vPC pairs being queried

    Attributes:
        class_name (str): The name of the current class
        log (logging.Logger): Logger instance for the Query class
        common (Common): Common utility instance for shared operations
        have: The current have state of the vPC pairs

    Note:
        This class is part of the Cisco ND Ansible collection for vPC pair management
        operations and follows the standard query pattern for state retrieval.
    """

    def __init__(self, common_util=None, logger=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")
        self.common = common_util

        msg = "ENTERED Query(): "
        msg += f"state: {self.common.state}, "
        self.log.debug(msg)
    
    def get_query_results(self):
        """
        Retrieve the current state of vPC pairs including pending create and delete lists when they contain items.

        This method collects the current state of vPC pairs from the have state
        and prepares it for output in the query result format. It conditionally includes
        separate lists for pending create and delete vpc pairs only if they contain items.

        When no specific search criteria (want) is provided, all vPC pairs are returned.
        When search criteria is provided, only matching vPC pairs are included in all lists.

        Returns:
            dict: A dictionary containing:
                - query: A nested dictionary with:
                    - vpc_pairs: List of active vPC pair configurations (always present, may be empty)
                    - pending_create_vpc_pairs: List of vPC pairs pending creation (only if items exist)
                    - pending_delete_vpc_pairs: List of vPC pairs pending deletion (only if items exist)
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable
        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)
        
        # Initialize result dictionary with vpc_pairs (always present)
        results = {
            "query": {
                "vpc_pairs": []
            }
        }
        
        if not self.common.want:
            # Return all vPC pairs when no specific search criteria provided
            results["query"]["vpc_pairs"] = [vpc_pair.model_dump() for vpc_pair in self.common.have]
            
            # Only add pending lists if they contain items
            if self.common.pending_create_vpc_pairs:
                results["query"]["pending_create_vpc_pairs"] = [vpc_pair.model_dump() for vpc_pair in self.common.pending_create_vpc_pairs]
            if self.common.pending_delete_vpc_pairs:
                results["query"]["pending_delete_vpc_pairs"] = [vpc_pair.model_dump() for vpc_pair in self.common.pending_delete_vpc_pairs]
        else:
            # Search for specific vPC pairs in have, pending_create, and pending_delete lists
            # Also filter pending lists based on want criteria
            pending_create_filtered = []
            pending_delete_filtered = []
            query_filtered = []

            for item in self.common.want:
                item_dict = item.model_dump()
                found_vpc_pair = None
                
                # Search in have list
                if item_dict.get("peer2SwitchId", None):
                    found_vpc_pair = self.common.get_pair_from_switches(
                        self.common.have, item_dict["peer1SwitchId"], item_dict["peer2SwitchId"])
                else:
                    found_vpc_pair = self.common.get_pair_from_switches(
                        self.common.have, item_dict["peer1SwitchId"])
                
                if found_vpc_pair:
                    query_filtered.append(found_vpc_pair)
                    continue
                
                # If not found in have, search in pending_create list
                if item_dict.get("peer2SwitchId", None):
                    found_vpc_pair = self.common.get_pair_from_switches(
                        self.common.pending_create_vpc_pairs, item_dict["peer1SwitchId"], item_dict["peer2SwitchId"])
                else:
                    found_vpc_pair = self.common.get_pair_from_switches(
                        self.common.pending_create_vpc_pairs, item_dict["peer1SwitchId"])
                
                if found_vpc_pair:
                    pending_create_filtered.append(found_vpc_pair)
                    continue
                
                # If not found in have or pending_create, search in pending_delete list
                if item_dict.get("peer2SwitchId", None):
                    found_vpc_pair = self.common.get_pair_from_switches(
                        self.common.pending_delete_vpc_pairs, item_dict["peer1SwitchId"], item_dict["peer2SwitchId"])
                else:
                    found_vpc_pair = self.common.get_pair_from_switches(
                        self.common.pending_delete_vpc_pairs, item_dict["peer1SwitchId"])
                
                if found_vpc_pair:
                    pending_delete_filtered.append(found_vpc_pair)
            
            # Set filtered lists in nested structure - vpc_pairs always present
            results["query"]["vpc_pairs"] = [vpc_pair.model_dump() for vpc_pair in query_filtered]
            
            # Only add pending lists if they contain filtered items
            if pending_create_filtered:
                results["query"]["pending_create_vpc_pairs"] = [vpc_pair.model_dump() for vpc_pair in pending_create_filtered]
            if pending_delete_filtered:
                results["query"]["pending_delete_vpc_pairs"] = [vpc_pair.model_dump() for vpc_pair in pending_delete_filtered]
        
        return results
        

def main():
    argument_spec = {}
    argument_spec.update(
        state=dict(
            type="str",
            default="merged",
            choices=["merged", "replaced", "deleted", "overridden", "query"],
        ),
        fabric=dict(required=True, type="str"),
        config=dict(required=False, type="list", elements="dict"),
        deploy=dict(required=False, type="bool", default=False),
        dry_run=dict(required=False, type="bool", default=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    if sys.version_info < (3, 9):
        module.fail_json(msg="Python version 3.9 or higher is required for this module.")

    if not HAS_DEEPDIFF:
        module.fail_json(msg=missing_required_lib("deepdiff"), exception=DEEPDIFF_IMPORT_ERROR)

    # Validate that deploy is not used with query state
    if module.params.get("state") == "query" and module.params.get("deploy"):
        module.fail_json(msg="Deploy parameter cannot be used with 'query' state")

    # Validate that dry_run is not used with query state
    if module.params.get("state") == "query" and module.params.get("dry_run"):
        module.fail_json(msg="Dry_run parameter cannot be used with 'query' state")

    # Logging setup
    try:
        log = Log()
        log.commit()
        mainlog = logging.getLogger("nd.main")
    except ValueError as error:
        module.fail_json(str(error))

    mainlog.info("---------------------------------------------")
    mainlog.info("Starting cisco.nd.nd_manage_vpc_pairs module")
    mainlog.info("---------------------------------------------\n")
    nd = NDModule(module)
    task_params = nd.params
    mainlog.debug("Task parameters: %s", task_params)
    inventory = UpdateInventory(nd)
    inventory.refresh()

    try:
        vpc_pairs = Common(task_params, nd, inventory)
    except ValueError as error:
        module.fail_json(msg=f"Configuration validation error: {str(error)}")

    vp_have = GetHave(nd, inventory)
    vp_have.refresh()

    have = vp_have.have

    vpc_pairs.have = have
    vpc_pairs.pending_delete_vpc_pairs = vp_have.pending_delete_vpc_pairs
    vpc_pairs.pending_create_vpc_pairs = vp_have.pending_create_vpc_pairs

    mainlog.debug("Haves: %s", vpc_pairs.have)
    mainlog.debug("Wants: %s", vpc_pairs.want)

    try:
        task = None
        if task_params.get("state") == "merged":
            task = Merged(common_util=vpc_pairs)
        elif task_params.get("state") == "replaced":
            task = Replaced(common_util=vpc_pairs)
        elif task_params.get("state") == "deleted":
            task = Deleted(common_util=vpc_pairs)
        elif task_params.get("state") == "overridden":
            task = Overridden(common_util=vpc_pairs)
        elif task_params.get("state") == "query":
            task = Query(common_util=vpc_pairs)
        if task is None:
            module.fail_json(f"Invalid state: {task_params['state']}")
    except ValueError as error:
        module.fail_json(f"{error}")

    #     # If the task is a query, we will just return the have state
    task.common.result["ip_to_sn_mapping"] = task.common.inventory.sw_sn_from_ip
    if isinstance(task, Query):
        # for vpc_pair in vpc_pairs.have:
        #     task.common.query.append(vpc_pair.model_dump(by_alias=True))
        query_results = task.get_query_results()
        task.common.result.update(query_results)
        
        task.common.result["changed"] = False
        module.exit_json(**task.common.result)

    # Process all the requests from task.common.requests
    # Sample entry:
    #   {'FDO23040Q85-FDO23040Q86': {'verb': 'DELETE', 'path': '/api/v1/manage/vpc-pairs/FDO23040Q85/FDO23040Q86', 'payload': ''}}
    if task.common.requests:
        for vpc_pair_key, request_data in task.common.requests.items():
            verb = request_data["verb"]
            path = request_data["path"]
            payload = request_data.get("payload", {})
            mainlog.debug("Processing request for vPC pair key: %s", vpc_pair_key)
            mainlog.debug("Verb: %s, Path: %s, Payload: %s", verb, path, payload)
            
            # Add payload/config to diff grouped by operation type
            if verb in ["POST", "PUT", "DELETE"]:
                # Ensure the operation key exists in diff
                if verb not in task.common.result["diff"]:
                    task.common.result["diff"][verb] = []
                
                if verb == "DELETE":
                    # For DELETE operations, extract switch IDs from vpc_pair_key or path
                    switch_ids = vpc_pair_key.replace("delete_", "").split("-")
                    if len(switch_ids) >= 2:
                        delete_config = {
                            "peer1SwitchId": switch_ids[0],
                            "peer2SwitchId": switch_ids[1]
                        }
                    else:
                        # Fallback: try to extract from path or use vpc_pair_key
                        delete_config = {"vpc_pair_key": vpc_pair_key}
                    task.common.result["diff"][verb].append(delete_config)
                elif verb == "PUT":
                    # For PUT operations, include switch IDs along with the payload
                    switch_ids = vpc_pair_key.replace("delete_", "").split("-")
                    if len(switch_ids) >= 2 and payload:
                        put_config = {
                            "peer1SwitchId": switch_ids[0],
                            "peer2SwitchId": switch_ids[1]
                        }
                        # Merge the payload into the config
                        put_config.update(payload)
                        task.common.result["diff"][verb].append(put_config)
                    elif payload:
                        # Fallback: just use payload if switch IDs can't be extracted
                        task.common.result["diff"][verb].append(payload)
                else:
                    # For POST, use the actual payload (which should already include switch IDs)
                    if payload:
                        task.common.result["diff"][verb].append(payload)
            
            # Pretty-print the payload for easier log reading
            pretty_payload = json.dumps(payload, indent=2, sort_keys=True)
            
            if task.common.dry_run:
                # In dry run mode, don't make actual API calls but log what would be done
                mainlog.info("DRY RUN: Would call nd.request with path: %s, verb: %s, and payload:\n%s", path, verb, pretty_payload)
                
                # Store dry run request information
                response_entry = {
                    "vpc_pair_key": vpc_pair_key,
                    "operation": verb,
                    "path": path,
                    "payload": payload,
                    "dry_run": True,
                    "response": "DRY RUN - No actual API call made"
                }
            else:
                # Normal mode - make actual API request
                mainlog.info("Calling nd.request with path: %s, verb: %s, and payload:\n%s", path, verb, pretty_payload)
                
                # Make the API request
                response = nd.request(path, method=verb, data=payload if payload else None)
                mainlog.debug("Response from nd.request: %s", response)
                
                # Store response with additional context
                response_entry = {
                    "vpc_pair_key": vpc_pair_key,
                    "operation": verb,
                    "path": path,
                    "response": response
                }
            
            task.common.result["response"].append(response_entry)
            
            # Only mark as changed if not in dry run mode
            if not task.common.dry_run:
                task.common.result["changed"] = True
    else:
        mainlog.info("No requests to process")

    # Deploy fabric changes if deploy parameter is True and state is not query
    if task.common.deploy and task.common.state != "query":
        if task.common.dry_run:
            mainlog.info("DRY RUN: Showing deployment information without executing")
            task.common.show_dry_run_deployment_info()
        else:
            mainlog.info("Deploy parameter is True, deploying fabric configuration changes")
            task.common.deploy_fabric()
    
    module.exit_json(**task.common.result)


if __name__ == "__main__":
    main()

