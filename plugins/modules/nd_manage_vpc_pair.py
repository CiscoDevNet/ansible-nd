# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__copyright__ = "Copyright (c) 2026 Cisco and/or its affiliates."
__author__ = "Sivakami S"

DOCUMENTATION = """
---
module: nd_vpc_pair
short_description: Manage vPC pairs in Nexus devices.
version_added: "1.0.0"
description:
- Create, update, delete, override, and gather vPC pairs on Nexus devices.
- Uses NDStateMachine framework with a vPC orchestrator.
- Integrates RestSend for battle-tested HTTP handling with retry logic.
- Handles VPC API quirks via custom orchestrator action handlers.
options:
    state:
        choices:
        - merged
        - replaced
        - deleted
        - overridden
        - gathered
        default: merged
        description:
        - The state of the vPC pair configuration after module completion.
        - C(gathered) is the query/read-only mode for this module.
        type: str
    fabric_name:
        description:
        - Name of the fabric.
        required: true
        type: str
    deploy:
        description:
        - Deploy configuration changes after applying them.
        - Saves fabric configuration and triggers deployment.
        type: bool
        default: false
    dry_run:
        description:
        - Show what changes would be made without executing them.
        - Maps to Ansible check_mode internally.
        type: bool
        default: false
    force:
        description:
        - Force deletion without pre-deletion validation checks.
        - 'WARNING: Bypasses safety checks for networks, VRFs, and vPC interfaces.'
        - Use only when validation API timeouts or you are certain deletion is safe.
        - Only applies to deleted state.
        type: bool
        default: false
    api_timeout:
        description:
        - API request timeout in seconds for primary operations (create, update, delete).
        - Increase for large fabrics or slow networks.
        type: int
        default: 30
    query_timeout:
        description:
        - API request timeout in seconds for query and recommendation operations.
        - Lower timeout for non-critical queries to avoid port exhaustion.
        type: int
        default: 10
    config:
        description:
        - List of vPC pair configuration dictionaries.
        type: list
        elements: dict
        suboptions:
            peer1_switch_id:
                description:
                - Peer1 switch serial number for the vPC pair.
                required: true
                type: str
            peer2_switch_id:
                description:
                - Peer2 switch serial number for the vPC pair.
                required: true
                type: str
            use_virtual_peer_link:
                description:
                - Enable virtual peer link for the vPC pair.
                type: bool
                default: true
notes:
    - This module uses NDStateMachine framework for state management
    - RestSend provides protocol-based HTTP abstraction with automatic retry logic
    - Results are aggregated using the Results class for consistent output format
    - Check mode is fully supported via both framework and RestSend
"""

EXAMPLES = """
# Create a new vPC pair
- name: Create vPC pair
  cisco.nd.nd_vpc_pair:
    fabric_name: myFabric
    state: merged
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"
        use_virtual_peer_link: true

# Delete a vPC pair
- name: Delete vPC pair
  cisco.nd.nd_vpc_pair:
    fabric_name: myFabric
    state: deleted
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"

# Gather existing vPC pairs
- name: Gather all vPC pairs
  cisco.nd.nd_vpc_pair:
    fabric_name: myFabric
    state: gathered

# Create and deploy
- name: Create vPC pair and deploy
  cisco.nd.nd_vpc_pair:
    fabric_name: myFabric
    state: merged
    deploy: true
    config:
      - peer1_switch_id: "FDO23040Q85"
        peer2_switch_id: "FDO23040Q86"

# Dry run to see what would change
- name: Dry run vPC pair creation
  cisco.nd.nd_vpc_pair:
    fabric_name: myFabric
    state: merged
    dry_run: true
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
before:
    description: vPC pair state before changes
    type: list
    returned: always
    sample: [{"switchId": "FDO123", "peerSwitchId": "FDO456", "useVirtualPeerLink": false}]
after:
    description: vPC pair state after changes
    type: list
    returned: always
    sample: [{"switchId": "FDO123", "peerSwitchId": "FDO456", "useVirtualPeerLink": true}]
gathered:
    description: Current vPC pairs (gathered state only)
    type: dict
    returned: when state is gathered
    contains:
        vpc_pairs:
            description: List of configured VPC pairs
            type: list
        pending_create_vpc_pairs:
            description: VPC pairs ready to be created (switches are paired but VPC not configured)
            type: list
        pending_delete_vpc_pairs:
            description: VPC pairs in transitional delete state
            type: list
    sample:
        vpc_pairs: [{"switchId": "FDO123", "peerSwitchId": "FDO456"}]
        pending_create_vpc_pairs: []
        pending_delete_vpc_pairs: []
response:
    description: List of all API responses
    type: list
    returned: always
    sample: [{"RETURN_CODE": 200, "METHOD": "PUT", "MESSAGE": "Success"}]
result:
    description: List of all operation results
    type: list
    returned: always
    sample: [{"success": true, "changed": true}]
diff:
    description: List of all changes made, organized by operation
    type: list
    returned: always
    contains:
        operation:
            description: Type of operation (POST/PUT/DELETE)
            type: str
        vpc_pair_key:
            description: Identifier for the VPC pair (switchId-peerSwitchId)
            type: str
        path:
            description: API endpoint path used
            type: str
        payload:
            description: Request payload sent to API
            type: dict
    sample: [{"operation": "PUT", "vpc_pair_key": "FDO123-FDO456", "path": "/api/v1/...", "payload": {}}]
metadata:
    description: Operation metadata with sequence and identifiers
    type: dict
    returned: when operations are performed
    contains:
        vpc_pair_key:
            description: VPC pair identifier
            type: str
        operation:
            description: Operation type (create/update/delete)
            type: str
        sequence_number:
            description: Operation sequence in batch
            type: int
    sample: {"vpc_pair_key": "FDO123-FDO456", "operation": "create", "sequence_number": 1}
warnings:
    description: List of warning messages from validation or operations
    type: list
    returned: when warnings occur
    sample: ["VPC pair has 2 vPC interfaces - deletion may require manual cleanup"]
failed:
    description: Whether any operation failed
    type: bool
    returned: when operations fail
    sample: false
ip_to_sn_mapping:
    description: Mapping of switch IP addresses to serial numbers
    type: dict
    returned: when available from fabric inventory
    sample: {"10.1.1.1": "FDO123", "10.1.1.2": "FDO456"}
deployment:
    description: Deployment operation results (when deploy=true)
    type: dict
    returned: when deploy parameter is true
    contains:
        deployment_needed:
            description: Whether deployment was needed based on changes
            type: bool
        changed:
            description: Whether deployment made changes
            type: bool
        response:
            description: List of deployment API responses (save and deploy)
            type: list
    sample: {"deployment_needed": true, "changed": true, "response": [...]}
deployment_needed:
    description: Flag indicating if deployment was needed
    type: bool
    returned: when deploy=true
    sample: true
pending_create_pairs_not_in_delete:
    description: VPC pairs in pending create state not included in delete wants (deleted state only)
    type: list
    returned: when state is deleted and pending create pairs exist
    sample: [{"switchId": "FDO789", "peerSwitchId": "FDO012"}]
pending_delete_pairs_not_in_delete:
    description: VPC pairs in pending delete state not included in delete wants (deleted state only)
    type: list
    returned: when state is deleted and pending delete pairs exist
    sample: []
"""

import json
import logging
import sys
import traceback
from typing import Any, ClassVar, Dict, List, Literal, Optional, Union

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging

# Service layer imports
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage_vpc_pair.vpc_pair_resources import (
    VpcPairResourceService,
    VpcPairResourceError,
)

# Static imports so Ansible's AnsiballZ packager includes these files in the
# module zip. Keep them optional when framework files are intentionally absent.
try:
    from ansible_collections.cisco.nd.plugins.module_utils import nd_config_collection as _nd_config_collection  # noqa: F401
    from ansible_collections.cisco.nd.plugins.module_utils import utils as _nd_utils  # noqa: F401
except Exception:  # pragma: no cover - compatibility for stripped framework trees
    _nd_config_collection = None  # noqa: F841
    _nd_utils = None  # noqa: F841

try:
    # pre-PR172 layout
    from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDNestedModel
except Exception:
    try:
        # PR172 layout
        from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
    except Exception:
        from pydantic import BaseModel as NDNestedModel

# Enum imports
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage_vpc_pair.enums import (
    ComponentTypeSupportEnum,
    VpcActionEnum,
    VpcFieldNames,
)

try:
    from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage_vpc_pair.vpc_pair_endpoints import (
        EpVpcPairConsistencyGet,
        EpVpcPairGet,
        EpVpcPairPut,
        EpVpcPairOverviewGet,
        EpVpcPairRecommendationGet,
        EpVpcPairSupportGet,
        EpVpcPairsListGet,
        VpcPairBasePath,
    )
except Exception:
    from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage_vpc_pair import (
        EpVpcPairConsistencyGet,
        EpVpcPairGet,
        EpVpcPairPut,
        EpVpcPairOverviewGet,
        EpVpcPairRecommendationGet,
        EpVpcPairSupportGet,
        EpVpcPairsListGet,
        VpcPairBasePath,
    )
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    CompositeQueryParams,
    EndpointQueryParams,
)

# RestSend imports 
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule as NDModuleV2,
    NDModuleError,
)
try:
    from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
except Exception:
    from ansible_collections.cisco.nd.plugins.module_utils.results import Results

# Pydantic imports
from pydantic import Field, field_validator, model_validator

# VPC Pair schema imports (for vpc_pair_details support)
try:
    from ansible_collections.cisco.nd.plugins.models.model_playbook_vpc_pair import (
        VpcPairDetailsDefault,
        VpcPairDetailsCustom,
    )
except Exception:
    from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage_vpc_pair.vpc_pair_schemas import (
        VpcPairDetailsDefault,
        VpcPairDetailsCustom,
    )

# DeepDiff for intelligent change detection
try:
    from deepdiff import DeepDiff
    HAS_DEEPDIFF = True
    DEEPDIFF_IMPORT_ERROR = None
except ImportError:
    HAS_DEEPDIFF = False
    DEEPDIFF_IMPORT_ERROR = traceback.format_exc()


def _collection_to_list_flex(collection) -> List[Dict[str, Any]]:
    """
    Serialize NDConfigCollection across old/new framework variants.
    """
    if collection is None:
        return []
    if hasattr(collection, "to_list"):
        return collection.to_list()
    if hasattr(collection, "to_payload_list"):
        return collection.to_payload_list()
    if hasattr(collection, "to_ansible_config"):
        return collection.to_ansible_config()
    return []


def _raise_vpc_error(msg: str, **details: Any) -> None:
    """Raise a structured vpc_pair error for main() to format via fail_json."""
    raise VpcPairResourceError(msg=msg, **details)


# ===== API Endpoints =====


class _ComponentTypeQueryParams(EndpointQueryParams):
    """Query params for endpoints that require componentType."""

    component_type: Optional[str] = None


class _ForceShowRunQueryParams(EndpointQueryParams):
    """Query params for deploy endpoint."""

    force_show_run: Optional[bool] = None


class VpcPairEndpoints:
    """
    Centralized API endpoint path management for VPC pair operations.

    All API endpoint paths are defined here to:
    - Eliminate scattered path definitions
    - Make API evolution easier
    - Enable easy endpoint discovery
    - Support multiple API versions

    Usage:
        # Get a path with parameters
        path = VpcPairEndpoints.vpc_pair_put(fabric_name="myFabric", switch_id="FDO123")
        # Returns: "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/vpcpair/fabrics/myFabric/switches/FDO123"
    """

    # Base paths
    NDFC_BASE = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest"
    MANAGE_BASE = "/api/v1/manage"

    # Path templates for VPC pair operations (NDFC API)
    VPC_PAIR_BASE = f"{NDFC_BASE}/vpcpair/fabrics/{{fabric_name}}"
    VPC_PAIR_SWITCH = f"{NDFC_BASE}/vpcpair/fabrics/{{fabric_name}}/switches/{{switch_id}}"

    # Path templates for fabric operations (Manage API - for config save/deploy actions)
    FABRIC_CONFIG_SAVE = f"{MANAGE_BASE}/fabrics/{{fabric_name}}/actions/configSave"
    FABRIC_CONFIG_DEPLOY = f"{MANAGE_BASE}/fabrics/{{fabric_name}}/actions/deploy"

    # Path templates for switch/inventory operations (Manage API)
    FABRIC_SWITCHES = f"{MANAGE_BASE}/fabrics/{{fabric_name}}/switches"
    SWITCH_VPC_PAIR = f"{MANAGE_BASE}/fabrics/{{fabric_name}}/switches/{{switch_id}}/vpcPair"
    SWITCH_VPC_RECOMMENDATIONS = f"{MANAGE_BASE}/fabrics/{{fabric_name}}/switches/{{switch_id}}/vpcPairRecommendations"
    SWITCH_VPC_OVERVIEW = f"{MANAGE_BASE}/fabrics/{{fabric_name}}/switches/{{switch_id}}/vpcPairOverview"

    @staticmethod
    def _append_query(path: str, *query_groups: EndpointQueryParams) -> str:
        """Compose query params using shared query param utilities."""
        composite_params = CompositeQueryParams()
        for query_group in query_groups:
            composite_params.add(query_group)
        query_string = composite_params.to_query_string(url_encode=False)
        return f"{path}?{query_string}" if query_string else path

    @staticmethod
    def vpc_pair_base(fabric_name: str) -> str:
        """
        Get base path for VPC pair operations.

        Args:
            fabric_name: Fabric name

        Returns:
            Base VPC pairs list path

        Example:
            >>> VpcPairEndpoints.vpc_pair_base("myFabric")
            '/api/v1/manage/fabrics/myFabric/vpcPairs'
        """
        endpoint = EpVpcPairsListGet(fabric_name=fabric_name)
        return endpoint.path

    @staticmethod
    def vpc_pairs_list(fabric_name: str) -> str:
        """
        Get path for querying VPC pairs list in a fabric.

        Args:
            fabric_name: Fabric name

        Returns:
            VPC pairs list path
        """
        endpoint = EpVpcPairsListGet(fabric_name=fabric_name)
        return endpoint.path

    @staticmethod
    def vpc_pair_put(fabric_name: str, switch_id: str) -> str:
        """
        Get path for VPC pair PUT operations (create/update/delete).

        Args:
            fabric_name: Fabric name
            switch_id: Switch serial number

        Returns:
            VPC pair PUT path

        Example:
            >>> VpcPairEndpoints.vpc_pair_put("myFabric", "FDO123")
            '/api/v1/manage/fabrics/myFabric/switches/FDO123/vpcPair'
        """
        endpoint = EpVpcPairPut(fabric_name=fabric_name, switch_id=switch_id)
        return endpoint.path

    @staticmethod
    def fabric_switches(fabric_name: str) -> str:
        """
        Get path for querying fabric switch inventory.

        Args:
            fabric_name: Fabric name

        Returns:
            Fabric switches path

        Example:
            >>> VpcPairEndpoints.fabric_switches("myFabric")
            '/api/v1/manage/fabrics/myFabric/switches'
        """
        return VpcPairBasePath.fabrics(fabric_name, "switches")

    @staticmethod
    def switch_vpc_pair(fabric_name: str, switch_id: str) -> str:
        """
        Get path for querying specific switch VPC pair.

        Args:
            fabric_name: Fabric name
            switch_id: Switch serial number

        Returns:
            Switch VPC pair path

        Example:
            >>> VpcPairEndpoints.switch_vpc_pair("myFabric", "FDO123")
            '/api/v1/manage/fabrics/myFabric/switches/FDO123/vpcPair'
        """
        endpoint = EpVpcPairGet(fabric_name=fabric_name, switch_id=switch_id)
        return endpoint.path

    @staticmethod
    def switch_vpc_recommendations(fabric_name: str, switch_id: str) -> str:
        """
        Get path for querying VPC pair recommendations for a switch.

        Args:
            fabric_name: Fabric name
            switch_id: Switch serial number

        Returns:
            VPC recommendations path

        Example:
            >>> VpcPairEndpoints.switch_vpc_recommendations("myFabric", "FDO123")
            '/api/v1/manage/fabrics/myFabric/switches/FDO123/vpcPairRecommendations'
        """
        endpoint = EpVpcPairRecommendationGet(fabric_name=fabric_name, switch_id=switch_id)
        return endpoint.path

    @staticmethod
    def switch_vpc_overview(fabric_name: str, switch_id: str, component_type: str = "full") -> str:
        """
        Get path for querying VPC pair overview (for pre-deletion validation).

        Args:
            fabric_name: Fabric name
            switch_id: Switch serial number
            component_type: Component type ("full" or "minimal"), default "full"

        Returns:
            VPC overview path with query parameters

        Example:
            >>> VpcPairEndpoints.switch_vpc_overview("myFabric", "FDO123")
            '/api/v1/manage/fabrics/myFabric/switches/FDO123/vpcPairOverview?componentType=full'
        """
        endpoint = EpVpcPairOverviewGet(fabric_name=fabric_name, switch_id=switch_id)
        base_path = endpoint.path
        query_params = _ComponentTypeQueryParams(component_type=component_type)
        return VpcPairEndpoints._append_query(base_path, query_params)

    @staticmethod
    def switch_vpc_support(
        fabric_name: str,
        switch_id: str,
        component_type: str = ComponentTypeSupportEnum.CHECK_PAIRING.value,
    ) -> str:
        """
        Get path for querying VPC pair support details.

        Args:
            fabric_name: Fabric name
            switch_id: Switch serial number
            component_type: Support check type

        Returns:
            VPC support path with query parameters
        """
        endpoint = EpVpcPairSupportGet(
            fabric_name=fabric_name,
            switch_id=switch_id,
            component_type=component_type,
        )
        base_path = endpoint.path
        query_params = _ComponentTypeQueryParams(component_type=component_type)
        return VpcPairEndpoints._append_query(base_path, query_params)

    @staticmethod
    def switch_vpc_consistency(fabric_name: str, switch_id: str) -> str:
        """
        Get path for querying VPC pair consistency details.

        Args:
            fabric_name: Fabric name
            switch_id: Switch serial number

        Returns:
            VPC consistency path
        """
        endpoint = EpVpcPairConsistencyGet(fabric_name=fabric_name, switch_id=switch_id)
        return endpoint.path

    @staticmethod
    def fabric_config_save(fabric_name: str) -> str:
        """
        Get path for saving fabric configuration.

        Args:
            fabric_name: Fabric name

        Returns:
            Fabric config save path

        Example:
            >>> VpcPairEndpoints.fabric_config_save("myFabric")
            '/api/v1/manage/fabrics/myFabric/actions/configSave'
        """
        return VpcPairBasePath.fabrics(fabric_name, "actions", "configSave")

    @staticmethod
    def fabric_config_deploy(fabric_name: str, force_show_run: bool = True) -> str:
        """
        Get path for deploying fabric configuration.

        Args:
            fabric_name: Fabric name
            force_show_run: Include forceShowRun query parameter, default True

        Returns:
            Fabric config deploy path with query parameters

        Example:
            >>> VpcPairEndpoints.fabric_config_deploy("myFabric")
            '/api/v1/manage/fabrics/myFabric/actions/deploy?forceShowRun=true'
        """
        base_path = VpcPairBasePath.fabrics(fabric_name, "actions", "deploy")
        query_params = _ForceShowRunQueryParams(
            force_show_run=True if force_show_run else None
        )
        return VpcPairEndpoints._append_query(base_path, query_params)


# ===== VPC Pair Model =====


class VpcPairModel(NDNestedModel):
    """
    Pydantic model for VPC pair configuration specific to nd_vpc_pair module.

    Uses composite identifier: (switch_id, peer_switch_id)

    Note: This model is separate from VpcPairBase in model_playbook_vpc_pair.py because:
    1. Different base class: NDNestedModel (module-specific) vs NDVpcPairBaseModel (API-generic)
    2. Different defaults: use_virtual_peer_link=True (module default) vs False (API default)
    3. Different type coercion: bool (strict) vs FlexibleBool (flexible API input)
    4. Module-specific validation and error messages tailored to Ansible user experience

    These models serve different purposes:
    - VpcPairModel: Ansible module input validation and framework integration
    - VpcPairBase: Generic API schema for broader vpc_pair functionality

    DO NOT consolidate without ensuring all tests pass and defaults match module documentation.
    """

    # Identifier configuration
    identifiers: ClassVar[List[str]] = ["switch_id", "peer_switch_id"]
    identifier_strategy: ClassVar[Literal["composite"]] = "composite"

    # Fields (Ansible names -> API aliases)
    switch_id: str = Field(
        alias=VpcFieldNames.SWITCH_ID,
        description="Peer-1 switch serial number",
        min_length=3,
        max_length=64
    )
    peer_switch_id: str = Field(
        alias=VpcFieldNames.PEER_SWITCH_ID,
        description="Peer-2 switch serial number",
        min_length=3,
        max_length=64
    )
    use_virtual_peer_link: bool = Field(
        default=True,
        alias=VpcFieldNames.USE_VIRTUAL_PEER_LINK,
        description="Virtual peer link enabled"
    )
    vpc_pair_details: Optional[Union[VpcPairDetailsDefault, VpcPairDetailsCustom]] = Field(
        default=None,
        discriminator="type",
        alias=VpcFieldNames.VPC_PAIR_DETAILS,
        description="VPC pair configuration details (default or custom template)"
    )

    @field_validator("switch_id", "peer_switch_id")
    @classmethod
    def validate_switch_id_format(cls, v: str) -> str:
        """
        Validate switch ID is not empty or whitespace.

        Args:
            v: Switch ID value

        Returns:
            Stripped switch ID

        Raises:
            ValueError: If switch ID is empty or whitespace
        """
        if not v or not v.strip():
            raise ValueError("Switch ID cannot be empty or whitespace")
        return v.strip()

    @model_validator(mode="after")
    def validate_different_switches(self) -> "VpcPairModel":
        """
        Ensure switch_id and peer_switch_id are different.

        Returns:
            Validated model instance

        Raises:
            ValueError: If switch_id equals peer_switch_id
        """
        if self.switch_id == self.peer_switch_id:
            raise ValueError(
                f"switch_id and peer_switch_id must be different: {self.switch_id}"
            )
        return self

    def to_payload(self) -> Dict[str, Any]:
        """
        Convert to API payload format.

        Note: vpcAction is added by custom functions, not here.
        """
        return self.model_dump(by_alias=True, exclude_none=True)

    def get_identifier_value(self):
        """
        Return a stable composite identifier for VPC pair operations.

        Sort switch IDs to treat (A,B) and (B,A) as the same logical pair.
        """
        return tuple(sorted([self.switch_id, self.peer_switch_id]))

    def to_config(self, **kwargs) -> Dict[str, Any]:
        """
        Convert to Ansible config shape with snake_case field names.
        """
        return self.model_dump(by_alias=False, exclude_none=True, **kwargs)

    @classmethod
    def from_response(cls, response: Dict[str, Any]) -> "VpcPairModel":
        """
        Parse VPC pair from API response.

        Handles API field name variations.
        """
        data = {
            VpcFieldNames.SWITCH_ID: response.get(VpcFieldNames.SWITCH_ID),
            VpcFieldNames.PEER_SWITCH_ID: response.get(VpcFieldNames.PEER_SWITCH_ID),
            VpcFieldNames.USE_VIRTUAL_PEER_LINK: response.get(
                VpcFieldNames.USE_VIRTUAL_PEER_LINK, True
            ),
        }
        return cls.model_validate(data)


# ===== Helper Functions =====


def _is_update_needed(want: Dict[str, Any], have: Dict[str, Any]) -> bool:
    """
    Determine if an update is needed by comparing want and have using DeepDiff.

    Uses DeepDiff for intelligent comparison that handles:
    - Field additions
    - Value changes
    - Nested structure changes
    - Ignores field order

    Falls back to simple comparison if DeepDiff is unavailable.

    Args:
        want: Desired VPC pair configuration (dict)
        have: Current VPC pair configuration (dict)

    Returns:
        bool: True if update is needed, False if already in desired state

    Example:
        >>> want = {"switchId": "FDO123", "useVirtualPeerLink": True}
        >>> have = {"switchId": "FDO123", "useVirtualPeerLink": False}
        >>> _is_update_needed(want, have)
        True
    """
    if not HAS_DEEPDIFF:
        # Fallback to simple comparison
        return want != have

    try:
        # Use DeepDiff for intelligent comparison
        diff = DeepDiff(have, want, ignore_order=True)
        return bool(diff)
    except Exception:
        # Fallback to simple comparison if DeepDiff fails
        return want != have


def _get_template_config(vpc_pair_model) -> Optional[Dict[str, Any]]:
    """
    Extract template configuration from VPC pair model if present.

    Supports both default and custom template types:
    - default: Standard parameters (domainId, keepAliveVrf, etc.)
    - custom: User-defined template with custom fields

    Args:
        vpc_pair_model: VpcPairModel instance

    Returns:
        dict: Template configuration or None if not provided

    Example:
        # For default template:
        config = _get_template_config(model)
        # Returns: {"type": "default", "domainId": 100, ...}

        # For custom template:
        config = _get_template_config(model)
        # Returns: {"type": "custom", "templateName": "my_template", ...}
    """
    # Check if model has vpc_pair_details
    if not hasattr(vpc_pair_model, "vpc_pair_details"):
        return None

    vpc_pair_details = vpc_pair_model.vpc_pair_details
    if not vpc_pair_details:
        return None

    # Return the validated Pydantic model as dict
    return vpc_pair_details.model_dump(by_alias=True, exclude_none=True)


def _build_vpc_pair_payload(vpc_pair_model) -> Dict[str, Any]:
    """
    Build the 4.2 API payload for pairing a VPC.

    Constructs payload according to OpenAPI spec with vpcAction
    discriminator and optional template details.

    Args:
        vpc_pair_model: VpcPairModel instance with configuration

    Returns:
        dict: Complete payload for PUT request in 4.2 format

    Example:
        payload = _build_vpc_pair_payload(vpc_pair_model)
        # Returns:
        # {
        #     "vpcAction": "pair",
        #     "switchId": "FDO123",
        #     "peerSwitchId": "FDO456",
        #     "useVirtualPeerLink": True,
        #     "vpcPairDetails": {...}  # Optional
        # }
    """
    # Handle both dict and model object inputs
    if isinstance(vpc_pair_model, dict):
        switch_id = vpc_pair_model.get(VpcFieldNames.SWITCH_ID)
        peer_switch_id = vpc_pair_model.get(VpcFieldNames.PEER_SWITCH_ID)
        use_virtual_peer_link = vpc_pair_model.get(VpcFieldNames.USE_VIRTUAL_PEER_LINK, True)
    else:
        switch_id = vpc_pair_model.switch_id
        peer_switch_id = vpc_pair_model.peer_switch_id
        use_virtual_peer_link = vpc_pair_model.use_virtual_peer_link

    # Base payload with vpcAction discriminator
    payload = {
        VpcFieldNames.VPC_ACTION: VpcActionEnum.PAIR.value,
        VpcFieldNames.SWITCH_ID: switch_id,
        VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
        VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_virtual_peer_link,
    }

    # Add template configuration if provided (only for model objects)
    if not isinstance(vpc_pair_model, dict):
        template_config = _get_template_config(vpc_pair_model)
        if template_config:
            payload[VpcFieldNames.VPC_PAIR_DETAILS] = template_config

    return payload


# API field compatibility mapping
# ND API versions use inconsistent field names - this mapping provides a canonical interface
API_FIELD_ALIASES = {
    # Primary field name -> list of alternative field names to check
    "useVirtualPeerLink": ["useVirtualPeerlink"],  # ND 4.2+ uses camelCase "Link", older versions use lowercase "link"
    "serialNumber": ["serial_number", "serialNo"],  # Alternative serial number field names
}


def _get_api_field_value(api_response: Dict, field_name: str, default=None):
    """
    Get field value from API response handling inconsistent field naming across ND API versions.

    Different ND API versions use inconsistent field names (useVirtualPeerLink vs useVirtualPeerlink).
    This function checks the primary field name and all known aliases.

    Args:
        api_response: API response dictionary
        field_name: Primary field name to retrieve
        default: Default value if field not found

    Returns:
        Field value or default if not found

    Example:
        >>> recommendation = {"useVirtualPeerlink": True}  # Old API format
        >>> _get_api_field_value(recommendation, "useVirtualPeerLink", False)
        True  # Found via alias mapping

        >>> recommendation = {"useVirtualPeerLink": True}  # New API format
        >>> _get_api_field_value(recommendation, "useVirtualPeerLink", False)
        True  # Found via primary field name
    """
    if not isinstance(api_response, dict):
        return default

    # Check primary field name first
    if field_name in api_response:
        return api_response[field_name]

    # Check aliases
    aliases = API_FIELD_ALIASES.get(field_name, [])
    for alias in aliases:
        if alias in api_response:
            return api_response[alias]

    return default


def _get_recommendation_details(nd_v2, fabric_name: str, switch_id: str, timeout: Optional[int] = None) -> Optional[Dict]:
    """
    Get VPC pair recommendation details from ND for a specific switch.

    Returns peer switch info and useVirtualPeerLink status.

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name
        switch_id: Switch serial number
        timeout: Optional timeout override (uses module param if not specified)

    Returns:
        Dict with peer info or None if not found (404)

    Raises:
        NDModuleError: On API errors other than 404 (timeouts, 500s, etc.)
    """
    # Validate inputs to prevent injection
    if not fabric_name or not isinstance(fabric_name, str):
        raise ValueError(f"Invalid fabric_name: {fabric_name}")
    if not switch_id or not isinstance(switch_id, str) or len(switch_id) < 3:
        raise ValueError(f"Invalid switch_id: {switch_id}")

    try:
        path = VpcPairEndpoints.switch_vpc_recommendations(fabric_name, switch_id)

        # Use query timeout from module params or override
        if timeout is None:
            timeout = nd_v2.module.params.get("query_timeout", 10)

        rest_send = nd_v2._get_rest_send()
        rest_send.save_settings()
        rest_send.timeout = timeout
        try:
            vpc_recommendations = nd_v2.request(path, HttpVerbEnum.GET)
        finally:
            rest_send.restore_settings()

        if vpc_recommendations is None or vpc_recommendations == {}:
            return None

        # Validate response structure and look for current peer
        if isinstance(vpc_recommendations, list):
            for sw in vpc_recommendations:
                # Validate each entry
                if not isinstance(sw, dict):
                    nd_v2.module.warn(
                        f"Skipping invalid recommendation entry for switch {switch_id}: "
                        f"expected dict, got {type(sw).__name__}"
                    )
                    continue

                # Check for current peer indicators
                if sw.get(VpcFieldNames.CURRENT_PEER) or sw.get(VpcFieldNames.IS_CURRENT_PEER):
                    # Validate required fields exist
                    if VpcFieldNames.SERIAL_NUMBER not in sw:
                        nd_v2.module.warn(
                            f"Recommendation missing serialNumber field for switch {switch_id}"
                        )
                        continue
                    return sw
        elif vpc_recommendations:
            # Unexpected response format
            nd_v2.module.warn(
                f"Unexpected recommendation response format for switch {switch_id}: "
                f"expected list, got {type(vpc_recommendations).__name__}"
            )

        return None
    except NDModuleError as error:
        # Handle expected error codes gracefully
        if error.status == 404:
            # No recommendations exist (expected for switches without VPC)
            return None
        elif error.status == 500:
            # Server error - recommendation API may be unstable
            # Treat as "no recommendations available" to allow graceful degradation
            nd_v2.module.warn(
                f"VPC recommendation API returned 500 error for switch {switch_id} - "
                f"treating as no recommendations available"
            )
            return None
        # Let other errors (timeouts, rate limits) propagate
        raise


def _extract_vpc_pairs_from_list_response(vpc_pairs_response: Any) -> List[Dict[str, Any]]:
    """
    Extract VPC pair list entries from /vpcPairs response payload.

    Supports common response wrappers used by ND API.
    """
    if not isinstance(vpc_pairs_response, dict):
        return []

    candidates = None
    for key in (VpcFieldNames.VPC_PAIRS, "items", VpcFieldNames.DATA):
        value = vpc_pairs_response.get(key)
        if isinstance(value, list):
            candidates = value
            break

    if not isinstance(candidates, list):
        return []

    extracted_pairs = []
    for item in candidates:
        if not isinstance(item, dict):
            continue

        switch_id = item.get(VpcFieldNames.SWITCH_ID)
        peer_switch_id = item.get(VpcFieldNames.PEER_SWITCH_ID)

        # Handle alternate response shape if switch IDs are nested under "switch"/"peerSwitch"
        if isinstance(switch_id, dict) and isinstance(peer_switch_id, dict):
            switch_id = switch_id.get("switch")
            peer_switch_id = peer_switch_id.get("peerSwitch")

        if not switch_id or not peer_switch_id:
            continue

        extracted_pairs.append(
            {
                VpcFieldNames.SWITCH_ID: switch_id,
                VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
                VpcFieldNames.USE_VIRTUAL_PEER_LINK: item.get(
                    VpcFieldNames.USE_VIRTUAL_PEER_LINK, True
                ),
            }
        )

    return extracted_pairs


def _get_pairing_support_details(
    nd_v2,
    fabric_name: str,
    switch_id: str,
    component_type: str = ComponentTypeSupportEnum.CHECK_PAIRING.value,
    timeout: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """
    Query /vpcPairSupport endpoint to validate pairing support.
    """
    if not fabric_name or not isinstance(fabric_name, str):
        raise ValueError(f"Invalid fabric_name: {fabric_name}")
    if not switch_id or not isinstance(switch_id, str) or len(switch_id) < 3:
        raise ValueError(f"Invalid switch_id: {switch_id}")

    path = VpcPairEndpoints.switch_vpc_support(
        fabric_name=fabric_name,
        switch_id=switch_id,
        component_type=component_type,
    )

    if timeout is None:
        timeout = nd_v2.module.params.get("query_timeout", 10)

    rest_send = nd_v2._get_rest_send()
    rest_send.save_settings()
    rest_send.timeout = timeout
    try:
        support_details = nd_v2.request(path, HttpVerbEnum.GET)
    finally:
        rest_send.restore_settings()

    if isinstance(support_details, dict):
        return support_details
    return None


def _validate_fabric_peering_support(
    nrm,
    nd_v2,
    fabric_name: str,
    switch_id: str,
    peer_switch_id: str,
    use_virtual_peer_link: bool,
) -> None:
    """
    Validate fabric peering support when virtual peer link is requested.

    If API explicitly reports unsupported fabric peering, logs warning and
    continues. If support API is unavailable, logs warning and continues.
    """
    if not use_virtual_peer_link:
        return

    switches_to_check = [switch_id, peer_switch_id]
    for support_switch_id in switches_to_check:
        if not support_switch_id:
            continue

        try:
            support_details = _get_pairing_support_details(
                nd_v2,
                fabric_name=fabric_name,
                switch_id=support_switch_id,
                component_type=ComponentTypeSupportEnum.CHECK_FABRIC_PEERING_SUPPORT.value,
            )
            if not support_details:
                continue

            is_supported = _get_api_field_value(
                support_details, "isVpcFabricPeeringSupported", None
            )
            if is_supported is False:
                status = _get_api_field_value(
                    support_details, "status", "Fabric peering not supported"
                )
                nrm.module.warn(
                    f"VPC fabric peering is not supported for switch {support_switch_id}: {status}. "
                    f"Continuing, but config save/deploy may report a platform limitation. "
                    f"Consider setting use_virtual_peer_link=false for this platform."
                )
        except Exception as support_error:
            nrm.module.warn(
                f"Fabric peering support check failed for switch {support_switch_id}: "
                f"{str(support_error).splitlines()[0]}. Continuing with create/update operation."
            )


def _get_consistency_details(
    nd_v2,
    fabric_name: str,
    switch_id: str,
    timeout: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """
    Query /vpcPairConsistency endpoint for consistency diagnostics.
    """
    if not fabric_name or not isinstance(fabric_name, str):
        raise ValueError(f"Invalid fabric_name: {fabric_name}")
    if not switch_id or not isinstance(switch_id, str) or len(switch_id) < 3:
        raise ValueError(f"Invalid switch_id: {switch_id}")

    path = VpcPairEndpoints.switch_vpc_consistency(fabric_name, switch_id)

    if timeout is None:
        timeout = nd_v2.module.params.get("query_timeout", 10)

    rest_send = nd_v2._get_rest_send()
    rest_send.save_settings()
    rest_send.timeout = timeout
    try:
        consistency_details = nd_v2.request(path, HttpVerbEnum.GET)
    finally:
        rest_send.restore_settings()

    if isinstance(consistency_details, dict):
        return consistency_details
    return None


def _is_switch_in_vpc_pair(
    nd_v2,
    fabric_name: str,
    switch_id: str,
    timeout: Optional[int] = None,
) -> Optional[bool]:
    """
    Best-effort active-membership check via vPC overview endpoint.

    Returns:
      - True: overview query succeeded (switch is part of a vPC pair)
      - False: API explicitly reports switch is not in a vPC pair
      - None: unknown/error (do not block caller logic)
    """
    if not fabric_name or not switch_id:
        return None

    path = VpcPairEndpoints.switch_vpc_overview(
        fabric_name, switch_id, component_type="full"
    )

    if timeout is None:
        timeout = nd_v2.module.params.get("query_timeout", 10)

    rest_send = nd_v2._get_rest_send()
    rest_send.save_settings()
    rest_send.timeout = timeout
    try:
        nd_v2.request(path, HttpVerbEnum.GET)
        return True
    except NDModuleError as error:
        error_msg = (error.msg or "").lower()
        if error.status == 400 and "not a part of vpc pair" in error_msg:
            return False
        return None
    except Exception:
        return None
    finally:
        rest_send.restore_settings()


def _validate_fabric_switches(nd_v2, fabric_name: str) -> Dict[str, Dict]:
    """
    Query and validate fabric switch inventory.

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name

    Returns:
        Dict mapping switch serial number to switch info

    Raises:
        ValueError: If inputs are invalid
        NDModuleError: If fabric switch query fails
    """
    # Input validation
    if not fabric_name or not isinstance(fabric_name, str):
        raise ValueError(f"Invalid fabric_name: {fabric_name}")

    # Use api_timeout from module params
    timeout = nd_v2.module.params.get("api_timeout", 30)

    rest_send = nd_v2._get_rest_send()
    rest_send.save_settings()
    rest_send.timeout = timeout
    try:
        switches_path = VpcPairEndpoints.fabric_switches(fabric_name)
        switches_response = nd_v2.request(switches_path, HttpVerbEnum.GET)
    finally:
        rest_send.restore_settings()

    if not switches_response:
        return {}

    # Validate response structure
    if not isinstance(switches_response, dict):
        nd_v2.module.warn(
            f"Unexpected switches response format: expected dict, got {type(switches_response).__name__}"
        )
        return {}

    switches = switches_response.get(VpcFieldNames.SWITCHES, [])

    # Validate switches is a list
    if not isinstance(switches, list):
        nd_v2.module.warn(
            f"Unexpected switches format: expected list, got {type(switches).__name__}"
        )
        return {}

    # Build validated switch dictionary
    result = {}
    for sw in switches:
        if not isinstance(sw, dict):
            nd_v2.module.warn(f"Skipping invalid switch entry: expected dict, got {type(sw).__name__}")
            continue

        serial_number = sw.get(VpcFieldNames.SERIAL_NUMBER)
        if not serial_number:
            continue

        # Validate serial number format
        if not isinstance(serial_number, str) or len(serial_number) < 3:
            nd_v2.module.warn(f"Skipping switch with invalid serial number: {serial_number}")
            continue

        result[serial_number] = sw

    return result


def _validate_switch_conflicts(want_configs: List[Dict], have_vpc_pairs: List[Dict], module) -> None:
    """
    Validate that switches in want configs aren't already in different VPC pairs.

    Optimized implementation using index-based lookup for O(n) time complexity instead of O(n²).

    Args:
        want_configs: List of desired VPC pair configs
        have_vpc_pairs: List of existing VPC pairs
        module: AnsibleModule instance for fail_json

    Raises:
        AnsibleModule.fail_json: If switch conflicts detected
    """
    conflicts = []

    # Build index of existing VPC pairs by switch ID - O(m) where m = len(have_vpc_pairs)
    # Maps switch_id -> list of VPC pairs containing that switch
    switch_to_vpc_index = {}
    for have in have_vpc_pairs:
        have_switch_id = have.get(VpcFieldNames.SWITCH_ID)
        have_peer_id = have.get(VpcFieldNames.PEER_SWITCH_ID)

        if have_switch_id:
            if have_switch_id not in switch_to_vpc_index:
                switch_to_vpc_index[have_switch_id] = []
            switch_to_vpc_index[have_switch_id].append(have)

        if have_peer_id:
            if have_peer_id not in switch_to_vpc_index:
                switch_to_vpc_index[have_peer_id] = []
            switch_to_vpc_index[have_peer_id].append(have)

    # Check each want config for conflicts - O(n) where n = len(want_configs)
    for want in want_configs:
        want_switches = {want.get(VpcFieldNames.SWITCH_ID), want.get(VpcFieldNames.PEER_SWITCH_ID)}
        want_switches.discard(None)

        # Build set of all VPC pairs that contain any switch from want_switches - O(1) lookup per switch
        # Use set to track VPC IDs we've already checked to avoid duplicate processing
        conflicting_vpcs = {}  # vpc_id -> vpc dict
        for switch in want_switches:
            if switch in switch_to_vpc_index:
                for vpc in switch_to_vpc_index[switch]:
                    # Use tuple of sorted switch IDs as unique identifier
                    vpc_id = tuple(sorted([vpc.get(VpcFieldNames.SWITCH_ID), vpc.get(VpcFieldNames.PEER_SWITCH_ID)]))
                    # Only add if we haven't seen this VPC ID before (avoids duplicate processing)
                    if vpc_id not in conflicting_vpcs:
                        conflicting_vpcs[vpc_id] = vpc

        # Check each potentially conflicting VPC pair
        for vpc_id, have in conflicting_vpcs.items():
            have_switches = {have.get(VpcFieldNames.SWITCH_ID), have.get(VpcFieldNames.PEER_SWITCH_ID)}
            have_switches.discard(None)

            # Same VPC pair is OK
            if want_switches == have_switches:
                continue

            # Check for switch overlap with different pairs
            switch_overlap = want_switches & have_switches
            if switch_overlap:
                # Filter out None values and ensure strings for joining
                overlap_list = [str(s) for s in switch_overlap if s is not None]
                want_key = f"{want.get(VpcFieldNames.SWITCH_ID)}-{want.get(VpcFieldNames.PEER_SWITCH_ID)}"
                have_key = f"{have.get(VpcFieldNames.SWITCH_ID)}-{have.get(VpcFieldNames.PEER_SWITCH_ID)}"
                conflicts.append(
                    f"Switch(es) {', '.join(overlap_list)} in wanted VPC pair {want_key} "
                    f"are already part of existing VPC pair {have_key}"
                )

    if conflicts:
        _raise_vpc_error(
            msg="Switch conflicts detected. A switch can only be part of one VPC pair at a time.",
            conflicts=conflicts
        )


def _validate_switches_exist_in_fabric(
    nrm,
    fabric_name: str,
    switch_id: str,
    peer_switch_id: str,
) -> None:
    """
    Validate both switches exist in discovered fabric inventory.

    This check is mandatory for create/update. Empty inventory is treated as
    a validation error to avoid bypassing guardrails and failing later with a
    less actionable API error.
    """
    fabric_switches = nrm.module.params.get("_fabric_switches")

    if fabric_switches is None:
        _raise_vpc_error(
            msg=(
                f"Switch validation failed for fabric '{fabric_name}': switch inventory "
                "was not loaded from query_all. Unable to validate requested vPC pair."
            ),
            vpc_pair_key=nrm.current_identifier,
            fabric=fabric_name,
        )

    valid_switches = sorted(list(fabric_switches))
    if not valid_switches:
        _raise_vpc_error(
            msg=(
                f"Switch validation failed for fabric '{fabric_name}': no switches were "
                "discovered in fabric inventory. Cannot create/update vPC pairs without "
                "validated switch membership."
            ),
            vpc_pair_key=nrm.current_identifier,
            fabric=fabric_name,
            total_valid_switches=0,
        )

    missing_switches = []
    if switch_id not in fabric_switches:
        missing_switches.append(switch_id)
    if peer_switch_id not in fabric_switches:
        missing_switches.append(peer_switch_id)

    if not missing_switches:
        return

    max_switches_in_error = 10
    error_msg = (
        f"Switch validation failed: The following switch(es) do not exist in fabric '{fabric_name}':\n"
        f"  Missing switches: {', '.join(missing_switches)}\n"
        f"  Affected vPC pair: {nrm.current_identifier}\n\n"
        "Please ensure:\n"
        "  1. Switch serial numbers are correct (not IP addresses)\n"
        "  2. Switches are discovered and present in the fabric\n"
        "  3. You have the correct fabric name specified\n\n"
    )

    if len(valid_switches) <= max_switches_in_error:
        error_msg += f"Valid switches in fabric: {', '.join(valid_switches)}"
    else:
        error_msg += (
            f"Valid switches in fabric (first {max_switches_in_error}): "
            f"{', '.join(valid_switches[:max_switches_in_error])} ... and "
            f"{len(valid_switches) - max_switches_in_error} more"
        )

    _raise_vpc_error(
        msg=error_msg,
        missing_switches=missing_switches,
        vpc_pair_key=nrm.current_identifier,
        total_valid_switches=len(valid_switches),
    )


def _validate_vpc_pair_deletion(nd_v2, fabric_name: str, switch_id: str, vpc_pair_key: str, module) -> None:
    """
    Validate VPC pair can be safely deleted by checking for dependencies.

    This function prevents data loss by ensuring the VPC pair has no active:
    1. Networks (networkCount must be 0 for all statuses)
    2. VRFs (vrfCount must be 0 for all statuses)
    3. Warns if vPC interfaces exist (vpcInterfaceCount > 0)

    Args:
        nd_v2: NDModuleV2 instance for RestSend
        fabric_name: Fabric name
        switch_id: Switch serial number
        vpc_pair_key: VPC pair identifier (e.g., "FDO123-FDO456") for error messages
        module: AnsibleModule instance for fail_json/warn

    Raises:
        AnsibleModule.fail_json: If VPC pair has active networks or VRFs

    Example:
        _validate_vpc_pair_deletion(nd_v2, "myFabric", "FDO123", "FDO123-FDO456", module)
    """
    try:
        # Query overview endpoint with full component data
        overview_path = VpcPairEndpoints.switch_vpc_overview(fabric_name, switch_id, component_type="full")

        # Bound overview validation call by query_timeout for deterministic behavior.
        rest_send = nd_v2._get_rest_send()
        rest_send.save_settings()
        rest_send.timeout = nd_v2.module.params.get("query_timeout", 10)
        try:
            response = nd_v2.request(overview_path, HttpVerbEnum.GET)
        finally:
            rest_send.restore_settings()

        # If no response, VPC pair doesn't exist - deletion not needed
        if not response:
            module.warn(
                f"VPC pair {vpc_pair_key} not found in overview query. "
                f"It may not exist or may have already been deleted."
            )
            return

        # Query consistency endpoint for additional diagnostics before deletion.
        # This is best effort and should not block deletion workflows.
        try:
            consistency = _get_consistency_details(nd_v2, fabric_name, switch_id)
            if consistency:
                type2_consistency = _get_api_field_value(consistency, "type2Consistency", None)
                if type2_consistency is False:
                    reason = _get_api_field_value(
                        consistency, "type2ConsistencyReason", "unknown reason"
                    )
                    module.warn(
                        f"VPC pair {vpc_pair_key} reports type2 consistency issue: {reason}"
                    )
        except Exception as consistency_error:
            module.warn(
                f"Failed to query consistency details for VPC pair {vpc_pair_key}: "
                f"{str(consistency_error).splitlines()[0]}"
            )

        # Validate response structure
        if not isinstance(response, dict):
            _raise_vpc_error(
                msg=f"Expected dict response from vPC pair overview for {vpc_pair_key}, got {type(response).__name__}",
                response=response
            )

        # Validate overlay data exists
        overlay = response.get(VpcFieldNames.OVERLAY)
        if not overlay:
            _raise_vpc_error(
                msg=(
                    f"vPC pair {vpc_pair_key} might not exist or overlay data unavailable. "
                    f"Cannot safely validate deletion."
                ),
                vpc_pair_key=vpc_pair_key,
                response=response
            )

        # Check 1: Validate no networks are attached
        network_count = overlay.get(VpcFieldNames.NETWORK_COUNT, {})
        if isinstance(network_count, dict):
            for status, count in network_count.items():
                try:
                    count_int = int(count)
                    if count_int != 0:
                        _raise_vpc_error(
                            msg=(
                                f"Cannot delete vPC pair {vpc_pair_key}. "
                                f"{count_int} network(s) with status '{status}' still exist. "
                                f"Remove all networks from this vPC pair before deleting it."
                            ),
                            vpc_pair_key=vpc_pair_key,
                            network_count=network_count,
                            blocking_status=status,
                            blocking_count=count_int
                        )
                except (ValueError, TypeError) as e:
                    # Best effort - log warning and continue
                    module.warn(f"Error parsing network count for status '{status}': {e}")
        elif network_count:
            # Non-dict format - log warning
            module.warn(
                f"networkCount is not a dict for {vpc_pair_key}: {type(network_count).__name__}. "
                f"Skipping network validation."
            )

        # Check 2: Validate no VRFs are attached
        vrf_count = overlay.get(VpcFieldNames.VRF_COUNT, {})
        if isinstance(vrf_count, dict):
            for status, count in vrf_count.items():
                try:
                    count_int = int(count)
                    if count_int != 0:
                        _raise_vpc_error(
                            msg=(
                                f"Cannot delete vPC pair {vpc_pair_key}. "
                                f"{count_int} VRF(s) with status '{status}' still exist. "
                                f"Remove all VRFs from this vPC pair before deleting it."
                            ),
                            vpc_pair_key=vpc_pair_key,
                            vrf_count=vrf_count,
                            blocking_status=status,
                            blocking_count=count_int
                        )
                except (ValueError, TypeError) as e:
                    # Best effort - log warning and continue
                    module.warn(f"Error parsing VRF count for status '{status}': {e}")
        elif vrf_count:
            # Non-dict format - log warning
            module.warn(
                f"vrfCount is not a dict for {vpc_pair_key}: {type(vrf_count).__name__}. "
                f"Skipping VRF validation."
            )

        # Check 3: Warn if vPC interfaces exist (non-blocking)
        inventory = response.get(VpcFieldNames.INVENTORY, {})
        if inventory and isinstance(inventory, dict):
            vpc_interface_count = inventory.get(VpcFieldNames.VPC_INTERFACE_COUNT)
            if vpc_interface_count:
                try:
                    count_int = int(vpc_interface_count)
                    if count_int > 0:
                        module.warn(
                            f"vPC pair {vpc_pair_key} has {count_int} vPC interface(s). "
                            f"Deletion may fail or require manual cleanup of interfaces. "
                            f"Consider removing vPC interfaces before deleting the vPC pair."
                        )
                except (ValueError, TypeError) as e:
                    # Best effort - just log debug message
                    pass
        elif not inventory:
            # No inventory data - warn user
            module.warn(
                f"Inventory data not available in overview response for {vpc_pair_key}. "
                f"Proceeding with deletion, but it may fail if vPC interfaces exist."
            )

    except VpcPairResourceError:
        raise
    except NDModuleError as error:
        error_msg = str(error.msg).lower() if error.msg else ""
        status_code = error.status or 0

        # If the overview query returns 400 with "not a part of" it means
        # the pair no longer exists on the controller.  Signal the caller
        # by raising a ValueError with a sentinel message so that the
        # delete function can treat this as an idempotent no-op.
        if status_code == 400 and "not a part of" in error_msg:
            raise ValueError(
                f"VPC pair {vpc_pair_key} is already unpaired on the controller. "
                f"No deletion required."
            )

        # Best effort validation - if overview query fails, log warning and proceed
        # The API will still reject deletion if dependencies exist
        module.warn(
            f"Could not validate vPC pair {vpc_pair_key} for deletion: {error.msg}. "
            f"Proceeding with deletion attempt. API will reject if dependencies exist."
        )

    except Exception as e:
        # Best effort validation - log warning and continue
        module.warn(
            f"Unexpected error validating VPC pair {vpc_pair_key} for deletion: {str(e)}. "
            f"Proceeding with deletion attempt."
        )


# ===== Custom Action Functions (used by VpcPairResourceService via orchestrator) =====


def _filter_vpc_pairs_by_requested_config(
    pairs: List[Dict[str, Any]],
    config: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Filter queried VPC pairs by explicit pair keys provided in gathered config.

    If gathered config is empty or does not contain complete switch pairs, return
    the unfiltered pair list.
    """
    if not pairs or not config:
        return list(pairs or [])

    requested_pair_keys = set()
    for item in config:
        switch_id = item.get("switch_id") or item.get(VpcFieldNames.SWITCH_ID)
        peer_switch_id = item.get("peer_switch_id") or item.get(VpcFieldNames.PEER_SWITCH_ID)
        if switch_id and peer_switch_id:
            requested_pair_keys.add(tuple(sorted([switch_id, peer_switch_id])))

    if not requested_pair_keys:
        return list(pairs)

    filtered_pairs = []
    for item in pairs:
        switch_id = item.get("switch_id") or item.get(VpcFieldNames.SWITCH_ID)
        peer_switch_id = item.get("peer_switch_id") or item.get(VpcFieldNames.PEER_SWITCH_ID)
        if switch_id and peer_switch_id:
            pair_key = tuple(sorted([switch_id, peer_switch_id]))
            if pair_key in requested_pair_keys:
                filtered_pairs.append(item)

    return filtered_pairs


def custom_vpc_query_all(nrm) -> List[Dict]:
    """
    Query existing VPC pairs with state-aware enrichment.

    Flow:
    - Base query from /vpcPairs list (always attempted first)
    - gathered/deleted: use lightweight list-only data when available
    - merged/replaced/overridden: enrich with switch inventory and recommendation
      APIs to build have/pending_create/pending_delete sets
    """
    fabric_name = nrm.module.params.get("fabric_name")

    if not fabric_name or not isinstance(fabric_name, str) or not fabric_name.strip():
        raise ValueError(f"fabric_name must be a non-empty string. Got: {fabric_name!r}")

    state = nrm.module.params.get("state", "merged")
    if state == "gathered":
        config = nrm.module.params.get("_gather_filter_config") or []
    else:
        config = nrm.module.params.get("config") or []

    # Initialize RestSend via NDModuleV2
    nd_v2 = NDModuleV2(nrm.module)

    def _set_lightweight_context(lightweight_have: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        nrm.module.params["_fabric_switches"] = []
        nrm.module.params["_fabric_switches_count"] = 0
        nrm.module.params["_ip_to_sn_mapping"] = {}
        nrm.module.params["_have"] = lightweight_have
        nrm.module.params["_pending_create"] = []
        nrm.module.params["_pending_delete"] = []
        return lightweight_have

    try:
        # Step 1: Base query from list endpoint (/vpcPairs)
        have = []
        list_query_succeeded = False
        try:
            list_path = VpcPairEndpoints.vpc_pairs_list(fabric_name)
            rest_send = nd_v2._get_rest_send()
            rest_send.save_settings()
            rest_send.timeout = nrm.module.params.get("query_timeout", 10)
            try:
                vpc_pairs_response = nd_v2.request(list_path, HttpVerbEnum.GET)
            finally:
                rest_send.restore_settings()
            have.extend(_extract_vpc_pairs_from_list_response(vpc_pairs_response))
            list_query_succeeded = True
        except Exception as list_error:
            nrm.module.warn(
                f"VPC pairs list query failed for fabric {fabric_name}: "
                f"{str(list_error).splitlines()[0]}."
            )

        # Lightweight path for read-only and delete workflows.
        # Keep heavy discovery/enrichment only for write states.
        if state in ("deleted", "gathered"):
            if list_query_succeeded:
                if state == "gathered":
                    have = _filter_vpc_pairs_by_requested_config(have, config)
                return _set_lightweight_context(have)

            nrm.module.warn(
                "Skipping switch-level discovery for read-only/delete workflow because "
                "the vPC list endpoint is unavailable."
            )

            if state == "gathered":
                return _set_lightweight_context([])

            # Preserve explicit delete intent without full-fabric discovery.
            # This keeps delete deterministic and avoids expensive inventory calls.
            fallback_have = []
            for item in config:
                switch_id_val = item.get("switch_id") or item.get(VpcFieldNames.SWITCH_ID)
                peer_switch_id_val = item.get("peer_switch_id") or item.get(VpcFieldNames.PEER_SWITCH_ID)
                if not switch_id_val or not peer_switch_id_val:
                    continue

                use_vpl_val = item.get("use_virtual_peer_link")
                if use_vpl_val is None:
                    use_vpl_val = item.get(VpcFieldNames.USE_VIRTUAL_PEER_LINK, True)

                fallback_have.append(
                    {
                        VpcFieldNames.SWITCH_ID: switch_id_val,
                        VpcFieldNames.PEER_SWITCH_ID: peer_switch_id_val,
                        VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl_val,
                    }
                )

            if fallback_have:
                nrm.module.warn(
                    "Using requested delete config as fallback existing set because "
                    "vPC list query failed."
                )
                return _set_lightweight_context(fallback_have)

            if config:
                nrm.module.warn(
                    "Delete config did not contain complete vPC pairs. "
                    "No delete intents can be built from list-query fallback."
                )
                return _set_lightweight_context([])

            nrm.module.warn(
                "Delete-all requested with no explicit pairs and unavailable list endpoint. "
                "Falling back to switch-level discovery."
            )

        # Step 2 (write-state enrichment): Query and validate fabric switches.
        fabric_switches = _validate_fabric_switches(nd_v2, fabric_name)

        if not fabric_switches:
            nrm.module.warn(f"No switches found in fabric {fabric_name}")
            nrm.module.params["_fabric_switches"] = []
            nrm.module.params["_fabric_switches_count"] = 0
            nrm.module.params["_have"] = []
            nrm.module.params["_pending_create"] = []
            nrm.module.params["_pending_delete"] = []
            return []

        # Keep only switch IDs for validation and serialize safely in module params.
        fabric_switches_list = list(fabric_switches.keys())
        nrm.module.params["_fabric_switches"] = fabric_switches_list
        nrm.module.params["_fabric_switches_count"] = len(fabric_switches)

        # Build IP-to-SN mapping (extract before dict is discarded).
        ip_to_sn = {
            sw.get(VpcFieldNames.FABRIC_MGMT_IP): sw.get(VpcFieldNames.SERIAL_NUMBER)
            for sw in fabric_switches.values()
            if VpcFieldNames.FABRIC_MGMT_IP in sw
        }
        nrm.module.params["_ip_to_sn_mapping"] = ip_to_sn

        # Step 3: Track 3-state VPC pairs (have/pending_create/pending_delete).
        pending_create = []
        pending_delete = []
        processed_switches = set()

        desired_pairs = {}
        config_switch_ids = set()
        for item in config:
            # Config items are normalized to snake_case in main().
            switch_id_val = item.get("switch_id") or item.get(VpcFieldNames.SWITCH_ID)
            peer_switch_id_val = item.get("peer_switch_id") or item.get(VpcFieldNames.PEER_SWITCH_ID)

            if switch_id_val:
                config_switch_ids.add(switch_id_val)
            if peer_switch_id_val:
                config_switch_ids.add(peer_switch_id_val)

            if switch_id_val and peer_switch_id_val:
                desired_pairs[tuple(sorted([switch_id_val, peer_switch_id_val]))] = item

        for switch_id, switch in fabric_switches.items():
            if switch_id in processed_switches:
                continue

            vpc_configured = switch.get(VpcFieldNames.VPC_CONFIGURED, False)
            vpc_data = switch.get("vpcData", {})

            if vpc_configured and vpc_data:
                peer_switch_id = vpc_data.get("peerSwitchId")
                processed_switches.add(switch_id)
                processed_switches.add(peer_switch_id)

                # For configured pairs, prefer direct vPC query as source of truth.
                try:
                    vpc_pair_path = VpcPairEndpoints.switch_vpc_pair(fabric_name, switch_id)
                    rest_send = nd_v2._get_rest_send()
                    rest_send.save_settings()
                    rest_send.timeout = 5
                    try:
                        direct_vpc = nd_v2.request(vpc_pair_path, HttpVerbEnum.GET)
                    finally:
                        rest_send.restore_settings()
                except (NDModuleError, Exception):
                    direct_vpc = None

                if direct_vpc:
                    resolved_peer_switch_id = direct_vpc.get(VpcFieldNames.PEER_SWITCH_ID) or peer_switch_id
                    if resolved_peer_switch_id:
                        processed_switches.add(resolved_peer_switch_id)
                    use_vpl = _get_api_field_value(direct_vpc, "useVirtualPeerLink", False)

                    # Direct /vpcPair can be stale for a short period after delete.
                    # Cross-check overview to avoid reporting stale active pairs.
                    membership = _is_switch_in_vpc_pair(
                        nd_v2, fabric_name, switch_id, timeout=5
                    )
                    if membership is False:
                        pair_key = None
                        if resolved_peer_switch_id:
                            pair_key = tuple(sorted([switch_id, resolved_peer_switch_id]))
                        desired_item = desired_pairs.get(pair_key) if pair_key else None
                        desired_use_vpl = None
                        if desired_item:
                            desired_use_vpl = desired_item.get("use_virtual_peer_link")
                            if desired_use_vpl is None:
                                desired_use_vpl = desired_item.get(VpcFieldNames.USE_VIRTUAL_PEER_LINK)

                        # Narrow override: trust direct payload only for write states
                        # when it matches desired pair intent.
                        if state in ("merged", "replaced", "overridden") and desired_item is not None:
                            if desired_use_vpl is None or bool(desired_use_vpl) == bool(use_vpl):
                                nrm.module.warn(
                                    f"Overview membership check returned 'not paired' for switch {switch_id}, "
                                    "but direct /vpcPair matched requested config. Treating pair as active."
                                )
                                membership = True
                    if membership is False:
                        pending_delete.append({
                            VpcFieldNames.SWITCH_ID: switch_id,
                            VpcFieldNames.PEER_SWITCH_ID: resolved_peer_switch_id,
                            VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl,
                        })
                    else:
                        have.append({
                            VpcFieldNames.SWITCH_ID: switch_id,
                            VpcFieldNames.PEER_SWITCH_ID: resolved_peer_switch_id,
                            VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl,
                        })
                else:
                    # Direct query failed - fall back to recommendation.
                    try:
                        recommendation = _get_recommendation_details(nd_v2, fabric_name, switch_id)
                    except Exception as rec_error:
                        error_msg = str(rec_error).splitlines()[0]
                        nrm.module.warn(
                            f"Recommendation query failed for switch {switch_id}: {error_msg}. "
                            f"Unable to read configured vPC pair details."
                        )
                        recommendation = None

                    if recommendation:
                        resolved_peer_switch_id = _get_api_field_value(recommendation, "serialNumber") or peer_switch_id
                        if resolved_peer_switch_id:
                            processed_switches.add(resolved_peer_switch_id)
                        use_vpl = _get_api_field_value(recommendation, "useVirtualPeerLink", False)
                        have.append({
                            VpcFieldNames.SWITCH_ID: switch_id,
                            VpcFieldNames.PEER_SWITCH_ID: resolved_peer_switch_id,
                            VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl,
                        })
                    else:
                        # VPC configured but query failed - mark as pending delete.
                        pending_delete.append({
                            VpcFieldNames.SWITCH_ID: switch_id,
                            VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
                            VpcFieldNames.USE_VIRTUAL_PEER_LINK: False,
                        })
            elif not config_switch_ids or switch_id in config_switch_ids:
                # For unconfigured switches, prefer direct vPC pair query first.
                try:
                    vpc_pair_path = VpcPairEndpoints.switch_vpc_pair(fabric_name, switch_id)
                    rest_send = nd_v2._get_rest_send()
                    rest_send.save_settings()
                    rest_send.timeout = 5
                    try:
                        direct_vpc = nd_v2.request(vpc_pair_path, HttpVerbEnum.GET)
                    finally:
                        rest_send.restore_settings()
                except (NDModuleError, Exception):
                    direct_vpc = None

                if direct_vpc:
                    peer_switch_id = direct_vpc.get(VpcFieldNames.PEER_SWITCH_ID)
                    if peer_switch_id:
                        processed_switches.add(switch_id)
                        processed_switches.add(peer_switch_id)

                        use_vpl = _get_api_field_value(direct_vpc, "useVirtualPeerLink", False)
                        membership = _is_switch_in_vpc_pair(
                            nd_v2, fabric_name, switch_id, timeout=5
                        )
                        if membership is False:
                            pair_key = tuple(sorted([switch_id, peer_switch_id]))
                            desired_item = desired_pairs.get(pair_key)
                            desired_use_vpl = None
                            if desired_item:
                                desired_use_vpl = desired_item.get("use_virtual_peer_link")
                                if desired_use_vpl is None:
                                    desired_use_vpl = desired_item.get(VpcFieldNames.USE_VIRTUAL_PEER_LINK)

                            if state in ("merged", "replaced", "overridden") and desired_item is not None:
                                if desired_use_vpl is None or bool(desired_use_vpl) == bool(use_vpl):
                                    nrm.module.warn(
                                        f"Overview membership check returned 'not paired' for switch {switch_id}, "
                                        "but direct /vpcPair matched requested config. Treating pair as active."
                                    )
                                    membership = True
                        if membership is False:
                            pending_delete.append({
                                VpcFieldNames.SWITCH_ID: switch_id,
                                VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
                                VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl,
                            })
                        else:
                            have.append({
                                VpcFieldNames.SWITCH_ID: switch_id,
                                VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
                                VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl,
                            })
                else:
                    # No direct pair; check recommendation for pending create candidates.
                    try:
                        recommendation = _get_recommendation_details(nd_v2, fabric_name, switch_id)
                    except Exception as rec_error:
                        error_msg = str(rec_error).splitlines()[0]
                        nrm.module.warn(
                            f"Recommendation query failed for switch {switch_id}: {error_msg}. "
                            f"No recommendation details available."
                        )
                        recommendation = None

                    if recommendation:
                        peer_switch_id = _get_api_field_value(recommendation, "serialNumber")
                        if peer_switch_id:
                            processed_switches.add(switch_id)
                            processed_switches.add(peer_switch_id)

                            use_vpl = _get_api_field_value(recommendation, "useVirtualPeerLink", False)
                            pending_create.append({
                                VpcFieldNames.SWITCH_ID: switch_id,
                                VpcFieldNames.PEER_SWITCH_ID: peer_switch_id,
                                VpcFieldNames.USE_VIRTUAL_PEER_LINK: use_vpl,
                            })

        # Step 4: Store all states for use in create/update/delete.
        nrm.module.params["_have"] = have
        nrm.module.params["_pending_create"] = pending_create
        nrm.module.params["_pending_delete"] = pending_delete

        # Build effective existing set for state reconciliation:
        # - Include active pairs (have) and pending-create pairs.
        # - Exclude pending-delete pairs from active set to avoid stale
        #   idempotence false-negatives right after unpair operations.
        pair_by_key = {}
        for pair in pending_create + have:
            switch_id = pair.get(VpcFieldNames.SWITCH_ID)
            peer_switch_id = pair.get(VpcFieldNames.PEER_SWITCH_ID)
            if not switch_id or not peer_switch_id:
                continue
            key = tuple(sorted([switch_id, peer_switch_id]))
            pair_by_key[key] = pair

        for pair in pending_delete:
            switch_id = pair.get(VpcFieldNames.SWITCH_ID)
            peer_switch_id = pair.get(VpcFieldNames.PEER_SWITCH_ID)
            if not switch_id or not peer_switch_id:
                continue
            key = tuple(sorted([switch_id, peer_switch_id]))
            pair_by_key.pop(key, None)

        existing_pairs = list(pair_by_key.values())
        return existing_pairs

    except NDModuleError as error:
        error_dict = error.to_dict()
        if "msg" in error_dict:
            error_dict["api_error_msg"] = error_dict.pop("msg")
        _raise_vpc_error(
            msg=f"Failed to query VPC pairs: {error.msg}",
            fabric=fabric_name,
            **error_dict
        )
    except VpcPairResourceError:
        raise
    except Exception as e:
        _raise_vpc_error(
            msg=f"Failed to query VPC pairs: {str(e)}",
            fabric=fabric_name,
            exception_type=type(e).__name__
        )


def custom_vpc_create(nrm) -> Optional[Dict[str, Any]]:
    """
    Custom create function for VPC pairs using RestSend with PUT + discriminator.
    - Validates switches exist in fabric (Common.validate_switches_exist)
    - Checks for switch conflicts (Common.validate_no_switch_conflicts)
    - Uses PUT instead of POST (non-RESTful API)
    - Adds vpcAction: "pair" discriminator
    - Proper error handling with NDModuleError
    - Results aggregation

    Args:
        nrm: NDStateMachine instance

    Returns:
        API response dictionary or None

    Raises:
        ValueError: If fabric_name or switch_id is not provided
        AnsibleModule.fail_json: If validation fails
    """
    if nrm.module.check_mode:
        return nrm.proposed_config

    fabric_name = nrm.module.params.get("fabric_name")
    switch_id = nrm.proposed_config.get(VpcFieldNames.SWITCH_ID)
    peer_switch_id = nrm.proposed_config.get(VpcFieldNames.PEER_SWITCH_ID)

    # Path validation
    if not fabric_name:
        raise ValueError("fabric_name is required but was not provided")
    if not switch_id:
        raise ValueError("switch_id is required but was not provided")
    if not peer_switch_id:
        raise ValueError("peer_switch_id is required but was not provided")

    # Validation Step 1: both switches must exist in discovered fabric inventory.
    _validate_switches_exist_in_fabric(
        nrm=nrm,
        fabric_name=fabric_name,
        switch_id=switch_id,
        peer_switch_id=peer_switch_id,
    )
    
    # Validation Step 2: Check for switch conflicts (from Common.validate_no_switch_conflicts)
    have_vpc_pairs = nrm.module.params.get("_have", [])
    if have_vpc_pairs:
        _validate_switch_conflicts([nrm.proposed_config], have_vpc_pairs, nrm.module)

    # Validation Step 3: Check if create is actually needed (idempotence check)
    if nrm.existing_config:
        want_dict = nrm.proposed_config.model_dump(by_alias=True, exclude_none=True) if hasattr(nrm.proposed_config, 'model_dump') else nrm.proposed_config
        have_dict = nrm.existing_config.model_dump(by_alias=True, exclude_none=True) if hasattr(nrm.existing_config, 'model_dump') else nrm.existing_config

        if not _is_update_needed(want_dict, have_dict):
            # Already exists in desired state - return existing config without changes
            nrm.module.warn(
                f"VPC pair {nrm.current_identifier} already exists in desired state - skipping create"
            )
            return nrm.existing_config

    # Initialize RestSend via NDModuleV2
    nd_v2 = NDModuleV2(nrm.module)
    use_virtual_peer_link = nrm.proposed_config.get(VpcFieldNames.USE_VIRTUAL_PEER_LINK, True)

    # Validate pairing support using dedicated endpoint.
    # Only fail when API explicitly states pairing is not allowed.
    try:
        support_details = _get_pairing_support_details(
            nd_v2,
            fabric_name=fabric_name,
            switch_id=switch_id,
            component_type=ComponentTypeSupportEnum.CHECK_PAIRING.value,
        )
        if support_details:
            is_pairing_allowed = _get_api_field_value(
                support_details, "isPairingAllowed", None
            )
            if is_pairing_allowed is False:
                reason = _get_api_field_value(
                    support_details, "reason", "pairing blocked by support checks"
                )
                _raise_vpc_error(
                    msg=f"VPC pairing is not allowed for switch {switch_id}: {reason}",
                    fabric=fabric_name,
                    switch_id=switch_id,
                    peer_switch_id=peer_switch_id,
                    support_details=support_details,
                )
    except VpcPairResourceError:
        raise
    except Exception as support_error:
        nrm.module.warn(
            f"Pairing support check failed for switch {switch_id}: "
            f"{str(support_error).splitlines()[0]}. Continuing with create operation."
        )

    # Validate fabric peering support if virtual peer link is requested.
    _validate_fabric_peering_support(
        nrm=nrm,
        nd_v2=nd_v2,
        fabric_name=fabric_name,
        switch_id=switch_id,
        peer_switch_id=peer_switch_id,
        use_virtual_peer_link=use_virtual_peer_link,
    )

    # Build path with switch ID using Manage API (not NDFC API)
    # The NDFC API (/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/vpcpair) may not be available
    # Use Manage API (/api/v1/manage/fabrics/.../vpcPair) instead
    path = VpcPairEndpoints.switch_vpc_pair(fabric_name, switch_id)

    # Build payload with discriminator using helper (supports vpc_pair_details)
    payload = _build_vpc_pair_payload(nrm.proposed_config)

    # Log the operation
    nrm.format_log(
        identifier=nrm.current_identifier,
        status="created",
        after_data=payload,
        sent_payload_data=payload
    )

    try:
        # Use PUT (not POST!) for create via RestSend
        response = nd_v2.request(path, HttpVerbEnum.PUT, payload)
        return response

    except NDModuleError as error:
        error_dict = error.to_dict()
        # Preserve original API error message with different key to avoid conflict
        if 'msg' in error_dict:
            error_dict['api_error_msg'] = error_dict.pop('msg')
        _raise_vpc_error(
            msg=f"Failed to create VPC pair {nrm.current_identifier}: {error.msg}",
            fabric=fabric_name,
            switch_id=switch_id,
            peer_switch_id=peer_switch_id,
            path=path,
            **error_dict
        )
    except VpcPairResourceError:
        raise
    except Exception as e:
        _raise_vpc_error(
            msg=f"Failed to create VPC pair {nrm.current_identifier}: {str(e)}",
            fabric=fabric_name,
            switch_id=switch_id,
            peer_switch_id=peer_switch_id,
            path=path,
            exception_type=type(e).__name__
        )


def custom_vpc_update(nrm) -> Optional[Dict[str, Any]]:
    """
    Custom update function for VPC pairs using RestSend.

    - Uses PUT with discriminator (same as create)
    - Validates switches exist in fabric
    - Checks for switch conflicts
    - Uses DeepDiff to detect if update is actually needed
    - Proper error handling

    Args:
        nrm: NDStateMachine instance

    Returns:
        API response dictionary or None

    Raises:
        ValueError: If fabric_name or switch_id is not provided
    """
    if nrm.module.check_mode:
        return nrm.proposed_config

    fabric_name = nrm.module.params.get("fabric_name")
    switch_id = nrm.proposed_config.get(VpcFieldNames.SWITCH_ID)
    peer_switch_id = nrm.proposed_config.get(VpcFieldNames.PEER_SWITCH_ID)

    # Path validation
    if not fabric_name:
        raise ValueError("fabric_name is required but was not provided")
    if not switch_id:
        raise ValueError("switch_id is required but was not provided")
    if not peer_switch_id:
        raise ValueError("peer_switch_id is required but was not provided")

    # Validation Step 1: both switches must exist in discovered fabric inventory.
    _validate_switches_exist_in_fabric(
        nrm=nrm,
        fabric_name=fabric_name,
        switch_id=switch_id,
        peer_switch_id=peer_switch_id,
    )
    
    # Validation Step 2: Check for switch conflicts (from Common.validate_no_switch_conflicts)
    have_vpc_pairs = nrm.module.params.get("_have", [])
    if have_vpc_pairs:
        # Filter out the current VPC pair being updated
        other_vpc_pairs = [
            vpc for vpc in have_vpc_pairs 
            if vpc.get(VpcFieldNames.SWITCH_ID) != switch_id
        ]
        if other_vpc_pairs:
            _validate_switch_conflicts([nrm.proposed_config], other_vpc_pairs, nrm.module)

    # Validation Step 3: Check if update is actually needed using DeepDiff
    if nrm.existing_config:
        want_dict = nrm.proposed_config.model_dump(by_alias=True, exclude_none=True) if hasattr(nrm.proposed_config, 'model_dump') else nrm.proposed_config
        have_dict = nrm.existing_config.model_dump(by_alias=True, exclude_none=True) if hasattr(nrm.existing_config, 'model_dump') else nrm.existing_config
        
        if not _is_update_needed(want_dict, have_dict):
            # No changes needed - return existing config
            nrm.module.warn(
                f"VPC pair {nrm.current_identifier} is already in desired state - skipping update"
            )
            return nrm.existing_config

    # Initialize RestSend via NDModuleV2
    nd_v2 = NDModuleV2(nrm.module)
    use_virtual_peer_link = nrm.proposed_config.get(VpcFieldNames.USE_VIRTUAL_PEER_LINK, True)

    # Validate fabric peering support if virtual peer link is requested.
    _validate_fabric_peering_support(
        nrm=nrm,
        nd_v2=nd_v2,
        fabric_name=fabric_name,
        switch_id=switch_id,
        peer_switch_id=peer_switch_id,
        use_virtual_peer_link=use_virtual_peer_link,
    )

    # Build path with switch ID using Manage API (not NDFC API)
    # The NDFC API (/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/vpcpair) may not be available
    # Use Manage API (/api/v1/manage/fabrics/.../vpcPair) instead
    path = VpcPairEndpoints.switch_vpc_pair(fabric_name, switch_id)

    # Build payload with discriminator using helper (supports vpc_pair_details)
    payload = _build_vpc_pair_payload(nrm.proposed_config)

    # Log the operation
    nrm.format_log(
        identifier=nrm.current_identifier,
        status="updated",
        after_data=payload,
        sent_payload_data=payload
    )

    try:
        # Use PUT for update via RestSend
        response = nd_v2.request(path, HttpVerbEnum.PUT, payload)
        return response

    except NDModuleError as error:
        error_dict = error.to_dict()
        # Preserve original API error message with different key to avoid conflict
        if 'msg' in error_dict:
            error_dict['api_error_msg'] = error_dict.pop('msg')
        _raise_vpc_error(
            msg=f"Failed to update VPC pair {nrm.current_identifier}: {error.msg}",
            fabric=fabric_name,
            switch_id=switch_id,
            path=path,
            **error_dict
        )
    except VpcPairResourceError:
        raise
    except Exception as e:
        _raise_vpc_error(
            msg=f"Failed to update VPC pair {nrm.current_identifier}: {str(e)}",
            fabric=fabric_name,
            switch_id=switch_id,
            path=path,
            exception_type=type(e).__name__
        )


def custom_vpc_delete(nrm) -> None:
    """
    Custom delete function for VPC pairs using RestSend with PUT + discriminator.

    - Pre-deletion validation (network/VRF/interface checks)
    - Uses PUT instead of DELETE (non-RESTful API)
    - Adds vpcAction: "unpair" discriminator
    - Proper error handling with NDModuleError

    Args:
        nrm: NDStateMachine instance

    Raises:
        ValueError: If fabric_name or switch_id is not provided
        AnsibleModule.fail_json: If validation fails (networks/VRFs attached)
    """
    if nrm.module.check_mode:
        return

    fabric_name = nrm.module.params.get("fabric_name")
    switch_id = nrm.existing_config.get(VpcFieldNames.SWITCH_ID)
    peer_switch_id = nrm.existing_config.get(VpcFieldNames.PEER_SWITCH_ID)

    # Path validation
    if not fabric_name:
        raise ValueError("fabric_name is required but was not provided")
    if not switch_id:
        raise ValueError("switch_id is required but was not provided")

    # Initialize RestSend via NDModuleV2
    nd_v2 = NDModuleV2(nrm.module)

    # CRITICAL: Pre-deletion validation to prevent data loss
    # Checks for active networks, VRFs, and warns about vPC interfaces
    vpc_pair_key = f"{switch_id}-{peer_switch_id}" if peer_switch_id else switch_id

    # Track whether force parameter was actually needed
    force_delete = nrm.module.params.get("force", False)
    validation_succeeded = False

    # Perform validation with timeout protection
    try:
        _validate_vpc_pair_deletion(nd_v2, fabric_name, switch_id, vpc_pair_key, nrm.module)
        validation_succeeded = True

        # If force was enabled but validation succeeded, inform user it wasn't needed
        if force_delete:
            nrm.module.warn(
                f"Force deletion was enabled for {vpc_pair_key}, but pre-deletion validation succeeded. "
                f"The 'force: true' parameter was not necessary in this case. "
                f"Consider removing 'force: true' to benefit from safety checks in future runs."
            )

    except ValueError as already_unpaired:
        # Sentinel from _validate_vpc_pair_deletion: pair no longer exists.
        # Treat as idempotent success — nothing to delete.
        nrm.module.warn(str(already_unpaired))
        return

    except (NDModuleError, Exception) as validation_error:
        # Validation failed - check if force deletion is enabled
        if not force_delete:
            _raise_vpc_error(
                msg=(
                    f"Pre-deletion validation failed for VPC pair {vpc_pair_key}. "
                    f"Error: {str(validation_error)}. "
                    f"If you're certain the VPC pair can be safely deleted, use 'force: true' parameter. "
                    f"WARNING: Force deletion bypasses safety checks and may cause data loss."
                ),
                vpc_pair_key=vpc_pair_key,
                validation_error=str(validation_error),
                force_available=True
            )
        else:
            # Force enabled and validation failed - this is when force was actually needed
            nrm.module.warn(
                f"Force deletion enabled for {vpc_pair_key} - bypassing pre-deletion validation. "
                f"Validation error was: {str(validation_error)}. "
                f"WARNING: Proceeding without safety checks - ensure no data loss will occur."
            )

    # Build path with switch ID using Manage API (not NDFC API)
    # The NDFC API (/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/vpcpair) may not be available
    # Use Manage API (/api/v1/manage/fabrics/.../vpcPair) instead
    path = VpcPairEndpoints.switch_vpc_pair(fabric_name, switch_id)

    # Build minimal payload with discriminator for delete
    payload = {
        VpcFieldNames.VPC_ACTION: VpcActionEnum.UNPAIR.value,  # ← Discriminator for DELETE
        VpcFieldNames.SWITCH_ID: nrm.existing_config.get(VpcFieldNames.SWITCH_ID),
        VpcFieldNames.PEER_SWITCH_ID: nrm.existing_config.get(VpcFieldNames.PEER_SWITCH_ID)
    }

    # Log the operation
    nrm.format_log(
        identifier=nrm.current_identifier,
        status="deleted",
        sent_payload_data=payload
    )

    try:
        # Use PUT (not DELETE!) for unpair via RestSend
        rest_send = nd_v2._get_rest_send()
        rest_send.save_settings()
        rest_send.timeout = nrm.module.params.get("api_timeout", 30)
        try:
            nd_v2.request(path, HttpVerbEnum.PUT, payload)
        finally:
            rest_send.restore_settings()

    except NDModuleError as error:
        error_msg = str(error.msg).lower() if error.msg else ""
        status_code = error.status or 0

        # Idempotent handling: if the API says the switch is not part of any
        # vPC pair, the pair is already gone — treat as a successful no-op.
        if status_code == 400 and "not a part of" in error_msg:
            nrm.module.warn(
                f"VPC pair {nrm.current_identifier} is already unpaired on the controller. "
                f"Treating as idempotent success. API response: {error.msg}"
            )
            return

        error_dict = error.to_dict()
        # Preserve original API error message with different key to avoid conflict
        if 'msg' in error_dict:
            error_dict['api_error_msg'] = error_dict.pop('msg')
        _raise_vpc_error(
            msg=f"Failed to delete VPC pair {nrm.current_identifier}: {error.msg}",
            fabric=fabric_name,
            switch_id=switch_id,
            path=path,
            **error_dict
        )
    except VpcPairResourceError:
        raise
    except Exception as e:
        _raise_vpc_error(
            msg=f"Failed to delete VPC pair {nrm.current_identifier}: {str(e)}",
            fabric=fabric_name,
            switch_id=switch_id,
            path=path,
            exception_type=type(e).__name__
        )


def _needs_deployment(result: Dict, nrm) -> bool:
    """
    Determine if deployment is needed based on changes and pending operations.
    
    Deployment is needed if any of:
    1. There are items in the diff (configuration changes)
    2. There are pending create VPC pairs
    3. There are pending delete VPC pairs
    
    Args:
        result: Module result dictionary with diff info
        nrm: NDStateMachine instance
        
    Returns:
        True if deployment is needed, False otherwise
    """
    # Check if there are any changes in the result
    has_changes = result.get("changed", False)
    
    # Check diff - framework stores before/after
    before = result.get("before", [])
    after = result.get("after", [])
    has_diff_changes = before != after
    
    # Check pending operations
    pending_create = nrm.module.params.get("_pending_create", [])
    pending_delete = nrm.module.params.get("_pending_delete", [])
    has_pending = bool(pending_create or pending_delete)
    
    needs_deploy = has_changes or has_diff_changes or has_pending
    
    return needs_deploy


def _is_non_fatal_config_save_error(error: NDModuleError) -> bool:
    """
    Return True only for known non-fatal configSave platform limitations.
    """
    if not isinstance(error, NDModuleError):
        return False

    # Keep this allowlist tight to avoid masking real config-save failures.
    if error.status != 500:
        return False

    message = (error.msg or "").lower()
    non_fatal_signatures = (
        "vpc fabric peering is not supported",
        "vpcsanitycheck",
        "unexpected error generating vpc configuration",
    )
    return any(signature in message for signature in non_fatal_signatures)


def custom_vpc_deploy(nrm, fabric_name: str, result: Dict) -> Dict[str, Any]:
    """
    Custom deploy function for fabric configuration changes using RestSend.

    - Smart deployment decision (Common.needs_deployment)
    - Step 1: Save fabric configuration
    - Step 2: Deploy fabric with forceShowRun=true
    - Proper error handling with NDModuleError
    - Results aggregation
    - Only deploys if there are actual changes or pending operations

    Args:
        nrm: NDStateMachine instance
        fabric_name: Fabric name to deploy
        result: Module result dictionary to check for changes

    Returns:
        Deployment result dictionary

    Raises:
        NDModuleError: If deployment fails
    """
    # Smart deployment decision (from Common.needs_deployment)
    if not _needs_deployment(result, nrm):
        return {
            "msg": "No configuration changes or pending operations detected, skipping deployment",
            "fabric": fabric_name,
            "deployment_needed": False,
            "changed": False
        }
    
    if nrm.module.check_mode:
        # Dry run deployment info (similar to show_dry_run_deployment_info)
        before = result.get("before", [])
        after = result.get("after", [])
        pending_create = nrm.module.params.get("_pending_create", [])
        pending_delete = nrm.module.params.get("_pending_delete", [])
        
        deployment_info = {
            "msg": "CHECK MODE: Would save and deploy fabric configuration",
            "fabric": fabric_name,
            "deployment_needed": True,
            "changed": True,
            "would_deploy": True,
            "deployment_decision_factors": {
                "diff_has_changes": before != after,
                "pending_create_operations": len(pending_create),
                "pending_delete_operations": len(pending_delete),
                "actual_changes": result.get("changed", False)
            },
            "planned_actions": [
                f"POST {VpcPairEndpoints.fabric_config_save(fabric_name)}",
                f"POST {VpcPairEndpoints.fabric_config_deploy(fabric_name, force_show_run=True)}"
            ]
        }
        return deployment_info

    # Initialize RestSend via NDModuleV2
    nd_v2 = NDModuleV2(nrm.module)
    results = Results()

    # Step 1: Save config
    save_path = VpcPairEndpoints.fabric_config_save(fabric_name)

    try:
        nd_v2.request(save_path, HttpVerbEnum.POST, {})

        results.response_current = {
            "RETURN_CODE": nd_v2.status,
            "METHOD": "POST",
            "REQUEST_PATH": save_path,
            "MESSAGE": "Config saved successfully",
            "DATA": {},
        }
        results.result_current = {"success": True, "changed": True}
        results.register_task_result()

    except NDModuleError as error:
        if _is_non_fatal_config_save_error(error):
            # Known platform limitation warning; continue to deploy step.
            nrm.module.warn(f"Config save failed: {error.msg}")

            results.response_current = {
                "RETURN_CODE": error.status if error.status else -1,
                "MESSAGE": error.msg,
                "REQUEST_PATH": save_path,
                "METHOD": "POST",
                "DATA": {},
            }
            results.result_current = {"success": True, "changed": False}
            results.register_task_result()
        else:
            # Unknown config-save failures are fatal.
            results.response_current = {
                "RETURN_CODE": error.status if error.status else -1,
                "MESSAGE": error.msg,
                "REQUEST_PATH": save_path,
                "METHOD": "POST",
                "DATA": {},
            }
            results.result_current = {"success": False, "changed": False}
            results.register_task_result()
            results.build_final_result()
            final_result = dict(results.final_result)
            final_msg = final_result.pop("msg", f"Config save failed: {error.msg}")
            _raise_vpc_error(msg=final_msg, **final_result)

    # Step 2: Deploy
    deploy_path = VpcPairEndpoints.fabric_config_deploy(fabric_name, force_show_run=True)

    try:
        nd_v2.request(deploy_path, HttpVerbEnum.POST, {})

        results.response_current = {
            "RETURN_CODE": nd_v2.status,
            "METHOD": "POST",
            "REQUEST_PATH": deploy_path,
            "MESSAGE": "Deployment successful",
            "DATA": {},
        }
        results.result_current = {"success": True, "changed": True}
        results.register_task_result()

    except NDModuleError as error:
        results.response_current = {
            "RETURN_CODE": error.status if error.status else -1,
            "MESSAGE": error.msg,
            "REQUEST_PATH": deploy_path,
            "METHOD": "POST",
            "DATA": {},
        }
        results.result_current = {"success": False, "changed": False}
        results.register_task_result()

        # Build final result and fail
        results.build_final_result()
        final_result = dict(results.final_result)
        final_msg = final_result.pop("msg", "Fabric deployment failed")
        _raise_vpc_error(msg=final_msg, **final_result)

    # Build final result
    results.build_final_result()
    return results.final_result


def run_vpc_module(nrm) -> Dict[str, Any]:
    """
    Run VPC module state machine with VPC-specific gathered output.

    gathered is the query/read-only mode for VPC pairs.
    """
    state = nrm.module.params.get("state", "merged")
    config = nrm.module.params.get("config", [])

    if state == "gathered":
        nrm.add_logs_and_outputs()
        nrm.result["changed"] = False

        current_pairs = nrm.result.get("current", []) or []
        pending_delete = nrm.module.params.get("_pending_delete", []) or []

        # Exclude pairs in pending-delete from active gathered set.
        pending_delete_keys = set()
        for pair in pending_delete:
            switch_id = pair.get(VpcFieldNames.SWITCH_ID) or pair.get("switch_id")
            peer_switch_id = pair.get(VpcFieldNames.PEER_SWITCH_ID) or pair.get("peer_switch_id")
            if switch_id and peer_switch_id:
                pending_delete_keys.add(tuple(sorted([switch_id, peer_switch_id])))

        filtered_current = []
        for pair in current_pairs:
            switch_id = pair.get(VpcFieldNames.SWITCH_ID) or pair.get("switch_id")
            peer_switch_id = pair.get(VpcFieldNames.PEER_SWITCH_ID) or pair.get("peer_switch_id")
            if switch_id and peer_switch_id:
                pair_key = tuple(sorted([switch_id, peer_switch_id]))
                if pair_key in pending_delete_keys:
                    continue
            filtered_current.append(pair)

        nrm.result["current"] = filtered_current
        nrm.result["gathered"] = {
            "vpc_pairs": filtered_current,
            "pending_create_vpc_pairs": nrm.module.params.get("_pending_create", []),
            "pending_delete_vpc_pairs": pending_delete,
        }
        return nrm.result

    # state=deleted with empty config means "delete all existing pairs in this fabric".
    #
    # state=overridden with empty config has the same user intent (TC4):
    # remove all existing pairs from this fabric.
    if state in ("deleted", "overridden") and not config:
        # Use the live existing collection from NDStateMachine.
        # nrm.result["current"] is only populated after add_logs_and_outputs(), so relying on
        # it here would incorrectly produce an empty delete list.
        existing_pairs = _collection_to_list_flex(getattr(nrm, "existing", None))
        if not existing_pairs:
            existing_pairs = nrm.result.get("current", []) or []

        delete_all_config = []
        for pair in existing_pairs:
            switch_id = pair.get(VpcFieldNames.SWITCH_ID) or pair.get("switch_id")
            peer_switch_id = pair.get(VpcFieldNames.PEER_SWITCH_ID) or pair.get("peer_switch_id")
            if switch_id and peer_switch_id:
                use_vpl = pair.get(VpcFieldNames.USE_VIRTUAL_PEER_LINK)
                if use_vpl is None:
                    use_vpl = pair.get("use_virtual_peer_link", True)
                delete_all_config.append(
                    {
                        "switch_id": switch_id,
                        "peer_switch_id": peer_switch_id,
                        "use_virtual_peer_link": use_vpl,
                    }
                )
        config = delete_all_config
        # Force explicit delete operations instead of relying on overridden-state
        # reconciliation behavior with empty desired config.
        if state == "overridden":
            state = "deleted"

    nrm.manage_state(state=state, new_configs=config)
    nrm.add_logs_and_outputs()
    return nrm.result


# ===== Module Entry Point =====


def main():
    """
    Module entry point combining framework + RestSend.

    Architecture:
    - Thin module entrypoint delegates to VpcPairResourceService
    - VpcPairResourceService handles NDStateMachine orchestration
    - Custom actions use RestSend (NDModuleV2) for HTTP with retry logic
    """
    argument_spec = dict(
        state=dict(
            type="str",
            default="merged",
            choices=["merged", "replaced", "deleted", "overridden", "gathered"],
        ),
        fabric_name=dict(type="str", required=True),
        deploy=dict(type="bool", default=False),
        dry_run=dict(type="bool", default=False),
        force=dict(
            type="bool",
            default=False,
            description="Force deletion without pre-deletion validation (bypasses safety checks)"
        ),
        api_timeout=dict(
            type="int",
            default=30,
            description="API request timeout in seconds for primary operations"
        ),
        query_timeout=dict(
            type="int",
            default=10,
            description="API request timeout in seconds for query/recommendation operations"
        ),
        config=dict(
            type="list",
            elements="dict",
            options=dict(
                peer1_switch_id=dict(type="str", required=True, aliases=["switch_id"]),
                peer2_switch_id=dict(type="str", required=True, aliases=["peer_switch_id"]),
                use_virtual_peer_link=dict(type="bool", default=True),
                vpc_pair_details=dict(type="dict"),
            ),
        ),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    setup_logging(module)

    # Module-level validations
    if sys.version_info < (3, 9):
        module.fail_json(msg="Python version 3.9 or higher is required for this module.")

    if not HAS_DEEPDIFF:
        module.fail_json(
            msg=missing_required_lib("deepdiff"),
            exception=DEEPDIFF_IMPORT_ERROR
        )

    # State-specific parameter validations
    state = module.params.get("state", "merged")
    deploy = module.params.get("deploy")
    dry_run = module.params.get("dry_run")

    if state == "gathered" and deploy:
        module.fail_json(msg="Deploy parameter cannot be used with 'gathered' state")

    if state == "gathered" and dry_run:
        module.fail_json(msg="Dry_run parameter cannot be used with 'gathered' state")

    # Map dry_run to check_mode
    if dry_run:
        module.check_mode = True

    # Validate force parameter usage:
    # - state=deleted
    # - state=overridden with empty config (interpreted as delete-all)
    force = module.params.get("force", False)
    user_config = module.params.get("config") or []
    force_applicable = state == "deleted" or (
        state == "overridden" and len(user_config) == 0
    )
    if force and not force_applicable:
        module.warn(
            "Parameter 'force' only applies to state 'deleted' or to "
            "state 'overridden' when config is empty (delete-all behavior). "
            f"Ignoring force for state '{state}'."
        )

    # Normalize config keys for model
    config = module.params.get("config") or []
    normalized_config = []

    for item in config:
        normalized = {
            "switch_id": item.get("peer1_switch_id") or item.get("switch_id"),
            "peer_switch_id": item.get("peer2_switch_id") or item.get("peer_switch_id"),
            "use_virtual_peer_link": item.get("use_virtual_peer_link", True),
            "vpc_pair_details": item.get("vpc_pair_details"),
        }
        normalized_config.append(normalized)

    module.params["config"] = normalized_config

    # Gather must remain strictly read-only. Preserve user-provided config as a
    # query filter, but clear the framework desired config to avoid unintended
    # reconciliation before run_vpc_module() handles gathered output.
    if state == "gathered":
        module.params["_gather_filter_config"] = list(normalized_config)
        module.params["config"] = []
    else:
        module.params["_gather_filter_config"] = []

    # VpcPairResourceService bridges NDStateMachine lifecycle hooks to RestSend actions.
    fabric_name = module.params.get("fabric_name")
    actions = {
        "query_all": custom_vpc_query_all,
        "create": custom_vpc_create,
        "update": custom_vpc_update,
        "delete": custom_vpc_delete,
    }

    try:
        service = VpcPairResourceService(
            module=module,
            model_class=VpcPairModel,
            actions=actions,
            run_state_handler=run_vpc_module,
            deploy_handler=custom_vpc_deploy,
            needs_deployment_handler=_needs_deployment,
        )
        result = service.execute(fabric_name=fabric_name)

        module.exit_json(**result)

    except VpcPairResourceError as e:
        module.fail_json(msg=e.msg, **e.details)
    except Exception as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
