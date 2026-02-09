# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Endpoint-specific query parameter classes.

This module provides query parameter classes tailored for specific API
endpoints, handling their unique parameter requirements.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name
__author__ = "Allen Robel"

from typing import Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import BooleanStringEnum
from ansible_collections.cisco.nd.plugins.module_utils.ep.endpoint_mixins import ForceShowRunMixin, InclAllMsdSwitchesMixin
from ansible_collections.cisco.nd.plugins.module_utils.pydantic_compat import BaseModel, ConfigDict, Field

# Config for classes that use enums and need automatic value extraction
ENUM_CONFIG = ConfigDict(validate_assignment=True, use_enum_values=True)


class EndpointQueryParams(BaseModel):
    """
    # Summary

    Base class for endpoint query parameter models.

    This abstract base class provides a common interface for all endpoint-specific
    query parameter classes. Subclasses must implement the to_query_string() method
    to generate properly formatted query strings for their specific endpoints.

    ## Raises

    None
    """

    def to_query_string(self) -> str:
        """
        Build a query string from the model fields.

        Subclasses must override this method to provide endpoint-specific
        query string formatting.

        Returns an empty string by default.
        """
        return ""


class FabricConfigDeployQueryParams(EndpointQueryParams, ForceShowRunMixin, InclAllMsdSwitchesMixin):
    """
    # Summary

    Query parameters for fabric config deploy endpoints.

    ## Parameters

    - force_show_run: If true, fetch latest running config from device; if false, use cached version (default: "false")
    - incl_all_msd_switches: If true and MSD fabric, deploy all child fabric changes; if false, skip child fabrics (default: "false")

    ## Raises

    None
    """

    model_config = ENUM_CONFIG

    def to_query_string(self) -> str:
        """Build query string with forceShowRun and inclAllMSDSwitches parameters."""
        params = []
        # Always include these params - they have default values
        # Use .value to get the string value from the enum
        params.append(f"forceShowRun={self.force_show_run.value if hasattr(self.force_show_run, 'value') else self.force_show_run}")
        params.append(f"inclAllMSDSwitches={self.incl_all_msd_switches.value if hasattr(self.incl_all_msd_switches, 'value') else self.incl_all_msd_switches}")
        return "&".join(params)


class FabricConfigPreviewQueryParams(EndpointQueryParams, ForceShowRunMixin):
    """
    # Summary

    Query parameters for fabric config preview endpoints.

    ## Parameters

    - force_show_run: Force show running config (default: "false")
    - show_brief: Show brief output (default: "false")
    """

    show_brief: BooleanStringEnum = Field(default=BooleanStringEnum.FALSE, description="Show brief output")

    def to_query_string(self) -> str:
        """Build query string with forceShowRun and showBrief parameters."""
        params = []
        if self.force_show_run:
            params.append(f"forceShowRun={self.force_show_run.value if hasattr(self.force_show_run, 'value') else self.force_show_run}")
        if self.show_brief:
            params.append(f"showBrief={self.show_brief.value if hasattr(self.show_brief, 'value') else self.show_brief}")
        return "&".join(params)


class LinkByUuidQueryParams(EndpointQueryParams):
    """
    # Summary

    Query parameters for link by UUID endpoints.

    ## Parameters

    - source_cluster_name: Source cluster name (e.g., "nd-cluster-1")
    - destination_cluster_name: Destination cluster name (e.g., "nd-cluster-2")
    """

    source_cluster_name: Optional[str] = Field(default=None, min_length=1, description="Source cluster name")
    destination_cluster_name: Optional[str] = Field(default=None, min_length=1, description="Destination cluster name")

    def to_query_string(self) -> str:
        """Build query string with sourceClusterName and destinationClusterName parameters."""
        params = []
        if self.source_cluster_name:
            params.append(f"sourceClusterName={self.source_cluster_name}")
        if self.destination_cluster_name:
            params.append(f"destinationClusterName={self.destination_cluster_name}")
        return "&".join(params)


class NetworkNamesQueryParams(EndpointQueryParams):
    """
    # Summary

    Query parameters for network deletion endpoints.

    ## Parameters

    - network_names: Comma-separated list of network names to delete e.g. "Net1,Net2,Net3"
    """

    network_names: Optional[str] = Field(default=None, min_length=1, description="Comma-separated network names")

    def to_query_string(self) -> str:
        """Build query string with network-names parameter."""
        params = []
        if self.network_names:
            params.append(f"network-names={self.network_names}")
        return "&".join(params)


class VrfNamesQueryParams(EndpointQueryParams):
    """
    # Summary

    Query parameters for VRF deletion endpoints.

    ## Parameters

    - vrf_names: Comma-separated list of VRF names to delete e.g. "VRF1,VRF2,VRF3"
    """

    vrf_names: Optional[str] = Field(default=None, min_length=1, description="Comma-separated VRF names")

    def to_query_string(self) -> str:
        """Build query string with vrf-names parameter."""
        params = []
        if self.vrf_names:
            params.append(f"vrf-names={self.vrf_names}")
        return "&".join(params)


class ClusterHealthConfigQueryParams(EndpointQueryParams):
    """
    # Summary

    Query parameters for cluster health config endpoint.

    ## Parameters

    - cluster_name: Cluster name (optional)
    """

    cluster_name: Optional[str] = Field(default=None, min_length=1, description="Cluster name")

    def to_query_string(self) -> str:
        """Build query string with clusterName parameter."""
        params = []
        if self.cluster_name:
            params.append(f"clusterName={self.cluster_name}")
        return "&".join(params)


class ClusterHealthStatusQueryParams(EndpointQueryParams):
    """
    # Summary

    Query parameters for cluster health status endpoint.

    ## Parameters

    - cluster_name: Cluster name (optional)
    - health_category: Health category (optional)
    - node_name: Node name (optional)
    """

    cluster_name: Optional[str] = Field(default=None, min_length=1, description="Cluster name")
    health_category: Optional[str] = Field(default=None, min_length=1, description="Health category")
    node_name: Optional[str] = Field(default=None, min_length=1, description="Node name")

    def to_query_string(self) -> str:
        """Build query string with clusterName, healthCategory, and nodeName parameters."""
        params = []
        if self.cluster_name:
            params.append(f"clusterName={self.cluster_name}")
        if self.health_category:
            params.append(f"healthCategory={self.health_category}")
        if self.node_name:
            params.append(f"nodeName={self.node_name}")
        return "&".join(params)
