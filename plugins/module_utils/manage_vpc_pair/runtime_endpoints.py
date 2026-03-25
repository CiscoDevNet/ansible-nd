# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

from typing import Optional

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    CompositeQueryParams,
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import (
    ComponentTypeSupportEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair import (
    EpVpcPairGet,
    EpVpcPairPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import (
    EpFabricSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair_consistency import (
    EpVpcPairConsistencyGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair_overview import (
    EpVpcPairOverviewGet,
    VpcPairOverviewEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair_recommendation import (
    EpVpcPairRecommendationGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair_support import (
    EpVpcPairSupportGet,
    VpcPairSupportEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vpc_pairs import (
    EpVpcPairsListGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_config_save import (
    EpFabricConfigSavePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_deploy import (
    EpFabricDeployPost,
)


class _ForceShowRunQueryParams(EndpointQueryParams):
    """Query params for deploy endpoint."""

    force_show_run: Optional[bool] = None


class VpcPairEndpoints:
    """
    Centralized endpoint builders for vPC pair runtime operations.

    Runtime helper -> API path:
    - vpc_pairs_list/vpc_pair_base -> /api/v1/manage/fabrics/{fabricName}/vpcPairs
    - switch_vpc_pair/vpc_pair_put -> /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPair
    - switch_vpc_support -> /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPairSupport
    - switch_vpc_overview -> /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPairOverview
    - switch_vpc_recommendations -> /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPairRecommendation
    - switch_vpc_consistency -> /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPairConsistency
    - fabric_config_save -> /api/v1/manage/fabrics/{fabricName}/actions/configSave
    - fabric_config_deploy -> /api/v1/manage/fabrics/{fabricName}/actions/deploy
    """

    @staticmethod
    def _append_query(path: str, *query_groups: EndpointQueryParams) -> str:
        """
        Append query parameters to an endpoint path.

        Args:
            path: Base URL path
            *query_groups: One or more EndpointQueryParams to serialize

        Returns:
            Path with query string appended, or original path if no params.
        """
        composite_params = CompositeQueryParams()
        for query_group in query_groups:
            composite_params.add(query_group)
        query_string = composite_params.to_query_string(url_encode=False)
        return f"{path}?{query_string}" if query_string else path

    @staticmethod
    def vpc_pair_base(fabric_name: str) -> str:
        """
        Build base path for vPC pairs list endpoint.

        Args:
            fabric_name: Fabric name

        Returns:
            Path: /api/v1/manage/fabrics/{fabricName}/vpcPairs
        """
        endpoint = EpVpcPairsListGet(fabric_name=fabric_name)
        return endpoint.path

    @staticmethod
    def vpc_pairs_list(fabric_name: str) -> str:
        """
        Build path for listing all vPC pairs in a fabric.

        Args:
            fabric_name: Fabric name

        Returns:
            Path: /api/v1/manage/fabrics/{fabricName}/vpcPairs
        """
        endpoint = EpVpcPairsListGet(fabric_name=fabric_name)
        return endpoint.path

    @staticmethod
    def vpc_pair_put(fabric_name: str, switch_id: str) -> str:
        """
        Build path for PUT (create/update/delete) on a switch vPC pair.

        Args:
            fabric_name: Fabric name
            switch_id: Switch serial number

        Returns:
            Path: /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPair
        """
        endpoint = EpVpcPairPut(fabric_name=fabric_name, switch_id=switch_id)
        return endpoint.path

    @staticmethod
    def fabric_switches(fabric_name: str) -> str:
        """
        Build path for querying fabric switch inventory.

        Args:
            fabric_name: Fabric name

        Returns:
            Path: /api/v1/manage/fabrics/{fabricName}/switches
        """
        endpoint = EpFabricSwitchesGet(fabric_name=fabric_name)
        return endpoint.path

    @staticmethod
    def switch_vpc_pair(fabric_name: str, switch_id: str) -> str:
        """
        Build path for GET/PUT on a specific switch vPC pair.

        Args:
            fabric_name: Fabric name
            switch_id: Switch serial number

        Returns:
            Path: /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPair
        """
        endpoint = EpVpcPairGet(fabric_name=fabric_name, switch_id=switch_id)
        return endpoint.path

    @staticmethod
    def switch_vpc_recommendations(fabric_name: str, switch_id: str) -> str:
        """
        Build path for querying vPC pair recommendations for a switch.

        Args:
            fabric_name: Fabric name
            switch_id: Switch serial number

        Returns:
            Path: .../switches/{switchId}/vpcPairRecommendation
        """
        endpoint = EpVpcPairRecommendationGet(fabric_name=fabric_name, switch_id=switch_id)
        return endpoint.path

    @staticmethod
    def switch_vpc_overview(fabric_name: str, switch_id: str, component_type: str = "full") -> str:
        """
        Build path for querying vPC pair overview for a switch.

        Args:
            fabric_name: Fabric name
            switch_id: Switch serial number
            component_type: Overview filter (default: "full")

        Returns:
            Path: .../switches/{switchId}/vpcPairOverview?componentType={type}
        """
        endpoint = EpVpcPairOverviewGet(
            fabric_name=fabric_name,
            switch_id=switch_id,
            endpoint_params=VpcPairOverviewEndpointParams(component_type=component_type),
        )
        return endpoint.path

    @staticmethod
    def switch_vpc_support(
        fabric_name: str,
        switch_id: str,
        component_type: str = ComponentTypeSupportEnum.CHECK_PAIRING.value,
    ) -> str:
        """
        Build path for querying vPC pair support status for a switch.

        Args:
            fabric_name: Fabric name
            switch_id: Switch serial number
            component_type: Support check type (default: checkPairing)

        Returns:
            Path: .../switches/{switchId}/vpcPairSupport?componentType={type}
        """
        endpoint = EpVpcPairSupportGet(
            fabric_name=fabric_name,
            switch_id=switch_id,
            endpoint_params=VpcPairSupportEndpointParams(component_type=component_type),
        )
        return endpoint.path

    @staticmethod
    def switch_vpc_consistency(fabric_name: str, switch_id: str) -> str:
        """
        Build path for querying vPC pair consistency diagnostics.

        Args:
            fabric_name: Fabric name
            switch_id: Switch serial number

        Returns:
            Path: .../switches/{switchId}/vpcPairConsistency
        """
        endpoint = EpVpcPairConsistencyGet(fabric_name=fabric_name, switch_id=switch_id)
        return endpoint.path

    @staticmethod
    def fabric_config_save(fabric_name: str) -> str:
        """
        Build path for fabric config-save action.

        Args:
            fabric_name: Fabric name

        Returns:
            Path: /api/v1/manage/fabrics/{fabricName}/actions/configSave
        """
        endpoint = EpFabricConfigSavePost(fabric_name=fabric_name)
        return endpoint.path

    @staticmethod
    def fabric_config_deploy(fabric_name: str, force_show_run: bool = True) -> str:
        """
        Build path for fabric deploy action.

        Args:
            fabric_name: Fabric name
            force_show_run: Whether to include forceShowRun query param (default: True)

        Returns:
            Path: .../fabrics/{fabricName}/actions/deploy?forceShowRun=true
        """
        endpoint = EpFabricDeployPost(fabric_name=fabric_name)
        base_path = endpoint.path
        query_params = _ForceShowRunQueryParams(
            force_show_run=True if force_show_run else None
        )
        return VpcPairEndpoints._append_query(base_path, query_params)
