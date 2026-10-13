# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Type, ClassVar
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.infra_tenant_domain.infra_tenant_domain import InfraTenantDomainModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra.tenant_domains import (
    EpInfraTenantDomainsPost,
    EpInfraTenantDomainsPut,
    EpInfraTenantDomainsDelete,
    EpInfraTenantDomainsGet,
)


class InfraTenantDomainOrchestrator(NDBaseOrchestrator[InfraTenantDomainModel]):
    model_class: ClassVar[Type[NDBaseModel]] = InfraTenantDomainModel

    create_endpoint: Type[NDEndpointBaseModel] = EpInfraTenantDomainsPost
    update_endpoint: Type[NDEndpointBaseModel] = EpInfraTenantDomainsPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpInfraTenantDomainsDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpInfraTenantDomainsGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpInfraTenantDomainsGet

    def query_all(self) -> ResponseType:
        """
        Custom query_all action to extract 'tenantDomains' from response.
        """
        try:
            api_endpoint = self.query_all_endpoint()
            result = self.sender.query_obj(api_endpoint.path)
            return result.get("tenantDomains", []) or []
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e
