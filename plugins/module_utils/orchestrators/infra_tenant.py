# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Type, ClassVar, List, Dict, Any, Optional
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.infra_tenant.infra_tenant import InfraTenantModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra.tenants import (
    EpInfraTenantsPost,
    EpInfraTenantsPut,
    EpInfraTenantsDelete,
    EpInfraTenantsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.tenant_fabric_associations import (
    EpManageTenantFabricAssociationsGet,
    EpManageTenantFabricAssociationsPost,
)


class InfraTenantOrchestrator(NDBaseOrchestrator[InfraTenantModel]):
    model_class: ClassVar[Type[NDBaseModel]] = InfraTenantModel

    create_endpoint: Type[NDEndpointBaseModel] = EpInfraTenantsPost
    update_endpoint: Type[NDEndpointBaseModel] = EpInfraTenantsPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpInfraTenantsDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpInfraTenantsGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpInfraTenantsGet

    # --- Helpers for fabric associations (manage API) ---

    def _query_all_fabric_associations(self) -> List[Dict[str, Any]]:
        """Fetch all tenant-fabric associations from the manage API."""
        try:
            ep = EpManageTenantFabricAssociationsGet()
            result = self.sender.query_obj(ep.path)
            return result.get("tenantFabricAssociations", []) or []
        except Exception:
            return []

    @staticmethod
    def _group_associations_by_tenant(associations: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group fabric associations by tenant name, stripping tenantName and syncStatus."""
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for assoc in associations:
            tenant_name = assoc.get("tenantName")
            if not tenant_name:
                continue
            entry = {k: v for k, v in assoc.items() if k not in ("tenantName", "syncStatus")}
            grouped.setdefault(tenant_name, []).append(entry)
        return grouped

    def _sync_fabric_associations(
        self,
        tenant_name: str,
        proposed_associations: Optional[List[Any]],
        existing_associations: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """
        Reconcile fabric associations for a tenant.

        Compares proposed vs existing associations and issues create/delete
        calls to the manage API as needed.
        """
        if proposed_associations is None:
            return

        ep = EpManageTenantFabricAssociationsPost()

        # Build lookup of existing associations by fabric_name
        existing_by_fabric: Dict[str, Dict[str, Any]] = {}
        if existing_associations:
            for assoc in existing_associations:
                fname = assoc.get("fabricName") or assoc.get("fabric_name")
                if fname:
                    existing_by_fabric[fname] = assoc

        # Build lookup of proposed associations by fabric_name
        proposed_by_fabric: Dict[str, Dict[str, Any]] = {}
        for assoc in proposed_associations:
            if hasattr(assoc, "model_dump"):
                d = assoc.model_dump(by_alias=True, exclude_none=True)
            elif isinstance(assoc, dict):
                d = dict(assoc)
            else:
                continue
            fname = d.get("fabricName") or d.get("fabric_name")
            if fname:
                proposed_by_fabric[fname] = d

        # Delete associations no longer proposed
        to_delete = []
        for fname in existing_by_fabric:
            if fname not in proposed_by_fabric:
                to_delete.append({
                    "fabricName": fname,
                    "tenantName": tenant_name,
                    "associate": False,
                })

        # Create or update associations
        to_create = []
        for fname, proposed_data in proposed_by_fabric.items():
            payload = {
                "fabricName": fname,
                "tenantName": tenant_name,
                "associate": True,
            }
            if "allowedVlans" in proposed_data:
                payload["allowedVlans"] = proposed_data["allowedVlans"]
            elif "allowed_vlans" in proposed_data:
                payload["allowedVlans"] = proposed_data["allowed_vlans"]
            if "localName" in proposed_data:
                payload["localName"] = proposed_data["localName"]
            elif "local_name" in proposed_data:
                payload["localName"] = proposed_data["local_name"]
            if "tenantPrefix" in proposed_data:
                payload["tenantPrefix"] = proposed_data["tenantPrefix"]
            elif "tenant_prefix" in proposed_data:
                payload["tenantPrefix"] = proposed_data["tenant_prefix"]

            existing = existing_by_fabric.get(fname)
            if existing:
                # Check if association changed
                changed = False
                for key in ("allowedVlans", "localName", "tenantPrefix"):
                    if payload.get(key) != existing.get(key):
                        changed = True
                        break
                if changed:
                    to_create.append(payload)
            else:
                to_create.append(payload)

        items = to_delete + to_create
        if items:
            self.sender.request(path=ep.path, method=ep.verb, data={"items": items})

    def _delete_fabric_associations(self, tenant_name: str) -> None:
        """Delete all fabric associations for a tenant."""
        all_assocs = self._query_all_fabric_associations()
        to_delete = [
            {
                "fabricName": a.get("fabricName"),
                "tenantName": tenant_name,
                "associate": False,
            }
            for a in all_assocs
            if a.get("tenantName") == tenant_name
        ]
        if to_delete:
            ep = EpManageTenantFabricAssociationsPost()
            self.sender.request(path=ep.path, method=ep.verb, data={"items": to_delete})

    # --- Overridden CRUD operations ---

    def query_all(self) -> ResponseType:
        """
        Fetch tenants from infra API and merge fabric associations from manage API.
        """
        try:
            # Fetch tenants
            tenant_ep = self.query_all_endpoint()
            tenant_result = self.sender.query_obj(tenant_ep.path)
            tenants = tenant_result.get("tenants", []) or []

            # Fetch fabric associations
            all_assocs = self._query_all_fabric_associations()
            grouped = self._group_associations_by_tenant(all_assocs)

            # Merge associations into tenant data
            for tenant in tenants:
                tenant_name = tenant.get("name")
                if tenant_name and tenant_name in grouped:
                    tenant["fabricAssociations"] = grouped[tenant_name]

            return tenants
        except Exception as e:
            raise Exception(f"Query all failed: {e}") from e

    def create(self, model_instance: InfraTenantModel, **kwargs) -> ResponseType:
        """Create tenant via infra API, then create fabric associations via manage API."""
        try:
            # Create tenant in infra API
            api_endpoint = self.create_endpoint()
            result = self.sender.request(
                path=api_endpoint.path,
                method=api_endpoint.verb,
                data=model_instance.to_payload(),
            )

            # Create fabric associations if specified
            if model_instance.fabric_associations:
                self._sync_fabric_associations(
                    tenant_name=model_instance.name,
                    proposed_associations=model_instance.fabric_associations,
                )

            return result
        except Exception as e:
            raise Exception(f"Create failed for {model_instance.get_identifier_value()}: {e}") from e

    def update(self, model_instance: InfraTenantModel, **kwargs) -> ResponseType:
        """Update tenant via infra API, then reconcile fabric associations via manage API."""
        try:
            # Update tenant in infra API
            api_endpoint = self.update_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            result = self.sender.request(
                path=api_endpoint.path,
                method=api_endpoint.verb,
                data=model_instance.to_payload(),
            )

            # Reconcile fabric associations if specified
            if model_instance.fabric_associations is not None:
                all_assocs = self._query_all_fabric_associations()
                existing_for_tenant = [
                    a for a in all_assocs
                    if a.get("tenantName") == model_instance.name
                ]
                self._sync_fabric_associations(
                    tenant_name=model_instance.name,
                    proposed_associations=model_instance.fabric_associations,
                    existing_associations=existing_for_tenant,
                )

            return result
        except Exception as e:
            raise Exception(f"Update failed for {model_instance.get_identifier_value()}: {e}") from e

    def delete(self, model_instance: InfraTenantModel, **kwargs) -> ResponseType:
        """Delete fabric associations first, then delete tenant via infra API."""
        try:
            # Delete all fabric associations for this tenant
            self._delete_fabric_associations(model_instance.name)

            # Delete tenant from infra API
            api_endpoint = self.delete_endpoint()
            api_endpoint.set_identifiers(model_instance.get_identifier_value())
            return self.sender.request(path=api_endpoint.path, method=api_endpoint.verb)
        except Exception as e:
            raise Exception(f"Delete failed for {model_instance.get_identifier_value()}: {e}") from e
