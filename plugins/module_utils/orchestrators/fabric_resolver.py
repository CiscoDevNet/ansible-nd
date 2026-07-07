# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import time

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics import (
    EpOneManageFabricsMembersGet,
)

_FEDERATION_MANAGER_NOT_FOUND_ERRORS: frozenset[str] = frozenset(
    [
        "A federation manager does not exist",
        "Invalid JSON response: this API is allowed only for remote user",
        "Invalid JSON response: cannot serve APIs as federation state is secondary. Use primary cluster for APIs",
        "Invalid JSON response: cannot serve APIs as federation state is not established yet",
    ]
)


def _nd_onemanage_proxy(_version_str: str) -> str:
    """
    Return the OneManage proxy prefix.

    OneManage OpenAPI paths are rooted at ``/api/v1/oneManage`` and must not
    be routed through an additional proxy prefix.
    """
    return ""


def _response_data(response: Any) -> Any:
    """Return the data payload from direct NDModule or wrapped RestSend responses."""
    if isinstance(response, dict) and "DATA" in response:
        return response.get("DATA")
    return response


def _response_message(data: Any) -> str:
    """Extract a controller message from common ND response shapes."""
    if isinstance(data, dict):
        message = data.get("message")
        if isinstance(message, str):
            return message
        error = data.get("error")
        if isinstance(error, dict):
            error_message = error.get("message")
            if isinstance(error_message, str):
                return error_message
    return str(data)


def _detect_fabric_type(
    fabric_name: str,
    fabric_associations: dict[str, Any],
    data_type: str,
) -> tuple[str | None, dict | None]:
    """Classify a fabric from association data."""
    if fabric_name not in fabric_associations:
        return None, None

    fabric_data = fabric_associations[fabric_name]
    fabric_type = fabric_data.get("fabricType")
    fabric_state = fabric_data.get("fabricState")
    detected_type: str | None = None

    if data_type == "mcfg":
        if fabric_type == "MFD":
            detected_type = "multicluster_parent"
        elif fabric_state == "member":
            detected_type = "multicluster_child"
    elif data_type == "msd":
        if fabric_type == "MSD":
            detected_type = "multisite_parent"
        elif fabric_type == "MFD":
            detected_type = "multicluster_parent"
        elif fabric_state == "member":
            detected_type = "multisite_child"
        else:
            detected_type = "standalone"

    return detected_type, fabric_data


class FabricResolverBase:
    """
    Common resolver for ND Manage fabric topology.

    Live ND 4.2 behavior shows true MSD parents and MCFG parents both appear
    as ``fabricType=MSD`` in the MSD association endpoint.  This resolver keeps
    association data as the topology baseline and uses bounded OneManage probes
    only to disambiguate fabric-group parents and member fabrics.
    """

    _NO_FEDERATION_MANAGER = "A federation manager does not exist"

    resource_name = "resource"
    resource_type_key = "managementType"
    resource_get_cls: type[Any] | None = None
    standalone_strategy_cls: type[Any] | None = None
    multisite_parent_strategy_cls: type[Any] | None = None
    multicluster_parent_strategy_cls: type[Any] | None = None
    child_strategy_cls: type[Any] | None = None

    def __init__(self, nd_module: Any, fabric_name: str):
        self._nd = nd_module
        self.fabric_name = fabric_name
        self._workflow_trace: list[dict[str, Any]] = []
        self._trace_started_at = time.monotonic()

    @property
    def workflow_trace(self) -> list[dict[str, Any]]:
        """Return resolver trace entries for the workflow coordinator."""
        return list(self._workflow_trace)

    def _trace(self, event: str, **details: Any) -> None:
        entry = {
            "sequence": len(self._workflow_trace) + 1,
            "elapsed_ms": int((time.monotonic() - self._trace_started_at) * 1000),
            "event": event,
        }
        entry.update(details)
        self._workflow_trace.append(entry)

    def resolve(self) -> Any:
        """Resolve and instantiate the strategy for ``fabric_name``."""
        self._trace("fabric_resolver_start", fabric_name=self.fabric_name, resource_name=self.resource_name)
        fabric_type, fabric_data = self._resolve_fabric_type()
        self._trace("fabric_resolver_type_resolved", fabric_type=fabric_type, fabric_name=self.fabric_name)
        fabric_data = self._enrich_with_manage_fabric_details(fabric_data)
        strategy = self._build_strategy(fabric_type, fabric_data)
        self._trace(
            "fabric_resolver_end",
            fabric_name=self.fabric_name,
            fabric_type=getattr(strategy, "fabric_type", fabric_type),
            strategy=strategy.__class__.__name__,
        )
        return strategy

    def _fetch_federated_fabric_associations(self, fabric_details: dict[str, Any] | None = None) -> Any:
        """
        Detect whether the fabric is managed through OneManage MCFG.

        The discriminator is a schema-backed resource GET under:
            /api/v1/oneManage/manage/fabrics/{fabricName}/...
        """
        fabric_details = fabric_details if fabric_details is not None else self._fetch_manage_fabric_details(self.fabric_name)
        if fabric_details.get("category") != "fabricGroup":
            return self._NO_FEDERATION_MANAGER

        if self.resource_get_cls is None:
            return self._NO_FEDERATION_MANAGER

        endpoint = self.resource_get_cls(fabric_name=self.fabric_name)
        endpoint.endpoint_params.max = 1
        self._trace("fabric_resolver_onemanage_resource_probe_start", path=endpoint.path, method=endpoint.verb.value)
        response = self._request_onemanage_probe(endpoint.path, endpoint.verb.value)
        if not response:
            self._trace("fabric_resolver_onemanage_resource_probe_end", found=False)
            return self._NO_FEDERATION_MANAGER

        data = _response_data(response)
        if isinstance(data, str):
            self._trace("fabric_resolver_onemanage_resource_probe_end", found=False, response_type="str")
            return self._NO_FEDERATION_MANAGER

        self._trace("fabric_resolver_onemanage_resource_probe_end", found=True)
        return {
            self.fabric_name: {
                "fabricName": self.fabric_name,
                "fabricType": "MFD",
                "fabricState": "active",
            }
        }

    def _request_onemanage_probe(self, path: str, method: str) -> Any:
        """Call a OneManage probe without letting HTTP errors abort detection."""
        connection = getattr(self._nd, "connection", None)
        if connection is None:
            return self._nd.request(path, method=method, ignore_not_found_error=True)

        try:
            info = connection.send_request(method, path)
            if hasattr(self._nd, "httpapi_logs") and hasattr(connection, "pop_messages"):
                self._nd.httpapi_logs.extend(connection.pop_messages())
        except Exception as exc:
            self._trace("fabric_resolver_onemanage_probe_error", path=path, method=method, error=repr(exc))
            return {}

        status = info.get("status", -1) if isinstance(info, dict) else -1
        body = info.get("body") if isinstance(info, dict) else None
        if status in (200, 201, 202, 204):
            return body
        if status == 404:
            return {}
        if status >= 400:
            message = _response_message(body)
            if message in _FEDERATION_MANAGER_NOT_FOUND_ERRORS or "this API is allowed only for remote user" in message:
                return {}
            return {}
        return body

    def _fetch_fabric_associations(self) -> dict[str, Any]:
        """GET MSD fabric associations and index them by fabric name."""
        path = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/msd/fabric-associations"
        self._trace("fabric_resolver_msd_associations_start", path=path)
        response = self._nd.request(
            path,
            method="GET",
            ignore_not_found_error=True,
        )
        if not response:
            self._trace("fabric_resolver_msd_associations_end", association_count=0)
            return {}

        data = _response_data(response)
        fabric_associations: dict[str, Any] = {}
        for fabric in data if isinstance(data, list) else []:
            if not isinstance(fabric, dict):
                continue
            fabric_name = fabric.get("fabricName")
            if not fabric_name:
                continue
            fabric_associations.setdefault(fabric_name, {})
            fabric_data: dict[str, Any] = {
                "fabricName": fabric_name,
                "fabricType": fabric.get("fabricType"),
                "fabricState": fabric.get("fabricState"),
                "fabricParent": fabric.get("fabricParent"),
            }
            fabric_associations[fabric_name].update(fabric_data)

            if fabric.get("fabricState") == "member":
                fabric_parent = fabric.get("fabricParent")
                if fabric_parent:
                    fabric_associations.setdefault(fabric_parent, {})
                    fabric_associations[fabric_parent].setdefault("members", []).append(fabric_data)

        self._trace("fabric_resolver_msd_associations_end", association_count=len(fabric_associations))
        return fabric_associations

    def _fetch_manage_fabric_details(self, fabric_name: str, cluster_name: str | None = None) -> dict[str, Any]:
        """GET ND Manage fabric details for the target fabric."""
        endpoint = EpManageFabricsGet(fabric_name=fabric_name)
        endpoint.endpoint_params.cluster_name = cluster_name
        self._trace("fabric_resolver_manage_fabric_start", fabric_name=fabric_name, cluster_name=cluster_name, path=endpoint.path)
        response = self._nd.request(
            endpoint.path,
            method=endpoint.verb.value,
            ignore_not_found_error=True,
        )
        data = _response_data(response)
        result = data if isinstance(data, dict) else {}
        self._trace(
            "fabric_resolver_manage_fabric_end",
            fabric_name=fabric_name,
            found=bool(result),
            category=result.get("category"),
            fabric_type=result.get("fabricType") or result.get("type"),
        )
        return result

    def _probe_onemanage_fabric_members(self, fabric_name: str) -> list[dict[str, Any]]:
        """Probe OneManage parent members without failing the resolver."""
        endpoint = EpOneManageFabricsMembersGet(fabric_name=fabric_name)
        self._trace("fabric_resolver_onemanage_members_probe_start", fabric_name=fabric_name, path=endpoint.path)
        response = self._request_onemanage_probe(endpoint.path, endpoint.verb.value)
        members = self._normalize_onemanage_fabric_members(response)
        self._trace("fabric_resolver_onemanage_members_probe_end", fabric_name=fabric_name, member_count=len(members))
        return members

    def _fetch_onemanage_fabric_members(self, fabric_name: str) -> list[dict[str, Any]]:
        """GET OneManage member fabrics for a multicluster parent fabric."""
        endpoint = EpOneManageFabricsMembersGet(fabric_name=fabric_name)
        self._trace("fabric_resolver_onemanage_members_fetch_start", fabric_name=fabric_name, path=endpoint.path)
        response = self._nd.request(
            endpoint.path,
            method=endpoint.verb.value,
            ignore_not_found_error=True,
        )
        members = self._normalize_onemanage_fabric_members(response)
        self._trace("fabric_resolver_onemanage_members_fetch_end", fabric_name=fabric_name, member_count=len(members))
        return members

    def _normalize_onemanage_fabric_members(self, response: Any) -> list[dict[str, Any]]:
        """Normalize OneManage members response shapes into member dicts."""
        data = _response_data(response)
        raw_members: list[Any] = []
        if isinstance(data, list):
            raw_members = data
        elif isinstance(data, dict):
            for key in ("fabrics", "members", "items", "data", "DATA"):
                members = data.get(key)
                if isinstance(members, list):
                    raw_members = members
                    break

        normalized_members: list[dict[str, Any]] = []
        for member in raw_members:
            if not isinstance(member, dict):
                continue
            fabric_name_value = member.get("fabricName") or member.get("name")
            if not fabric_name_value:
                continue
            normalized = dict(member)
            normalized["fabricName"] = fabric_name_value
            normalized.setdefault("fabricState", "member")
            normalized.setdefault("fabricType", member.get("fabricType") or member.get("type"))
            normalized_members.append(normalized)
        return normalized_members

    def _resolve_member_fabric_type(self, msd_fabric_data: dict[str, Any]) -> tuple[str, dict]:
        """Resolve member fabrics using the parent OneManage members list."""
        parent_fabric = msd_fabric_data.get("fabricParent")
        if parent_fabric:
            for member in self._probe_onemanage_fabric_members(parent_fabric):
                if member.get("fabricName") == self.fabric_name:
                    resolved = dict(msd_fabric_data)
                    resolved.update(member)
                    resolved["fabricParent"] = parent_fabric
                    self._trace("fabric_resolver_member_type_resolved", fabric_name=self.fabric_name, fabric_type="multicluster_child")
                    return "multicluster_child", resolved
        self._trace("fabric_resolver_member_type_resolved", fabric_name=self.fabric_name, fabric_type="multisite_child")
        return "multisite_child", msd_fabric_data

    def _enrich_with_manage_fabric_details(self, fabric_data: dict) -> dict:
        """Add management type and member details when available."""
        enriched = dict(fabric_data or {})
        try:
            details = self._fetch_manage_fabric_details(self.fabric_name, enriched.get("clusterName"))
        except Exception:
            details = {}

        management = details.get("management") if isinstance(details, dict) else {}
        if isinstance(management, dict):
            management_type = management.get("type")
            if management_type:
                enriched[self.resource_type_key] = management_type
                enriched["managementType"] = management_type
        if details:
            enriched["manageFabricDetails"] = details
        if enriched.get("fabricType") == "MFD":
            enriched["onemanageProxyPath"] = _nd_onemanage_proxy(self._nd.version or "")
            try:
                members = self._fetch_onemanage_fabric_members(self.fabric_name)
            except Exception:
                members = []
            if members:
                enriched.setdefault("members", members)
                enriched["manageFabricMembers"] = members
        return enriched

    def _resolve_fabric_type(self) -> tuple[str, dict]:
        """Run association-first detection with OneManage disambiguation."""
        msd_fabric_type = None
        msd_fabric_data = None
        try:
            msd_data = self._fetch_fabric_associations()
            msd_fabric_type, msd_fabric_data = _detect_fabric_type(self.fabric_name, msd_data, "msd")
        except Exception:
            pass

        try:
            fabric_details = self._fetch_manage_fabric_details(self.fabric_name)
        except Exception:
            fabric_details = {}

        if msd_fabric_data and msd_fabric_data.get("fabricState") == "member":
            return self._resolve_member_fabric_type(msd_fabric_data)

        if fabric_details and fabric_details.get("category") != "fabricGroup":
            if msd_fabric_type and msd_fabric_type != "standalone":
                return msd_fabric_type, msd_fabric_data
            return "standalone", {
                "fabricName": self.fabric_name,
                "fabricType": fabric_details.get("fabricType") or fabric_details.get("type"),
                "fabricState": fabric_details.get("fabricState") or "active",
            }

        try:
            fed_data = self._fetch_federated_fabric_associations(fabric_details)
            if fed_data != self._NO_FEDERATION_MANAGER:
                fabric_type, fabric_data = _detect_fabric_type(self.fabric_name, fed_data, "mcfg")
                if fabric_type:
                    return fabric_type, fabric_data
        except Exception:
            pass

        if msd_fabric_type:
            return msd_fabric_type, msd_fabric_data

        raise ValueError(f"Fabric '{self.fabric_name}' not found in any NDFC fabric associations. Verify the fabric name and ND connectivity.")

    def _build_strategy(self, fabric_type: str, fabric_data: dict) -> Any:
        """Instantiate the strategy that matches ``fabric_type``."""
        common = dict(fabric_name=self.fabric_name, fabric_data=fabric_data)

        if fabric_type == "multicluster_parent" and self.multicluster_parent_strategy_cls is not None:
            self._trace("fabric_resolver_strategy_build", fabric_type=fabric_type, strategy=self.multicluster_parent_strategy_cls.__name__)
            return self.multicluster_parent_strategy_cls(**common)
        if fabric_type == "multisite_parent" and self.multisite_parent_strategy_cls is not None:
            self._trace("fabric_resolver_strategy_build", fabric_type=fabric_type, strategy=self.multisite_parent_strategy_cls.__name__)
            return self.multisite_parent_strategy_cls(**common)
        if fabric_type == "multicluster_child" and self.child_strategy_cls is not None:
            self._trace("fabric_resolver_strategy_build", fabric_type=fabric_type, strategy=self.child_strategy_cls.__name__)
            return self.child_strategy_cls(cluster_name=fabric_data.get("clusterName"), **common)
        if fabric_type == "multisite_child" and self.child_strategy_cls is not None:
            self._trace("fabric_resolver_strategy_build", fabric_type=fabric_type, strategy=self.child_strategy_cls.__name__)
            return self.child_strategy_cls(**common)
        if self.standalone_strategy_cls is None:
            raise ValueError("standalone_strategy_cls is not configured")
        self._trace("fabric_resolver_strategy_build", fabric_type=fabric_type, strategy=self.standalone_strategy_cls.__name__)
        return self.standalone_strategy_cls(**common)

    @classmethod
    def strategy_from_fabric_details(cls, fabric_name: str, fabric_details: dict) -> Any:
        """
        Build a strategy from normalized or raw fabric details without API calls.
        """
        cluster_name = fabric_details.get("cluster_name") or fabric_details.get("clusterName")
        kwargs: dict = dict(fabric_name=fabric_name, fabric_data=fabric_details)

        ft_internal = fabric_details.get("fabric_type")
        if ft_internal:
            if ft_internal == "multicluster_child" and cls.child_strategy_cls is not None:
                return cls.child_strategy_cls(cluster_name=cluster_name, **kwargs)
            if ft_internal == "multisite_child" and cls.child_strategy_cls is not None:
                return cls.child_strategy_cls(**kwargs)
            if ft_internal == "multicluster_parent" and cls.multicluster_parent_strategy_cls is not None:
                return cls.multicluster_parent_strategy_cls(**kwargs)
            if ft_internal == "multisite_parent" and cls.multisite_parent_strategy_cls is not None:
                return cls.multisite_parent_strategy_cls(**kwargs)
            if cls.standalone_strategy_cls is not None:
                return cls.standalone_strategy_cls(**kwargs)

        fabric_type_api = fabric_details.get("fabricType", "")
        fabric_state = fabric_details.get("fabricState", "")
        if fabric_type_api == "MFD" and cls.multicluster_parent_strategy_cls is not None:
            return cls.multicluster_parent_strategy_cls(**kwargs)
        if fabric_type_api == "MSD" and cls.multisite_parent_strategy_cls is not None:
            return cls.multisite_parent_strategy_cls(**kwargs)
        if fabric_state == "member" and cls.child_strategy_cls is not None:
            return cls.child_strategy_cls(cluster_name=cluster_name, **kwargs)
        if cls.standalone_strategy_cls is None:
            raise ValueError("standalone_strategy_cls is not configured")
        return cls.standalone_strategy_cls(**kwargs)
