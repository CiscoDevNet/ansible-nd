# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
NetworkFabricResolver — Dynamically selects the correct Network strategy based on
the fabric type returned by the ND Manage API.

This consolidates fabric-type detection and workflow routing into a single,
testable, reusable component under the orchestrator layer.

Detection algorithm:
 1. Query Manage MSD fabric associations. This covers standalone, MSD parent,
    and MSD child fabrics without touching OneManage.
 2. If the target fabric is not present there, probe the OneManage MCFG
    resource surface.
 3. Classify the target fabric:
      multicluster_parent, multicluster_child,
      multisite_parent,    multisite_child,
      standalone
 4. Return the matching concrete strategy instance.
"""

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricsGet,
    EpManageFabricsMembersGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics import (
    EpOneManageFabricsMembersGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics_networks import (
    EpOneManageFabricsNetworksGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_network import (
    BaseNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import (
    StandaloneNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_network import (
    MultisiteParentNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_network import (
    MulticlusterParentNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.child_network import (
    ChildNetworkStrategy,
)

# ---------------------------------------------------------------------------
# Module-level constants and helpers
# ---------------------------------------------------------------------------

# Error messages returned by the NDFC federated-fabrics API when the site is
# not part of a federation (standalone or MSD-only deployments).
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

    The OneManage OpenAPI server is ``/api/v1/oneManage``.  Resource paths
    in this module are built directly from that server root and must not be
    routed through an additional proxy prefix.
    """
    return ""


def _response_data(response: Any) -> Any:
    """
    Return the data payload from either NDModule.request() or RestSend-style
    response wrappers.

    ``NDModule.request()`` returns the response body directly.  For the NDFC
    fabric association endpoints that body is commonly a list.  Some newer
    helpers return a wrapper dict with a ``DATA`` key, so accept both shapes.
    """
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


# ---------------------------------------------------------------------------
# Internal fabric-type detection helper
# ---------------------------------------------------------------------------


def _detect_fabric_type(
    fabric_name: str,
    fabric_associations: dict[str, Any],
    data_type: str,
) -> tuple[str | None, dict | None]:
    """
    Classify a fabric based on its properties in the fabric associations dict.

    Args:
        fabric_name: The fabric to classify.
        fabric_associations: Mapping of fabricName → fabric properties dict.
        data_type: "mcfg" for federated (MFD) data, "msd" for MSD data.

    Returns:
        (fabric_type_str, fabric_data_dict) or (None, None) if not found.
    """
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
            # Standalone: not MSD, not MFD, not a member
            detected_type = "standalone"

    return detected_type, fabric_data


# ---------------------------------------------------------------------------
# Public resolver
# ---------------------------------------------------------------------------


class NetworkFabricResolver:
    """
    Resolves the correct Network strategy for a given fabric name by querying
    fabric association data from the ND controller.

    Usage
    -----
    resolver = NetworkFabricResolver(nd_module=nd_module, fabric_name="fab1")
    strategy = resolver.resolve()
    # strategy is now e.g. MultisiteParentNetworkStrategy(fabric_name="fab1", ...)
    """

    # Sentinel returned by the ND API when no federation manager is present.
    _NO_FEDERATION_MANAGER = "A federation manager does not exist"

    def __init__(self, nd_module: Any, fabric_name: str):
        """
        Args:
            nd_module: An NDModule instance (provides send/receive to the ND API).
            fabric_name: The fabric whose type should be resolved.
        """
        self._nd = nd_module
        self.fabric_name = fabric_name

    # ── Public API ─────────────────────────────────────────────────

    def resolve(self) -> BaseNetworkStrategy:
        """
        Query ND for fabric associations and return the matching strategy.

        Raises:
            ValueError: If the fabric is not found in any association data.
        """
        fabric_type, fabric_data = self._resolve_fabric_type()
        fabric_data = self._enrich_with_manage_fabric_details(fabric_data)
        return self._build_strategy(fabric_type, fabric_data)

    # ── Internal helpers ───────────────────────────────────────────

    def _fetch_federated_fabric_associations(self, fabric_details: dict[str, Any] | None = None) -> Any:
        """
        Detect whether the fabric is managed through OneManage MCFG.

        ``oneManage.json`` does not expose a fabric-association endpoint.
        The live 4.2 controller returns 404 for ``/api/v1/oneManage/fabrics``.
        After MSD/standalone classification has failed, use the schema-backed
        MCFG resource surface as a bounded probe:
            GET /api/v1/oneManage/manage/fabrics/{fabricName}/networks?max=1

        Returns:
            dict: Mapping of fabricName -> fabric properties dict (including
                  a ``members`` list for parent fabrics).
            str:  ``_NO_FEDERATION_MANAGER`` sentinel when the site is not
                  part of a federation (standalone or MSD-only deployments).
        """
        fabric_details = fabric_details if fabric_details is not None else self._fetch_manage_fabric_details(self.fabric_name)
        if fabric_details.get("category") != "fabricGroup":
            return self._NO_FEDERATION_MANAGER

        endpoint = EpOneManageFabricsNetworksGet(fabric_name=self.fabric_name)
        endpoint.endpoint_params.max = 1

        response = self._request_onemanage_probe(endpoint.path, endpoint.verb.value)

        # Empty / falsy response: API unavailable or returned an HTTP error.
        # Treat as "no OneManage resource surface" so Phase 2 takes over.
        if not response:
            return self._NO_FEDERATION_MANAGER

        data = _response_data(response)
        if isinstance(data, str):
            if data in _FEDERATION_MANAGER_NOT_FOUND_ERRORS:
                return self._NO_FEDERATION_MANAGER
            return self._NO_FEDERATION_MANAGER

        return {
            self.fabric_name: {
                "fabricName": self.fabric_name,
                "fabricType": "MFD",
                "fabricState": "active",
            }
        }

    def _request_onemanage_probe(self, path: str, method: str) -> Any:
        """
        Call the OneManage resource probe without letting HTTP errors abort the module.

        ``NDModule.request()`` converts non-2xx responses into ``fail_json``.
        For fabric detection, OneManage probe errors are expected on standalone
        and MSD-only controllers, so use the lower-level connection response and
        return an empty result for known "not MCFG" failures.
        """
        connection = getattr(self._nd, "connection", None)
        if connection is None:
            return self._nd.request(path, method=method, ignore_not_found_error=True)

        try:
            info = connection.send_request(method, path)
            if hasattr(self._nd, "httpapi_logs") and hasattr(connection, "pop_messages"):
                self._nd.httpapi_logs.extend(connection.pop_messages())
        except Exception:
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
        """
        GET MSD fabric associations (MSD / standalone scope).

        API:
            GET /appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/msd/fabric-associations

        The response DATA is a flat list of all fabrics.  Each entry carries:
            fabricName, fabricType, fabricState, fabricParent (for member fabrics)

        The dict returned maps fabricName -> fabric properties, with a ``members``
        list added to parent fabric entries so _detect_fabric_type can walk it.
        """
        path = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/msd/fabric-associations"
        response = self._nd.request(
            path,
            method="GET",
            ignore_not_found_error=True,
        )
        if not response:
            return {}

        data = _response_data(response)
        fabric_associations: dict[str, Any] = {}
        for fabric in data if isinstance(data, list) else []:
            if not isinstance(fabric, dict):
                continue
            fabric_name = fabric.get("fabricName")
            if not fabric_name:
                continue
            if fabric_name not in fabric_associations:
                fabric_associations[fabric_name] = {}
            fabric_data: dict[str, Any] = {
                "fabricName": fabric_name,
                "fabricType": fabric.get("fabricType"),
                "fabricState": fabric.get("fabricState"),
            }
            fabric_associations[fabric_name].update(fabric_data)

            # Build the members list on the parent entry so the coordinator
            # can resolve child strategies without extra API calls.
            if fabric.get("fabricState") == "member":
                fabric_parent = fabric.get("fabricParent")
                if fabric_parent:
                    if fabric_parent not in fabric_associations:
                        fabric_associations[fabric_parent] = {}
                    fabric_associations[fabric_parent].setdefault("members", []).append(fabric_data)

        return fabric_associations

    def _fetch_manage_fabric_details(self, fabric_name: str, cluster_name: str | None = None) -> dict[str, Any]:
        """
        GET ND Manage fabric details for the target fabric.

        The fabric-association APIs used for topology routing expose MSD/MFD
        relationship data but not the Network schema discriminator to use when
        creating a Network.  The Manage fabric details API includes
        ``management.type`` (for example ``vxlanIbgp`` or ``vxlanEbgp``),
        which maps to the default Network ``networkType`` for standard Network creates.
        """
        endpoint = EpManageFabricsGet(fabric_name=fabric_name)
        endpoint.endpoint_params.cluster_name = cluster_name
        response = self._nd.request(
            endpoint.path,
            method=endpoint.verb.value,
            ignore_not_found_error=True,
        )
        data = _response_data(response)
        return data if isinstance(data, dict) else {}

    def _fetch_manage_fabric_members(self, fabric_name: str, cluster_name: str | None = None) -> list[dict[str, Any]]:
        """
        GET ND Manage member fabrics for a multicluster parent fabric.

        This is used only as an additive MCFG enrichment; standalone and MSD
        routing continue to use the existing association data.
        """
        endpoint = EpManageFabricsMembersGet(fabric_name=fabric_name)
        endpoint.endpoint_params.cluster_name = cluster_name
        response = self._nd.request(
            endpoint.path,
            method=endpoint.verb.value,
            ignore_not_found_error=True,
        )
        data = _response_data(response)
        if isinstance(data, list):
            return [member for member in data if isinstance(member, dict)]
        if isinstance(data, dict):
            for key in ("members", "items", "data", "DATA"):
                members = data.get(key)
                if isinstance(members, list):
                    return [member for member in members if isinstance(member, dict)]
        return []

    def _fetch_onemanage_fabric_members(self, fabric_name: str) -> list[dict[str, Any]]:
        """
        GET OneManage member fabrics for a multicluster parent fabric.

        API:
            GET /api/v1/oneManage/manage/fabrics/{fabricName}/members
        """
        endpoint = EpOneManageFabricsMembersGet(fabric_name=fabric_name)
        response = self._nd.request(
            endpoint.path,
            method=endpoint.verb.value,
            ignore_not_found_error=True,
        )
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

    def _enrich_with_manage_fabric_details(self, fabric_data: dict) -> dict:
        """
        Add ``networkType`` and Manage fabric details to fabric_data when available.

        Failures are intentionally non-fatal: topology resolution has already
        succeeded, and the Network payload transformer can still fall back to the
        historical VXLAN iBGP default if details are unavailable.
        """
        enriched = dict(fabric_data or {})
        try:
            details = self._fetch_manage_fabric_details(self.fabric_name, enriched.get("clusterName"))
        except Exception:
            details = {}

        management = details.get("management") if isinstance(details, dict) else {}
        if isinstance(management, dict):
            network_type = management.get("type")
            if network_type:
                enriched["networkType"] = network_type
                enriched["managementType"] = network_type
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
        """
        Run the two-phase detection logic (Manage/MSD → MCFG fallback).

        Phase 1: Try Manage MSD associations, which classify standalone, MSD
                 parent, and MSD child fabrics without OneManage.
        Phase 2: Fall back to the OneManage MCFG resource probe only if the
                 fabric is not classified by Phase 1.

        Returns:
            (fabric_type_string, raw_fabric_data_dict)

        Raises:
            ValueError if the fabric cannot be found in any data source.
        """
        # Phase 1 — Manage MSD / standalone association data.
        try:
            msd_data = self._fetch_fabric_associations()
            fabric_type, fabric_data = _detect_fabric_type(self.fabric_name, msd_data, "msd")
            if fabric_type:
                return fabric_type, fabric_data
        except Exception:
            pass

        try:
            fabric_details = self._fetch_manage_fabric_details(self.fabric_name)
        except Exception:
            fabric_details = {}

        if fabric_details and fabric_details.get("category") != "fabricGroup":
            return "standalone", {
                "fabricName": self.fabric_name,
                "fabricType": fabric_details.get("fabricType") or fabric_details.get("type"),
                "fabricState": fabric_details.get("fabricState") or "active",
            }

        # Phase 2 — federated MCFG fallback.
        try:
            fed_data = self._fetch_federated_fabric_associations(fabric_details)
            if fed_data != self._NO_FEDERATION_MANAGER:
                fabric_type, fabric_data = _detect_fabric_type(self.fabric_name, fed_data, "mcfg")
                if fabric_type:
                    return fabric_type, fabric_data
                # Fabric present but unclassified by mcfg — fail below.
        except Exception:
            pass

        raise ValueError(f"Fabric '{self.fabric_name}' not found in any NDFC fabric " "associations. Verify the fabric name and ND connectivity.")

    def _build_strategy(self, fabric_type: str, fabric_data: dict) -> BaseNetworkStrategy:
        """Instantiate and return the strategy that matches fabric_type."""
        common = dict(
            fabric_name=self.fabric_name,
            fabric_data=fabric_data,
        )

        if fabric_type == "multicluster_parent":
            return MulticlusterParentNetworkStrategy(**common)
        elif fabric_type == "multisite_parent":
            return MultisiteParentNetworkStrategy(**common)
        elif fabric_type == "multicluster_child":
            return ChildNetworkStrategy(cluster_name=fabric_data.get("clusterName"), **common)
        elif fabric_type == "multisite_child":
            return ChildNetworkStrategy(**common)
        else:
            # "standalone" and any unrecognised value
            return StandaloneNetworkStrategy(**common)

    # ── Fast-path strategy builder (no API call) ───────────────────

    @staticmethod
    def strategy_from_fabric_details(fabric_name: str, fabric_details: dict) -> BaseNetworkStrategy:
        """
        Build a strategy from a fabric_details dict, accepting two forms:

        - Internal normalized (snake_case): ``fabric_type`` key with values
          such as ``"multicluster_child"``, ``"multisite_parent"``, etc.
          Set by the coordinator fast-path (no API round-trip needed).

        - Raw ND API member dict (camelCase): ``fabricType`` / ``fabricState``
          / ``clusterName`` keys as returned by the fabric associations
          endpoint and stored in ``strategy.fabric_data["members"]``.
        """
        # Accept cluster_name from either key form.
        cluster_name = fabric_details.get("cluster_name") or fabric_details.get("clusterName")
        kwargs: dict = dict(fabric_name=fabric_name, fabric_data=fabric_details)

        # Internal type string (coordinator fast-path) takes priority.
        ft_internal = fabric_details.get("fabric_type")
        if ft_internal:
            if ft_internal == "multicluster_child":
                return ChildNetworkStrategy(cluster_name=cluster_name, **kwargs)
            elif ft_internal == "multisite_child":
                return ChildNetworkStrategy(**kwargs)
            elif ft_internal == "multicluster_parent":
                return MulticlusterParentNetworkStrategy(**kwargs)
            elif ft_internal == "multisite_parent":
                return MultisiteParentNetworkStrategy(**kwargs)
            else:
                return StandaloneNetworkStrategy(**kwargs)

        # Raw ND API form: classify from fabricType / fabricState.
        fabric_type_api = fabric_details.get("fabricType", "")
        fabric_state = fabric_details.get("fabricState", "")

        if fabric_type_api == "MFD":
            return MulticlusterParentNetworkStrategy(**kwargs)
        elif fabric_type_api == "MSD":
            return MultisiteParentNetworkStrategy(**kwargs)
        elif fabric_state == "member":
            # Member fabric: clusterName present → multicluster child.
            return ChildNetworkStrategy(cluster_name=cluster_name, **kwargs)
        else:
            return StandaloneNetworkStrategy(**kwargs)
