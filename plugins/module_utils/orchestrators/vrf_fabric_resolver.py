# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
VrfFabricResolver — Dynamically selects the correct VRF strategy based on
the fabric type returned by the ND Manage API.

This consolidates the action plugin's fabric-type detection and workflow
routing into a single, testable, reusable component under the orchestrator
layer.

Detection algorithm (mirrors dcnm_vrf action plugin logic):
 1. Query federated fabric associations (MFD / "mcfg" scope).
 2. If federation manager absent, fall back to MSD associations.
 3. Classify the target fabric:
      multicluster_parent, multicluster_child,
      multisite_parent,    multisite_child,
      standalone
 4. Return the matching concrete strategy instance.
"""


from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_vrf import (
    BaseVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import (
    StandaloneVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_vrf import (
    MultisiteParentVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_vrf import (
    MulticlusterParentVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.child_vrf import (
    ChildVrfStrategy,
)


# ---------------------------------------------------------------------------
# Module-level constants and helpers
# ---------------------------------------------------------------------------

# Error messages returned by the NDFC federated-fabrics API when the site is
# not part of a federation (standalone or MSD-only deployments).  Mirrors
# FEDERATION_MANAGER_NOT_FOUND_ERRORS in the dcnm_vrf action plugin.
_FEDERATION_MANAGER_NOT_FOUND_ERRORS: frozenset[str] = frozenset([
    "A federation manager does not exist",
    "Invalid JSON response: this API is allowed only for remote user",
    "Invalid JSON response: cannot serve APIs as federation state is secondary. "
    "Use primary cluster for APIs",
    "Invalid JSON response: cannot serve APIs as federation state is not established yet",
])


def _nd_onemanage_proxy(version_str: str) -> str:
    """
    Return ``'/onemanage'`` for ND >= 3.2 (NDFC >= 12.4) where the NDFC API
    is accessed via the onemanage proxy, otherwise return ``''``.

    ``NDModule.version`` returns a string built from major.minor.maintenance
    (e.g. "3.2.1"), so we compare against ND version numbers, not NDFC ones.
    Mirrors the ``ndfc_version >= 12.4`` check in the dcnm_vrf action plugin.
    Defaults to the proxy path for unknown/unparseable versions since
    NDBR-VRF targets modern ND deployments.
    """
    try:
        parts = str(version_str).split(".")
        major, minor = int(parts[0]), int(parts[1])
        if major > 3 or (major == 3 and minor >= 2):
            return "/onemanage"
        return ""
    except (ValueError, IndexError, AttributeError):
        return "/onemanage"  # default: assume modern ND deployment


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

class VrfFabricResolver:
    """
    Resolves the correct VRF strategy for a given fabric name by querying
    fabric association data from the ND controller.

    Usage
    -----
    resolver = VrfFabricResolver(nd_module=nd_module, fabric_name="fab1")
    strategy = resolver.resolve()
    # strategy is now e.g. MultisiteParentVrfStrategy(fabric_name="fab1", ...)
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

    def resolve(self) -> BaseVrfStrategy:
        """
        Query ND for fabric associations and return the matching strategy.

        Raises:
            ValueError: If the fabric is not found in any association data.
        """
        fabric_type, fabric_data = self._resolve_fabric_type()
        fabric_data = self._enrich_with_manage_fabric_details(fabric_data)
        return self._build_strategy(fabric_type, fabric_data)

    # ── Internal helpers ───────────────────────────────────────────

    def _fetch_federated_fabric_associations(self) -> Any:
        """
        GET federated fabric associations (multicluster / MFD scope).

        Calls the NDFC onemanage fabrics endpoint through ND's REST proxy:
            GET {proxy}/appcenter/cisco/ndfc/api/v1/onemanage/fabrics

        where {proxy} is '/onemanage' for ND >= 3.2 (NDFC >= 12.4) and ''
        for older releases.  Mirrors ``obtain_federated_fabric_associations``
        from the dcnm_vrf action plugin.

        Returns:
            dict: Mapping of fabricName -> fabric properties dict (including
                  a ``members`` list for parent fabrics).
            str:  ``_NO_FEDERATION_MANAGER`` sentinel when the site is not
                  part of a federation (standalone or MSD-only deployments).
        """
        proxy = _nd_onemanage_proxy(self._nd.version or "")
        path = f"{proxy}/appcenter/cisco/ndfc/api/v1/onemanage/fabrics"

        response = self._nd.request(
            path,
            method="GET",
            ignore_not_found_error=True,
        )

        # Empty / falsy response: API unavailable or returned an HTTP error.
        # Treat as "no federation manager" so Phase 2 takes over.
        if not response:
            return self._NO_FEDERATION_MANAGER

        # The NDFC API sometimes returns HTTP 200 with an error string
        # (e.g. "A federation manager does not exist").  Detect those here.
        data = _response_data(response)
        if isinstance(data, str):
            if data in _FEDERATION_MANAGER_NOT_FOUND_ERRORS:
                return self._NO_FEDERATION_MANAGER
            # Any other unexpected string in DATA: fall back to Phase 2.
            return self._NO_FEDERATION_MANAGER

        # Build fabricName -> fabric_data mapping from the DATA list.
        # Each entry may contain a nested ``members`` list for parent fabrics.
        # Mirrors the dict-building loop in obtain_federated_fabric_associations.
        fabric_associations: dict[str, Any] = {}
        for fabric in (data if isinstance(data, list) else []):
            if not isinstance(fabric, dict):
                continue
            parent_name = fabric.get("fabricName")
            if not parent_name:
                continue
            parent_entry: dict[str, Any] = {
                "fabricName": parent_name,
                "fabricType": fabric.get("fabricType"),
                "fabricState": fabric.get("fabricState"),
            }
            fabric_associations[parent_name] = parent_entry
            for child in fabric.get("members", []):
                if not isinstance(child, dict):
                    continue
                child_name = child.get("fabricName")
                if not child_name:
                    continue
                child_entry: dict[str, Any] = {
                    "fabricName": child_name,
                    "clusterName": child.get("clusterName"),
                    "fabricType": child.get("fabricType"),
                    "fabricState": child.get("fabricState"),
                }
                fabric_associations[child_name] = child_entry
                parent_entry.setdefault("members", []).append(child_entry)

        return fabric_associations

    def _fetch_fabric_associations(self) -> dict[str, Any]:
        """
        GET MSD fabric associations (MSD / standalone scope).

        Mirrors ``obtain_fabric_associations`` from the dcnm_vrf action plugin.

        API:
            GET /appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/fabrics/msd/fabric-associations

        The response DATA is a flat list of all fabrics.  Each entry carries:
            fabricName, fabricType, fabricState, fabricParent (for member fabrics)

        The dict returned maps fabricName -> fabric properties, with a ``members``
        list added to parent fabric entries so _detect_fabric_type can walk it.
        """
        path = (
            "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/control/"
            "fabrics/msd/fabric-associations"
        )
        response = self._nd.request(
            path,
            method="GET",
            ignore_not_found_error=True,
        )
        if not response:
            return {}

        data = _response_data(response)
        fabric_associations: dict[str, Any] = {}
        for fabric in (data if isinstance(data, list) else []):
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
                    fabric_associations[fabric_parent].setdefault("members", []).append(
                        fabric_data
                    )

        return fabric_associations

    def _fetch_manage_fabric_details(
        self, fabric_name: str, cluster_name: str | None = None
    ) -> dict[str, Any]:
        """
        GET ND Manage fabric details for the target fabric.

        The fabric-association APIs used for topology routing expose MSD/MFD
        relationship data but not the VRF schema discriminator to use when
        creating a VRF.  The Manage fabric details API includes
        ``management.type`` (for example ``vxlanIbgp`` or ``vxlanEbgp``),
        which maps to the default VRF ``vrfType`` for standard VRF creates.
        """
        path = f"/api/v1/manage/fabrics/{fabric_name}"
        response = self._nd.request(
            path,
            method="GET",
            qs={"clusterName": cluster_name} if cluster_name else None,
            ignore_not_found_error=True,
        )
        data = _response_data(response)
        return data if isinstance(data, dict) else {}

    def _enrich_with_manage_fabric_details(self, fabric_data: dict) -> dict:
        """
        Add ``vrfType`` and Manage fabric details to fabric_data when available.

        Failures are intentionally non-fatal: topology resolution has already
        succeeded, and the VRF payload transformer can still fall back to the
        historical VXLAN iBGP default if details are unavailable.
        """
        enriched = dict(fabric_data or {})
        try:
            details = self._fetch_manage_fabric_details(
                self.fabric_name, enriched.get("clusterName")
            )
        except Exception:
            details = {}

        management = details.get("management") if isinstance(details, dict) else {}
        if isinstance(management, dict):
            vrf_type = management.get("type")
            if vrf_type:
                enriched["vrfType"] = vrf_type
                enriched["managementType"] = vrf_type
        if details:
            enriched["manageFabricDetails"] = details
        return enriched

    def _resolve_fabric_type(self) -> tuple[str, dict]:
        """
        Run the two-phase detection logic (mcfg → msd fallback).

        Phase 1: Try federated (MFD / "mcfg") associations.
        Phase 2: Fall back to MSD associations if Phase 1 fails or the
                 fabric is not classified by mcfg data.

        Returns:
            (fabric_type_string, raw_fabric_data_dict)

        Raises:
            ValueError if the fabric cannot be found in any data source.
        """
        # Phase 1 — federated (MFD / "mcfg")
        # Mirrors the action plugin: if Phase 1 returns the sentinel string
        # or fails for any reason, fall straight through to Phase 2.
        try:
            fed_data = self._fetch_federated_fabric_associations()
            if fed_data != self._NO_FEDERATION_MANAGER:
                fabric_type, fabric_data = _detect_fabric_type(
                    self.fabric_name, fed_data, "mcfg"
                )
                if fabric_type:
                    return fabric_type, fabric_data
                # Fabric present but unclassified by mcfg — fall through to Phase 2
        except Exception:
            # Phase 1 unavailable or failed; fall straight through to Phase 2
            pass

        # Phase 2 — MSD associations
        msd_data = self._fetch_fabric_associations()
        fabric_type, fabric_data = _detect_fabric_type(
            self.fabric_name, msd_data, "msd"
        )
        if not fabric_type:
            raise ValueError(
                f"Fabric '{self.fabric_name}' not found in any NDFC fabric "
                "associations. Verify the fabric name and ND connectivity."
            )
        return fabric_type, fabric_data

    def _build_strategy(self, fabric_type: str, fabric_data: dict) -> BaseVrfStrategy:
        """Instantiate and return the strategy that matches fabric_type."""
        common = dict(
            fabric_name=self.fabric_name,
            fabric_data=fabric_data,
        )

        if fabric_type == "multicluster_parent":
            return MulticlusterParentVrfStrategy(**common)
        elif fabric_type == "multisite_parent":
            return MultisiteParentVrfStrategy(**common)
        elif fabric_type == "multicluster_child":
            return ChildVrfStrategy(
                cluster_name=fabric_data.get("clusterName"), **common
            )
        elif fabric_type == "multisite_child":
            return ChildVrfStrategy(**common)
        else:
            # "standalone" and any unrecognised value
            return StandaloneVrfStrategy(**common)

    # ── Fast-path strategy builder (no API call) ───────────────────

    @staticmethod
    def strategy_from_fabric_details(
        fabric_name: str, fabric_details: dict
    ) -> BaseVrfStrategy:
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
                return ChildVrfStrategy(cluster_name=cluster_name, **kwargs)
            elif ft_internal == "multisite_child":
                return ChildVrfStrategy(**kwargs)
            elif ft_internal == "multicluster_parent":
                return MulticlusterParentVrfStrategy(**kwargs)
            elif ft_internal == "multisite_parent":
                return MultisiteParentVrfStrategy(**kwargs)
            else:
                return StandaloneVrfStrategy(**kwargs)

        # Raw ND API form: classify from fabricType / fabricState.
        fabric_type_api = fabric_details.get("fabricType", "")
        fabric_state = fabric_details.get("fabricState", "")

        if fabric_type_api == "MFD":
            return MulticlusterParentVrfStrategy(**kwargs)
        elif fabric_type_api == "MSD":
            return MultisiteParentVrfStrategy(**kwargs)
        elif fabric_state == "member":
            # Member fabric: clusterName present → multicluster child.
            return ChildVrfStrategy(cluster_name=cluster_name, **kwargs)
        else:
            return StandaloneVrfStrategy(**kwargs)
