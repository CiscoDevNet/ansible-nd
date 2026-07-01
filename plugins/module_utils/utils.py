# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Set

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_config_save import (
    EpFabricConfigSavePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_deploy import (
    EpFabricDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


def sanitize_dict(dict_to_sanitize, keys=None, values=None, recursive=True, remove_none_values=True):
    if keys is None:
        keys = []
    if values is None:
        values = []

    result = deepcopy(dict_to_sanitize)
    for k, v in dict_to_sanitize.items():
        if k in keys:
            del result[k]
        elif v in values or (v is None and remove_none_values):
            del result[k]
        elif isinstance(v, dict) and recursive:
            result[k] = sanitize_dict(v, keys, values)
        elif isinstance(v, list) and recursive:
            for index, item in enumerate(v):
                if isinstance(item, dict):
                    result[k][index] = sanitize_dict(item, keys, values)
    return result


def _has_perfect_matching(adjacency: List[List[int]]) -> bool:
    """Return True if every subset item can be matched to a distinct candidate.

    ``adjacency[i]`` holds the indices of the candidates that subset item ``i``
    can match. This solves the maximum bipartite matching problem with Kuhn's
    augmenting-path algorithm so that a less-specific item never greedily
    consumes a candidate that a more-specific item needs.
    """
    # candidate index -> subset item index it is currently assigned to
    match_to_item: Dict[int, int] = {}

    def _try_assign(item_index: int, visited: Set[int]) -> bool:
        for candidate_index in adjacency[item_index]:
            if candidate_index in visited:
                continue
            visited.add(candidate_index)
            assigned_item = match_to_item.get(candidate_index)
            # Candidate is free, or its current owner can be reassigned elsewhere.
            if assigned_item is None or _try_assign(assigned_item, visited):
                match_to_item[candidate_index] = item_index
                return True
        return False

    for item_index in range(len(adjacency)):
        if not _try_assign(item_index, set()):
            return False
    return True


def issubset(subset: Any, superset: Any, allow_superset: bool = False) -> bool:
    """Check if subset is contained in superset.

    For dicts, only the non-``None`` keys of ``subset`` are compared; keys whose
    value is ``None`` are ignored, and keys present only in ``superset`` are
    allowed. For lists, every ``subset`` element must pair with a distinct
    ``superset`` element (matching is order-independent). By default the two
    lists must be the same length; when ``allow_superset`` is True the
    ``subset`` list may be shorter so that extra existing elements are
    tolerated (``len(subset) <= len(superset)``).

    Args:
        subset: The value to check.
        superset: The value to check against.
        allow_superset: When True, list matching is one-directional: an element
            in ``subset`` is considered matched when it is a subset of a
            candidate in ``superset``, even if the candidate has additional
            keys, and ``superset`` may contain extra elements that ``subset``
            does not (``len(subset) <= len(superset)``). When False (default)
            matching is bidirectional and the lengths must be equal. For lists
            of dicts the default is equivalent to equality *after* ``None``
            -valued keys are dropped from both sides (it is not strict ``==``
            equality, because such keys are ignored).
    """
    if type(subset) is not type(superset):
        return False

    if not isinstance(subset, dict):
        if isinstance(subset, list):
            # Under allow_superset the proposed list only needs to map into the
            # existing one, so extra existing elements are tolerated
            # (len(subset) <= len(superset)). Otherwise matching is
            # bidirectional and the lengths must be identical.
            if allow_superset:
                if len(subset) > len(superset):
                    return False
            elif len(subset) != len(superset):
                return False

            # Build the bipartite adjacency: for each subset item, which
            # candidates it can match. A full matching is then required so a
            # less-specific item cannot greedily consume a candidate that a
            # more-specific item needs (relevant under allow_superset=True).
            adjacency: List[List[int]] = []
            for item in subset:
                matches = []
                for index, candidate in enumerate(superset):
                    if allow_superset:
                        match = issubset(item, candidate, allow_superset=True)
                    else:
                        match = issubset(item, candidate) and issubset(candidate, item)
                    if match:
                        matches.append(index)
                if not matches:
                    return False
                adjacency.append(matches)

            return _has_perfect_matching(adjacency)
        return subset == superset

    for key, value in subset.items():
        if value is None:
            continue

        if key not in superset:
            return False

        if not issubset(value, superset[key], allow_superset=allow_superset):
            return False

    return True


def remove_unwanted_keys(data: dict, unwanted_keys: list[str | list[str]]) -> dict:
    """Remove unwanted keys from dict (supports nested paths)."""
    data = deepcopy(data)

    for key in unwanted_keys:
        if isinstance(key, str):
            if key in data:
                del data[key]

        elif isinstance(key, list) and len(key) > 0:
            try:
                parent = data
                for k in key[:-1]:
                    if isinstance(parent, dict) and k in parent:
                        parent = parent[k]
                    else:
                        break
                else:
                    if isinstance(parent, dict) and key[-1] in parent:
                        del parent[key[-1]]
            except (KeyError, TypeError, IndexError):
                pass

    return data


def register_action_api_call(
    results: Any,
    request_path: str,
    payload: dict[str, Any],
    return_code: int | None,
    message: str,
    success: bool,
    changed: bool,
    method: str = "POST",
) -> None:
    """
    Register a single save/deploy API call into a Results instance.

    Keeps response/result shape consistent across modules that use Allen's
    Results Framework.
    """
    results.response_current = {
        "RETURN_CODE": return_code if return_code is not None else -1,
        "METHOD": method,
        "REQUEST_PATH": request_path,
        "MESSAGE": message,
        "DATA": payload,
    }
    results.result_current = {"success": success, "changed": changed}
    results.register_api_call()


class FabricUtils:
    """
    Shared helper for fabric-level config save/deploy actions.
    """

    def __init__(self, nd_module: Any, fabric_name: str) -> None:
        self.nd = nd_module
        self.fabric_name = fabric_name

    @staticmethod
    def build_config_save_path(fabric_name: str) -> str:
        """
        Build /actions/configSave endpoint path for the given fabric.
        """
        endpoint = EpFabricConfigSavePost(fabric_name=fabric_name)
        return endpoint.path

    @staticmethod
    def build_config_deploy_path(fabric_name: str, force_show_run: bool = True) -> str:
        """
        Build /actions/deploy endpoint path for the given fabric.
        """
        endpoint = EpFabricDeployPost(fabric_name=fabric_name)
        path = endpoint.path
        if force_show_run:
            separator = "&" if "?" in path else "?"
            path = f"{path}{separator}forceShowRun=true"
        return path

    @property
    def config_save_path(self) -> str:
        return self.build_config_save_path(self.fabric_name)

    def config_deploy_path(self, force_show_run: bool = True) -> str:
        return self.build_config_deploy_path(self.fabric_name, force_show_run=force_show_run)

    def save_config(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Call fabric config-save action.
        """
        path = self.config_save_path
        response_data = self.nd.request(path, HttpVerbEnum.POST, payload)
        return {
            "path": path,
            "status": self.nd.status,
            "response_data": response_data,
        }

    def deploy_config(self, payload: dict[str, Any], force_show_run: bool = True) -> dict[str, Any]:
        """
        Call fabric deploy action.
        """
        path = self.config_deploy_path(force_show_run=force_show_run)
        response_data = self.nd.request(path, HttpVerbEnum.POST, payload)
        return {
            "path": path,
            "status": self.nd.status,
            "response_data": response_data,
        }
