# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from copy import deepcopy
from typing import Any, Dict, List, Optional, Union


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


def issubset(subset: Any, superset: Any) -> bool:
    """Check if subset is contained in superset."""
    if type(subset) is not type(superset):
        return False

    if not isinstance(subset, dict):
        if isinstance(subset, list):
            if len(subset) != len(superset):
                return False

            remaining = list(superset)
            for item in subset:
                for index, candidate in enumerate(remaining):
                    if issubset(item, candidate) and issubset(candidate, item):
                        del remaining[index]
                        break
                else:
                    return False
            return True
        return subset == superset

    for key, value in subset.items():
        if value is None:
            continue

        if key not in superset:
            return False

        if not issubset(value, superset[key]):
            return False

    return True


def remove_unwanted_keys(data: Dict, unwanted_keys: List[Union[str, List[str]]]) -> Dict:
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


class FabricSwitchIndex:
    """Switch lookup helper for any fabric, decoupled from any model class.

    Indexes a fabric's switches by management IP, hostname, and serial number
    so callers can resolve a switch identifier from any of those forms.
    Hostname collisions are tracked as a list so resolve() can fail with a
    clear error instead of guessing.
    """

    IP_KEYS = ("fabricManagementIp", "managementIp", "mgmtIp", "ip")
    NAME_KEYS = ("hostname", "switchName", "name")
    ID_KEYS = ("switchId", "serialNumber", "id")
    SWITCHES_PATH = "/api/v1/manage/fabrics/{0}/switches"

    def __init__(self, raw_switches: Optional[List[Dict[str, Any]]] = None) -> None:
        self.by_ip: Dict[str, str] = {}
        self.by_name: Dict[str, List[str]] = {}
        self.by_id: Dict[str, Dict[str, Optional[str]]] = {}

        for switch in raw_switches or []:
            if not isinstance(switch, dict):
                continue
            switch_id = self._first_present(switch, self.ID_KEYS)
            if not switch_id:
                continue
            ip = self._first_present(switch, self.IP_KEYS)
            name = self._first_present(switch, self.NAME_KEYS)
            if ip:
                self.by_ip[ip] = switch_id
            if name:
                self.by_name.setdefault(name, []).append(switch_id)
            self.by_id[switch_id] = {"name": name, "ip": ip}

    @staticmethod
    def _first_present(data: Dict[str, Any], keys) -> Optional[str]:
        for key in keys:
            value = data.get(key)
            if value:
                return value
        return None

    @classmethod
    def from_fabric(cls, nd, fabric: str, log=None) -> "FabricSwitchIndex":
        path = cls.SWITCHES_PATH.format(fabric)
        try:
            response = nd.request(path, method="GET")
        except Exception as exc:
            if log is not None:
                log.warning("Failed to fetch switches for fabric '%s': %s", fabric, exc)
            return cls([])

        if isinstance(response, list):
            items = response
        elif isinstance(response, dict):
            items = response.get("switches", response.get("items", []))
        else:
            items = []
        return cls(items)

    def resolve(
        self,
        switch_id: Optional[str] = None,
        switch_ip: Optional[str] = None,
        switch_name: Optional[str] = None,
        fabric_name: Optional[str] = None,
        side: str = "",
    ) -> Optional[str]:
        """Priority: switch_id > switch_ip > switch_name. Raises on miss or ambiguous name."""
        if switch_id:
            return switch_id

        side_prefix = "{0}_".format(side) if side else ""
        fabric_suffix = " in fabric '{0}'".format(fabric_name) if fabric_name else ""

        if switch_ip:
            sid = self.by_ip.get(switch_ip)
            if not sid:
                raise Exception(
                    "Could not resolve {0}switch_ip='{1}'{2}. "
                    "No switch with that management IP was found.".format(side_prefix, switch_ip, fabric_suffix)
                )
            return sid

        if switch_name:
            matches = self.by_name.get(switch_name, [])
            if len(matches) == 1:
                return matches[0]
            if len(matches) > 1:
                raise Exception(
                    "{0}switch_name='{1}' is ambiguous{2} (matches {3} switches: {4}). "
                    "Use {0}switch_ip or {0}switch_id to disambiguate.".format(
                        side_prefix, switch_name, fabric_suffix, len(matches), ", ".join(matches)
                    )
                )
            raise Exception(
                "Could not resolve {0}switch_name='{1}'{2}. "
                "No switch with that hostname was found.".format(side_prefix, switch_name, fabric_suffix)
            )

        return None
