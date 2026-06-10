# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Helpers that extend FabricSwitchInventory with the by-name lookup and
priority-based resolve() semantics that the upstream class does not
provide. Kept here (not in fabric_inventory.py) so the vendored upstream
file stays byte-identical to the source PR.
"""

from __future__ import absolute_import, division, print_function

import logging
from typing import Any, Dict, List, Optional

from ansible_collections.cisco.nd.plugins.module_utils.fabric_inventory import FabricSwitchInventory
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_data_models import SwitchDataModel


class _FabricInventorySenderAdapter:
    """Bridge RestSend to the nd.request(verb=...) / nd.module.fail_json shape FabricSwitchInventory expects."""

    def __init__(self, rest_send):
        self._rest_send = rest_send
        self.module = rest_send.sender.ansible_module

    def request(self, path, verb=None, **_kwargs):
        self._rest_send.path = path
        self._rest_send.verb = verb
        self._rest_send.commit()
        if not self._rest_send.success:
            raise Exception("Request failed {0}".format(self._rest_send.error_summary))
        return self._rest_send.response_current.get("DATA", {})


def inventory_for_fabric(rest_send, fabric_name: str, log: logging.Logger) -> FabricSwitchInventory:
    """Build a FabricSwitchInventory for a fabric using RestSend + SwitchDataModel."""
    adapter = _FabricInventorySenderAdapter(rest_send)
    return FabricSwitchInventory.from_fabric(adapter, fabric_name, log, SwitchDataModel)


def by_name(inventory: FabricSwitchInventory) -> Dict[str, List[Any]]:
    """Return switches keyed by hostname. Value is a list to expose collisions."""
    result: Dict[str, List[Any]] = {}
    for sw in inventory.switches:
        name = getattr(sw, "hostname", None)
        if name:
            result.setdefault(name, []).append(sw)
    return result


def resolve(
    inventory: FabricSwitchInventory,
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
        sw = inventory.by_ip().get(switch_ip)
        if not sw:
            raise Exception(
                "Could not resolve {0}switch_ip='{1}'{2}. "
                "No switch with that management IP was found.".format(side_prefix, switch_ip, fabric_suffix)
            )
        return sw.switch_id

    if switch_name:
        matches = by_name(inventory).get(switch_name, [])
        if len(matches) == 1:
            return matches[0].switch_id
        if len(matches) > 1:
            ids = [m.switch_id for m in matches]
            raise Exception(
                "{0}switch_name='{1}' is ambiguous{2} (matches {3} switches: {4}). "
                "Use {0}switch_ip or {0}switch_id to disambiguate.".format(
                    side_prefix, switch_name, fabric_suffix, len(matches), ", ".join(ids)
                )
            )
        raise Exception(
            "Could not resolve {0}switch_name='{1}'{2}. "
            "No switch with that hostname was found.".format(side_prefix, switch_name, fabric_suffix)
        )

    return None
