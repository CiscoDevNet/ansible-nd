# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from dataclasses import asdict, dataclass, replace
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

PAGE_SIZE = 100
PAGE_LIMIT = 100
FABRIC_PREFIX = "/api/v1/manage/fabrics/"
PRESENT_STATES = frozenset({"paired", "pairPending"})
HA_STATES = PRESENT_STATES | {"unpaired", "unpairPending"}


# Inventory normalization


@dataclass(frozen=True)
class SwitchObservation:
    peer_id: str | None
    state: str
    topology: str


def _read_switch_observation(row: object) -> tuple[str, SwitchObservation]:
    if not isinstance(row, dict) or not isinstance(row.get("switchInfo"), dict):
        raise AnsibleActionFail("HA inventory row requires switchInfo")

    info = row["switchInfo"]
    switch_id, peer_id = info.get("id"), info.get("peerId")
    state, topology = info.get("haPaired"), row.get("pairingType")
    if not isinstance(switch_id, str) or not switch_id.strip():
        raise AnsibleActionFail("HA inventory row requires a switch serial")
    if topology not in ("vpc", "nonVpc"):
        raise AnsibleActionFail(f"Switch {switch_id!r} has invalid pairing type {topology!r}")
    if not isinstance(state, str) or state not in HA_STATES:
        raise AnsibleActionFail(f"Switch {switch_id!r} has invalid HA state {state!r}")
    if peer_id is None and (topology == "vpc" or state in PRESENT_STATES):
        raise AnsibleActionFail(f"Switch {switch_id!r} is missing a peer serial")
    if peer_id is not None and (not isinstance(peer_id, str) or not peer_id.strip() or peer_id == switch_id):
        raise AnsibleActionFail(f"Switch {switch_id!r} has an invalid peer serial")
    return switch_id, SwitchObservation(peer_id, state, topology)


def _summarize_ha_inventory(reported: dict[str, SwitchObservation]) -> dict[str, Any]:
    switches = reported.copy()
    active_peers: dict[str, str] = {}
    for switch_id, observation in reported.items():
        peer_id = observation.peer_id
        if peer_id is None:
            continue
        if observation.topology == "vpc":
            # A single vPC row carries HA evidence for both physical peers.
            peer_observation = replace(observation, peer_id=switch_id)
            if switches.setdefault(peer_id, peer_observation) != peer_observation:
                raise AnsibleActionFail(f"Switches {switch_id!r} and {peer_id!r} have conflicting vPC observations")
        if observation.state in PRESENT_STATES and (
            active_peers.setdefault(switch_id, peer_id) != peer_id or active_peers.setdefault(peer_id, switch_id) != switch_id
        ):
            raise AnsibleActionFail(f"Switches {switch_id!r} and {peer_id!r} have conflicting active HA pairs")

    return {
        "present_pairs": [{"switch_id": first, "peer_switch_id": second} for first, second in sorted(active_peers.items()) if first < second],
        "switches": {switch_id: asdict(observation) for switch_id, observation in switches.items()},
    }


def _read_fabric_switch(row: object) -> tuple[str, str | None]:
    """Extract the serial and management IP used to resolve fixture switches."""
    if not isinstance(row, dict):
        raise AnsibleActionFail("Fabric switch inventory row must be a mapping")
    switch_id, management_ip = row.get("switchId"), row.get("fabricManagementIp")
    if not isinstance(switch_id, str) or not switch_id.strip():
        raise AnsibleActionFail("Fabric switch inventory row requires a switch serial")
    if management_ip is not None and not isinstance(management_ip, str):
        raise AnsibleActionFail(f"Switch {switch_id!r} has an invalid management IP value")
    return switch_id, management_ip


# Read-only action plugin


class ActionModule(ActionBase):
    """Read complete Manage inventories for HA tests and fixture discovery."""

    TRANSFERS_FILES = False
    _supports_check_mode = True

    def run(self, tmp: str | None = None, task_vars: dict[str, Any] | None = None) -> dict[str, Any]:
        result = super().run(tmp, task_vars)
        path = self._task.args.get("path")
        if not isinstance(path, str):
            raise AnsibleActionFail("The HA or fabric switch inventory path is required")
        parsed = urlsplit(path)
        fabric, _separator, endpoint = parsed.path.removeprefix(FABRIC_PREFIX).partition("/")
        if parsed.scheme or parsed.netloc or not parsed.path.startswith(FABRIC_PREFIX) or not fabric or endpoint not in ("smartSwitches/haPairs", "switches"):
            raise AnsibleActionFail(f"Expected a Manage HA inventory path or fabric switch list, received {path!r}")
        query = [(key, value) for key, value in parse_qsl(parsed.query) if key not in ("max", "offset")]
        if any(key == "filter" for key, _value in query):
            raise AnsibleActionFail("An inventory scope check requires an unfiltered path")
        collection = "rows" if endpoint == "smartSwitches/haPairs" else "switches"

        original_check_mode = self._task.check_mode
        try:
            # nd_rest skips requests in check mode. Every request here is a GET.
            self._task.check_mode = False
            reported = self._read_inventory_pages(parsed.path, query, collection, task_vars)
        finally:
            self._task.check_mode = original_check_mode
        observation = _summarize_ha_inventory(reported) if collection == "rows" else {"fabric_switches": reported}
        result.update(changed=False, **observation)
        return result

    def _read_inventory_pages(self, path: str, query: list[tuple[str, str]], collection: str, task_vars: dict[str, Any] | None) -> dict[str, Any]:
        reported: dict[str, Any] = {}
        read_row = _read_switch_observation if collection == "rows" else _read_fabric_switch
        label = "HA inventory" if collection == "rows" else "Fabric switch inventory"
        for _page_number in range(PAGE_LIMIT):
            offset = len(reported)
            page_query = urlencode([*query, ("max", PAGE_SIZE), ("offset", offset)], quote_via=quote)
            response = self._execute_module(
                module_name="cisco.nd.nd_rest",
                module_args={"path": urlunsplit(("", "", path, page_query, "")), "method": "get"},
                task_vars=task_vars,
            )
            if response.get("failed") or str(response.get("status")) != "200":
                raise AnsibleActionFail(f"{label} GET at offset {offset} failed with HTTP {response.get('status')}: {response.get('msg', '')}")
            current = response.get("current")
            if not isinstance(current, dict) or not isinstance(current.get(collection), list):
                raise AnsibleActionFail(f"{label} at offset {offset} requires current.{collection} to be a list")
            if not current[collection]:
                return reported
            for row in current[collection]:
                switch_id, observation = read_row(row)
                if switch_id in reported:
                    raise AnsibleActionFail(f"{label} returned repeated serial {switch_id!r}")
                reported[switch_id] = observation
        raise AnsibleActionFail(f"{label} exceeded {PAGE_LIMIT} pages without an empty terminal page")
