# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""HTTP-boundary controller for the real vPC query and state-machine paths."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import MagicMock
from urllib.parse import parse_qs, unquote, urlsplit

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair import actions, query
from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.resources import VpcPairStateMachine


def pair(number=0, virtual=False, details=None):
    """Build deterministic, disjoint vPC identities with optional direct details."""
    value = {"switchId": f"PAIR-{number:03}-A", "peerSwitchId": f"PAIR-{number:03}-B", "useVirtualPeerLink": virtual}
    if details is not None:
        value["vpcPairDetails"] = deepcopy(details)
    return value


def config_for(value, reverse=False, mode=None):
    """Return ordinary module input, optionally in the reverse peer order."""
    first, second = value["switchId"], value["peerSwitchId"]
    result = {"switch_id": second if reverse else first, "peer_switch_id": first if reverse else second}
    if mode is not None:
        result["use_virtual_peer_link"] = mode
    return result


def make_module(config=None, state="merged", check_mode=False, save=False, deploy=False, verify=False):
    """Minimal Ansible module context; no query or reconciliation behavior is mocked."""
    return SimpleNamespace(
        params={
            "fabric_name": "scope-fabric",
            "state": state,
            "config": deepcopy(config or []),
            "config_actions": {"save": save, "deploy": deploy},
            "verify": {"enabled": verify, "retries": 1, "interval": 0, "timeout": 1},
            "output_level": "debug",
            "ignore_errors": False,
            "force": False,
        },
        check_mode=check_mode,
        warn=MagicMock(),
    )


class VpcController:
    """Simulate HTTP responses without replacing selection or conflict validation.

    ``failures`` contains serials whose direct GET must fail. ``page_size`` can
    make the requested peer appear on a later intended-list page. Accepted PUTs
    update the controller, so post-write queries exercise the same real path.
    """

    def __init__(self, pairs, *, list_mode=False, list_details=False, physical=True, page_size=500, extra_switches=()):
        self.pairs = deepcopy(pairs)
        self.list_mode = list_mode
        self.list_details = list_details
        self.physical = physical
        self.page_size = page_size
        self.failures = set()
        self.fail_after_write = set()
        self.list_failure = False
        self.calls = []
        self.inventory = []
        self.pending_switches = set()
        self.rest = SimpleNamespace(save_settings=lambda: None, restore_settings=lambda: None, timeout=0)
        for index, value in enumerate(pairs):
            for offset, field in enumerate(("switchId", "peerSwitchId")):
                serial = value[field]
                peer = value["peerSwitchId" if field == "switchId" else "switchId"]
                self.inventory.append(
                    {
                        "serialNumber": serial,
                        "fabricManagementIp": f"192.0.2.{index * 2 + offset + 1}",
                        "vpcConfigured": physical,
                        "vpcData": {"peerSwitchId": peer},
                    }
                )
        for index, serial in enumerate(extra_switches):
            self.inventory.append({"serialNumber": serial, "fabricManagementIp": f"198.51.100.{index + 1}", "vpcConfigured": False})

    def for_module(self, module):
        """Expose precisely the NDModuleV2 transport surface used by vPC helpers."""
        return SimpleNamespace(module=module, request=self.request, _get_rest_send=lambda: self.rest)

    def request(self, path, method, payload=None):
        """Record every HTTP operation and implement only documented fixture routes."""
        method = str(getattr(method, "value", method)).upper()
        self.calls.append((method, path, deepcopy(payload)))
        parsed = urlsplit(path)
        route = unquote(parsed.path)
        suffix = route.rsplit("/", 1)[-1]
        if method == "GET" and route == "/api/v1/manage/fabrics/scope-fabric":
            return {"management": {"type": "external"}}
        if method == "GET" and suffix == "vpcPairs":
            if self.list_failure:
                raise RuntimeError("intended-list read unavailable")
            params = parse_qs(parsed.query)
            assert params["view"] == ["intendedPairs"]
            offset = int(params.get("offset", [0])[0])
            rows = deepcopy(self.pairs[offset : offset + self.page_size])
            for value in rows:
                if not self.list_details:
                    value.pop("vpcPairDetails", None)
                if not self.list_mode:
                    value.pop("useVirtualPeerLink", None)
            return {"vpcPairs": rows, "meta": {"counts": {"total": len(self.pairs), "remaining": len(self.pairs) - offset - len(rows)}}}
        if method == "GET" and suffix == "switches":
            rows = deepcopy(self.inventory)
            for value in rows:
                value["configSyncStatus"] = "pending" if value["serialNumber"] in self.pending_switches else "inSync"
            return {"switches": rows}
        serial = route.split("/switches/", 1)[1].split("/", 1)[0] if "/switches/" in route else None
        if method == "GET" and suffix == "vpcPair":
            if serial in self.failures:
                raise RuntimeError("direct-detail read unavailable\ncontroller diagnostics must remain bounded")
            for value in self.pairs:
                if serial in (value["switchId"], value["peerSwitchId"]):
                    result = deepcopy(value)
                    if serial == result["peerSwitchId"]:
                        result["switchId"], result["peerSwitchId"] = result["peerSwitchId"], result["switchId"]
                    return result
            return {}
        if method == "GET" and suffix == "vpcPairOverview":
            return {"inventory": {"syncStatus": {"pending": int(serial in self.pending_switches), "inSync": 2}}, "overlay": {}}
        if method == "GET" and suffix == "vpcPairSupport":
            return {"isPairingAllowed": True, "isVpcFabricPeeringSupported": True}
        if method == "GET" and suffix == "vpcPairConsistency":
            return {"type2Consistency": True}
        if method == "PUT" and suffix == "vpcPair":
            key = {payload["switchId"], payload["peerSwitchId"]}
            self.pairs = [value for value in self.pairs if {value["switchId"], value["peerSwitchId"]} != key]
            if payload.get("vpcAction") != "unPair":
                self.pairs.append(deepcopy(payload))
            self.failures.update(self.fail_after_write)
            return deepcopy(payload)
        raise AssertionError(f"Unexpected fixture HTTP request: {method} {path}")

    @property
    def detail_serials(self):
        """All direct detail GETs, excluding overview/support reads and PUTs."""
        return [
            unquote(urlsplit(path).path).split("/switches/")[1].split("/")[0]
            for method, path, _payload in self.calls
            if method == "GET" and urlsplit(path).path.endswith("/vpcPair")
        ]

    @property
    def writes(self):
        """Recorded HTTP writes, including accepted writes before a refresh failure."""
        return [call for call in self.calls if call[0] != "GET"]

    @property
    def overview_serials(self):
        """Pair sync/membership queries used to verify save/deploy authority."""
        return [
            unquote(urlsplit(path).path).split("/switches/")[1].split("/")[0]
            for method, path, _payload in self.calls
            if method == "GET" and "vpcPairOverview" in urlsplit(path).path
        ]


def patch_controller(monkeypatch, controller, query_impl=query):
    """Replace the HTTP transport only; all public query/action helpers stay real."""
    for owner in (query_impl, actions):
        monkeypatch.setattr(owner, "NDModuleV2", controller.for_module)


def make_machine(module):
    """Use the genuine constructor, model collections, orchestrator and handlers."""
    return VpcPairStateMachine(module)
