# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Small Network config helpers shared by the workflow, attachment, and dependency
components.
"""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActions


def configured_network_names(config: list[dict]) -> list[str]:
    """Return configured Network names in stable order."""
    seen: set[str] = set()
    names: list[str] = []
    for network in config:
        name = network.get("network_name") or network.get("networkName")
        if name and name not in seen:
            names.append(name)
            seen.add(name)
    return names


def deploy_enabled_by_network(config: list[dict], actions: ConfigActions | None = None) -> dict[str, bool]:
    """Return effective per-Network deploy intent from the shared action plan."""
    deploy_enabled: dict[str, bool] = {}
    for index, network in enumerate(config):
        name = network.get("network_name") or network.get("networkName")
        if name:
            if actions is None:
                deploy_enabled[name] = network.get("deploy", True)
            elif index < len(actions.resource_deploy_overrides):
                deploy_enabled[name] = actions.resource_deploy_enabled(index)
            else:
                deploy_enabled[name] = actions.deploy
    return deploy_enabled


def deploy_type_by_network(config: list[dict], actions: ConfigActions | None = None) -> dict[str, str]:
    """Return the shared module-level deploy scope for every configured Network."""
    deploy_type: dict[str, str] = {}
    for network in config:
        name = network.get("network_name") or network.get("networkName")
        if name:
            if actions is None:
                deploy_type[name] = network.get("deploy_type") or network.get("deployType") or "switch"
            else:
                deploy_type[name] = "network" if actions.type == "resource" else "switch"
    return deploy_type


def network_name_filter(network_names: list[str]) -> str:
    """Build a raw Lucene filter for endpoint serialization."""
    terms = [f"networkName:{network_name}" for network_name in sorted(set(network_names))]
    expression = terms[0] if len(terms) == 1 else "(" + " OR ".join(terms) + ")"
    return expression
