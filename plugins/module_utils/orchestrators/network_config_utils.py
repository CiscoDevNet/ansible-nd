# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Small Network config helpers shared by the workflow, attachment, and dependency
components.
"""

from __future__ import annotations

from urllib.parse import quote


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


def deploy_enabled_by_network(config: list[dict]) -> dict[str, bool]:
    """Return per-Network deploy intent; omitted deploy defaults to True."""
    deploy_enabled: dict[str, bool] = {}
    for network in config:
        name = network.get("network_name") or network.get("networkName")
        if name:
            deploy_enabled[name] = network.get("deploy", True)
    return deploy_enabled


def deploy_type_by_network(config: list[dict]) -> dict[str, str]:
    """Return per-Network deploy scope; omitted deploy_type defaults to switch."""
    deploy_type: dict[str, str] = {}
    for network in config:
        name = network.get("network_name") or network.get("networkName")
        if name:
            deploy_type[name] = network.get("deploy_type") or network.get("deployType") or "switch"
    return deploy_type


def network_name_filter(network_names: list[str]) -> str:
    """Build a URL-safe Lucene filter for Network names."""
    terms = [f"networkName:{network_name}" for network_name in sorted(set(network_names))]
    expression = terms[0] if len(terms) == 1 else "(" + " OR ".join(terms) + ")"
    return quote(expression, safe="")
