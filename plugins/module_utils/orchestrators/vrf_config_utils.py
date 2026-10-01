# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Small VRF config helpers shared by the workflow, attachment, and dependency
components.
"""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActions


def configured_vrf_names(config: list[dict]) -> list[str]:
    """Return configured VRF names in stable order."""
    seen: set[str] = set()
    names: list[str] = []
    for vrf in config:
        name = vrf.get("vrf_name") or vrf.get("vrfName")
        if name and name not in seen:
            names.append(name)
            seen.add(name)
    return names


def deploy_enabled_by_vrf(config: list[dict], actions: ConfigActions | None = None) -> dict[str, bool]:
    """Return effective per-VRF deploy intent from the shared action plan."""
    deploy_enabled: dict[str, bool] = {}
    for index, vrf in enumerate(config):
        name = vrf.get("vrf_name") or vrf.get("vrfName")
        if name:
            if actions is None:
                deploy_enabled[name] = vrf.get("deploy", True)
            elif index < len(actions.resource_deploy_overrides):
                deploy_enabled[name] = actions.resource_deploy_enabled(index)
            else:
                deploy_enabled[name] = actions.deploy
    return deploy_enabled


def deploy_type_by_vrf(config: list[dict], actions: ConfigActions | None = None) -> dict[str, str]:
    """Return the shared module-level deploy scope for every configured VRF."""
    deploy_type: dict[str, str] = {}
    for vrf in config:
        name = vrf.get("vrf_name") or vrf.get("vrfName")
        if name:
            if actions is None:
                deploy_type[name] = vrf.get("deploy_type") or vrf.get("deployType") or "switch"
            else:
                deploy_type[name] = "vrf" if actions.type == "resource" else "switch"
    return deploy_type


def vrf_name_filter(vrf_names: list[str]) -> str:
    """Build a raw Lucene filter for endpoint serialization."""
    terms = [f"vrfName:{vrf_name}" for vrf_name in sorted(set(vrf_names))]
    expression = terms[0] if len(terms) == 1 else "(" + " OR ".join(terms) + ")"
    return expression
