# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Cross-family tests for fabric BGP and release-aware site-ID preflight."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ebgp_vxlan import (
    FabricAiEbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ai_ibgp_vxlan import (
    FabricAiIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import (
    FabricCampusIbgpVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import (
    FabricExternalConnectivityModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import (
    FabricIbgpModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ebgp_vxlan import (
    ManageAiEbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ai_ibgp_vxlan import (
    ManageAiIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.validations.manage_fabric_bgp_validation import (
    parse_controller_version,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_campus_ibgp_vxlan import (
    ManageCampusIbgpVxlanFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ebgp_vxlan import (
    ManageEbgpFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_external import (
    ManageExternalFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ibgp_vxlan import (
    ManageIbgpFabricOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

FABRIC_FAMILIES = (
    (FabricExternalConnectivityModel, ManageExternalFabricOrchestrator),
    (FabricIbgpModel, ManageIbgpFabricOrchestrator),
    (FabricEbgpModel, ManageEbgpFabricOrchestrator),
    (FabricAiIbgpVxlanModel, ManageAiIbgpVxlanFabricOrchestrator),
    (FabricAiEbgpVxlanModel, ManageAiEbgpVxlanFabricOrchestrator),
    (FabricCampusIbgpVxlanModel, ManageCampusIbgpVxlanFabricOrchestrator),
)


def _orchestrator(orchestrator_class, state: str, version: str | None = None):
    rest_send = RestSend({"check_mode": False, "state": state})
    rest_send._controller_version = version
    return orchestrator_class(rest_send=rest_send)


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
def test_partial_merged_proposal_may_omit_bgp_asn(model_class, orchestrator_class) -> None:
    model = model_class.from_config(
        {"fabric_name": "fabric1", "management": {"performance_monitoring": True}},
        context={"state": "merged"},
    )

    assert model.management is not None
    assert model.management.bgp_asn is None
    orchestrator = _orchestrator(orchestrator_class, "merged")
    orchestrator.preflight_create([])
    orchestrator.preflight([model])


@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
def test_create_requires_bgp_asn(model_class, orchestrator_class) -> None:
    model = model_class.from_config({"fabric_name": "fabric1", "management": {}}, context={"state": "merged"})

    with pytest.raises(RuntimeError, match=r"management\.bgp_asn is required when creating.*fabric1"):
        _orchestrator(orchestrator_class, "merged").preflight_create([model])


@pytest.mark.parametrize("state", ("replaced", "overridden"))
@pytest.mark.parametrize(("model_class", "orchestrator_class"), FABRIC_FAMILIES)
def test_exact_states_require_bgp_asn(model_class, orchestrator_class, state: str) -> None:
    model = model_class.from_config({"fabric_name": "fabric1", "management": {}}, context={"state": state})

    with pytest.raises(RuntimeError, match=rf"management\.bgp_asn is required when state is '{state}'"):
        _orchestrator(orchestrator_class, state).preflight([model])


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("4.2.1.10", (4, 2, 1)),
        ("4.3.1.175", (4, 3, 1)),
        (None, None),
        ("invalid", None),
    ),
)
def test_parse_controller_version(value, expected) -> None:
    assert parse_controller_version(value) == expected


def test_extended_site_id_is_release_aware() -> None:
    model = FabricIbgpModel.from_config(
        {
            "fabric_name": "fabric1",
            "management": {"bgp_asn": "65001", "site_id": "4294967296"},
        }
    )

    with pytest.raises(RuntimeError, match="require ND 4.3.1 or later"):
        _orchestrator(ManageIbgpFabricOrchestrator, "merged", "4.2.1.10").preflight([model])

    _orchestrator(ManageIbgpFabricOrchestrator, "merged", "4.3.1.175").preflight([model])
