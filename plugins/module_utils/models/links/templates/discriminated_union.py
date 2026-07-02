# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Discriminated union type for link template inputs.

``LinkTemplateInputs`` is an Annotated Union over every policy type model in
this package. Pydantic picks the correct subclass from the ``policy_type_marker``
literal field during parsing, giving per policy field validation for free.
"""

from __future__ import annotations

from typing import Annotated, Union

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .ebgp_vrf_lite import EbgpVrfLiteTemplateInputs
from .ipv6_link_local import Ipv6LinkLocalTemplateInputs
from .layer2_dci import Layer2DciTemplateInputs
from .layer3_dci_vrf_lite import Layer3DciVrfLiteTemplateInputs
from .mpls_overlay import MplsOverlayTemplateInputs
from .mpls_underlay import MplsUnderlayTemplateInputs
from .multisite_overlay import MultisiteOverlayTemplateInputs
from .multisite_underlay import MultisiteUnderlayTemplateInputs
from .numbered import NumberedTemplateInputs
from .preprovision import PreprovisionTemplateInputs
from .unnumbered import UnnumberedTemplateInputs
from .user_defined import UserDefinedTemplateInputs
from .vpc_peer_keepalive import VpcPeerKeepaliveTemplateInputs

LinkTemplateInputs = Annotated[
    Union[
        NumberedTemplateInputs,
        UnnumberedTemplateInputs,
        Ipv6LinkLocalTemplateInputs,
        EbgpVrfLiteTemplateInputs,
        Layer2DciTemplateInputs,
        Layer3DciVrfLiteTemplateInputs,
        MultisiteOverlayTemplateInputs,
        MultisiteUnderlayTemplateInputs,
        MplsOverlayTemplateInputs,
        MplsUnderlayTemplateInputs,
        PreprovisionTemplateInputs,
        UserDefinedTemplateInputs,
        VpcPeerKeepaliveTemplateInputs,
    ],
    Field(discriminator="policy_type_marker"),
]

# Every policy-type model in the union, used to enumerate secret keys across all
# of them without knowing which one a given link resolves to.
_LINK_TEMPLATE_INPUT_MODELS = (
    NumberedTemplateInputs,
    UnnumberedTemplateInputs,
    Ipv6LinkLocalTemplateInputs,
    EbgpVrfLiteTemplateInputs,
    Layer2DciTemplateInputs,
    Layer3DciVrfLiteTemplateInputs,
    MultisiteOverlayTemplateInputs,
    MultisiteUnderlayTemplateInputs,
    MplsOverlayTemplateInputs,
    MplsUnderlayTemplateInputs,
    PreprovisionTemplateInputs,
    UserDefinedTemplateInputs,
    VpcPeerKeepaliveTemplateInputs,
)


def all_secret_template_input_keys(by_alias: bool = False) -> set[str]:
    """Union of secret (``no_log``-worthy) key names across every policy type.

    ``template_inputs`` is a free-form dict, so Ansible cannot mark its secret
    keys ``no_log`` in the argument spec. The module registers these values with
    ``module.no_log_values`` at runtime instead; this returns the key names to
    look for, derived from the models so it never drifts as fields are added.
    """
    keys: set[str] = set()
    for model in _LINK_TEMPLATE_INPUT_MODELS:
        keys |= model.secret_field_keys(by_alias=by_alias)
    return keys


__all__ = [
    "LinkTemplateInputs",
    "all_secret_template_input_keys",
    "NumberedTemplateInputs",
    "UnnumberedTemplateInputs",
    "Ipv6LinkLocalTemplateInputs",
    "EbgpVrfLiteTemplateInputs",
    "Layer2DciTemplateInputs",
    "Layer3DciVrfLiteTemplateInputs",
    "MultisiteOverlayTemplateInputs",
    "MultisiteUnderlayTemplateInputs",
    "MplsOverlayTemplateInputs",
    "MplsUnderlayTemplateInputs",
    "PreprovisionTemplateInputs",
    "UserDefinedTemplateInputs",
    "VpcPeerKeepaliveTemplateInputs",
]
