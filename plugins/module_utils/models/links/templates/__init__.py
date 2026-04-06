# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Discriminated union type for link template inputs.

``LinkTemplateInputs`` is an Annotated Union over every policy type model in
this package. Pydantic picks the correct subclass from the ``policy_type_marker``
literal field during parsing, giving per policy field validation for free.
"""

from __future__ import absolute_import, division, print_function

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


__all__ = [
    "LinkTemplateInputs",
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
