# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Discriminated union type for link template inputs.

``LinkTemplateInputs`` is an Annotated Union over every policy type model in
this package. Pydantic picks the correct subclass from the ``policy_type_marker``
literal field during parsing, giving per policy field validation for free.
"""

from __future__ import annotations

from typing import Annotated

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .ebgp_vrf_lite import EbgpVrfLiteTemplateInputs
from .csr_bgp_over_ipsec import CsrBgpOverIpsecTemplateInputs
from .csr_evpn_multisite_overlay import CsrEvpnMultisiteOverlayTemplateInputs
from .csr_multisite_underlay import CsrMultisiteUnderlayTemplateInputs
from .ios_xe_numbered import IosXeNumberedTemplateInputs
from .ipfm_numbered import IpfmNumberedTemplateInputs
from .ipv6_link_local import Ipv6LinkLocalTemplateInputs
from .layer2_dci import Layer2DciTemplateInputs
from .layer3_dci_vrf_lite import Layer3DciVrfLiteTemplateInputs
from .mpls_overlay import MplsOverlayTemplateInputs
from .mpls_underlay import MplsUnderlayTemplateInputs
from .multisite_overlay import MultisiteOverlayTemplateInputs
from .multisite_underlay import MultisiteUnderlayTemplateInputs
from .multisite_underlay_inter_fabric_group import MultisiteUnderlayInterFabricGroupTemplateInputs
from .numbered import NumberedTemplateInputs
from .ospf_vrf_lite import OspfVrfLiteTemplateInputs
from .preprovision import PreprovisionTemplateInputs
from .routed_fabric import RoutedFabricTemplateInputs
from .service_po_trunk import ServicePoTrunkTemplateInputs
from .service_trunk import ServiceTrunkTemplateInputs
from .service_vpc_trunk import ServiceVpcTrunkTemplateInputs
from .unnumbered import UnnumberedTemplateInputs
from .user_defined import UserDefinedTemplateInputs
from .vpc_peer_keepalive import VpcPeerKeepaliveTemplateInputs
from .vxlan_aci_evpn_overlay import VxlanAciEvpnOverlayTemplateInputs
from .vxlan_aci_multisite_underlay import VxlanAciMultisiteUnderlayTemplateInputs

# ``A | B`` here is a runtime union over pydantic model classes, not a deferred
# annotation, so ``from __future__ import annotations`` does not defer it. It works
# (pydantic's metaclass supports ``__or__``), but pylint's static check cannot see
# that, so scope-disable ``unsupported-binary-operation`` for just this assignment.
# pylint: disable=unsupported-binary-operation
LinkTemplateInputs = Annotated[
    NumberedTemplateInputs
    | UnnumberedTemplateInputs
    | Ipv6LinkLocalTemplateInputs
    | EbgpVrfLiteTemplateInputs
    | IosXeNumberedTemplateInputs
    | Layer2DciTemplateInputs
    | Layer3DciVrfLiteTemplateInputs
    | MultisiteOverlayTemplateInputs
    | MultisiteUnderlayTemplateInputs
    | MplsOverlayTemplateInputs
    | MplsUnderlayTemplateInputs
    | PreprovisionTemplateInputs
    | UserDefinedTemplateInputs
    | VpcPeerKeepaliveTemplateInputs
    | IpfmNumberedTemplateInputs
    | OspfVrfLiteTemplateInputs
    | CsrMultisiteUnderlayTemplateInputs
    | CsrEvpnMultisiteOverlayTemplateInputs
    | CsrBgpOverIpsecTemplateInputs
    | VxlanAciMultisiteUnderlayTemplateInputs
    | VxlanAciEvpnOverlayTemplateInputs
    | RoutedFabricTemplateInputs
    | MultisiteUnderlayInterFabricGroupTemplateInputs
    | ServiceTrunkTemplateInputs
    | ServicePoTrunkTemplateInputs
    | ServiceVpcTrunkTemplateInputs,
    Field(discriminator="policy_type_marker"),
]
# pylint: enable=unsupported-binary-operation

# Policy types this module strictly models and can create/update. Reads of any
# other (valid) ND policy type fall back to a permissive opaque record so the
# full-fabric query is never aborted by an unrelated, unsupported link.
ADDITIONAL_POLICY_TYPES = (
    "ipfmNumbered",
    "ospfVrfLite",
    "csrMultisiteUnderlay",
    "csrEvpnMultisiteOverlay",
    "csrBgpOverIpsec",
    "vxlanAciMultisiteUnderlay",
    "vxlanAciEvpnOverlay",
    "routedFabric",
    "multisiteUnderlayInterFabricGroup",
    "serviceTrunk",
    "servicePoTrunk",
    "serviceVpcTrunk",
)

SUPPORTED_POLICY_TYPES = (
    "numbered",
    "unnumbered",
    "ipv6LinkLocal",
    "ebgpVrfLite",
    "iosXeNumbered",
    "layer2Dci",
    "layer3DciVrfLite",
    "multisiteOverlay",
    "multisiteUnderlay",
    "mplsOverlay",
    "mplsUnderlay",
    "preprovision",
    "userDefined",
    "vpcPeerKeepalive",
) + ADDITIONAL_POLICY_TYPES

# Every policy-type model in the union, used to enumerate secret keys across all
# of them without knowing which one a given link resolves to.
_LINK_TEMPLATE_INPUT_MODELS = (
    NumberedTemplateInputs,
    UnnumberedTemplateInputs,
    Ipv6LinkLocalTemplateInputs,
    EbgpVrfLiteTemplateInputs,
    IosXeNumberedTemplateInputs,
    Layer2DciTemplateInputs,
    Layer3DciVrfLiteTemplateInputs,
    MultisiteOverlayTemplateInputs,
    MultisiteUnderlayTemplateInputs,
    MplsOverlayTemplateInputs,
    MplsUnderlayTemplateInputs,
    PreprovisionTemplateInputs,
    UserDefinedTemplateInputs,
    VpcPeerKeepaliveTemplateInputs,
    IpfmNumberedTemplateInputs,
    OspfVrfLiteTemplateInputs,
    CsrMultisiteUnderlayTemplateInputs,
    CsrEvpnMultisiteOverlayTemplateInputs,
    CsrBgpOverIpsecTemplateInputs,
    VxlanAciMultisiteUnderlayTemplateInputs,
    VxlanAciEvpnOverlayTemplateInputs,
    RoutedFabricTemplateInputs,
    MultisiteUnderlayInterFabricGroupTemplateInputs,
    ServiceTrunkTemplateInputs,
    ServicePoTrunkTemplateInputs,
    ServiceVpcTrunkTemplateInputs,
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
    "SUPPORTED_POLICY_TYPES",
    "ADDITIONAL_POLICY_TYPES",
    "all_secret_template_input_keys",
    "NumberedTemplateInputs",
    "UnnumberedTemplateInputs",
    "Ipv6LinkLocalTemplateInputs",
    "EbgpVrfLiteTemplateInputs",
    "IosXeNumberedTemplateInputs",
    "Layer2DciTemplateInputs",
    "Layer3DciVrfLiteTemplateInputs",
    "MultisiteOverlayTemplateInputs",
    "MultisiteUnderlayTemplateInputs",
    "MplsOverlayTemplateInputs",
    "MplsUnderlayTemplateInputs",
    "PreprovisionTemplateInputs",
    "UserDefinedTemplateInputs",
    "VpcPeerKeepaliveTemplateInputs",
    "IpfmNumberedTemplateInputs",
    "OspfVrfLiteTemplateInputs",
    "CsrMultisiteUnderlayTemplateInputs",
    "CsrEvpnMultisiteOverlayTemplateInputs",
    "CsrBgpOverIpsecTemplateInputs",
    "VxlanAciMultisiteUnderlayTemplateInputs",
    "VxlanAciEvpnOverlayTemplateInputs",
    "RoutedFabricTemplateInputs",
    "MultisiteUnderlayInterFabricGroupTemplateInputs",
    "ServiceTrunkTemplateInputs",
    "ServicePoTrunkTemplateInputs",
    "ServiceVpcTrunkTemplateInputs",
]
