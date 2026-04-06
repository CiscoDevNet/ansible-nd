# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared base class and field group mixins for link template input models.

Policy specific models compose the mixins they need instead of redeclaring
common fields (interface basics, descriptions, MACsec, QKD, etc.).
"""

from __future__ import absolute_import, division, print_function

from typing import Any, Dict, Optional, Union, get_args, get_origin

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict, Field
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


class InterfaceBasicsMixin(BaseModel):
    """Common interface level settings shared by most policy types."""

    interface_admin_state: Optional[bool] = Field(default=None, alias="interfaceAdminState")
    mtu: Optional[int] = Field(default=None, alias="mtu")
    speed: Optional[str] = Field(default=None, alias="speed")
    fec: Optional[str] = Field(default=None, alias="fec")


class InterfaceDescriptionsMixin(BaseModel):
    """Source/destination interface descriptions and freeform config strings."""

    src_interface_description: Optional[str] = Field(default=None, alias="srcInterfaceDescription")
    dst_interface_description: Optional[str] = Field(default=None, alias="dstInterfaceDescription")
    src_interface_config: Optional[str] = Field(default=None, alias="srcInterfaceConfig")
    dst_interface_config: Optional[str] = Field(default=None, alias="dstInterfaceConfig")


class DhcpRelayMixin(BaseModel):
    """DHCP relay toggles for numbered/unnumbered links."""

    dhcp_relay_on_src_interface: Optional[bool] = Field(default=None, alias="dhcpRelayOnSrcInterface")
    dhcp_relay_on_dst_interface: Optional[bool] = Field(default=None, alias="dhcpRelayOnDstInterface")


class BfdEchoMixin(BaseModel):
    """BFD echo toggles for numbered links."""

    bfd_echo_on_src_interface: Optional[bool] = Field(default=None, alias="bfdEchoOnSrcInterface")
    bfd_echo_on_dst_interface: Optional[bool] = Field(default=None, alias="bfdEchoOnDstInterface")


class MacsecCoreMixin(BaseModel):
    """MACsec on/off toggle."""

    macsec: Optional[bool] = Field(default=None, alias="macsec")


class MacsecFullMixin(MacsecCoreMixin):
    """Full MACsec configuration for DCI style links (cipher/keys/override)."""

    macsec_cipher_suite: Optional[str] = Field(default=None, alias="macsecCipherSuite")
    macsec_primary_cryptographic_algorithm: Optional[str] = Field(default=None, alias="macsecPrimaryCryptographicAlgorithm")
    macsec_primary_key_string: Optional[str] = Field(default=None, alias="macsecPrimaryKeyString")
    macsec_fallback_cryptographic_algorithm: Optional[str] = Field(default=None, alias="macsecFallbackCryptographicAlgorithm")
    macsec_fallback_key_string: Optional[str] = Field(default=None, alias="macsecFallbackKeyString")
    override_fabric_macsec: Optional[bool] = Field(default=None, alias="overrideFabricMacsec")


class QkdMixin(BaseModel):
    """Quantum Key Distribution fields for DCI links."""

    qkd: Optional[bool] = Field(default=None, alias="qkd")
    ignore_certificate: Optional[bool] = Field(default=None, alias="ignoreCertificate")
    src_kme_server_ip: Optional[str] = Field(default=None, alias="srcKmeServerIp")
    dst_kme_server_ip: Optional[str] = Field(default=None, alias="dstKmeServerIp")
    src_macsec_key_chain_prefix: Optional[str] = Field(default=None, alias="srcMacsecKeyChainPrefix")
    dst_macsec_key_chain_prefix: Optional[str] = Field(default=None, alias="dstMacsecKeyChainPrefix")
    src_qkd_profile_name: Optional[str] = Field(default=None, alias="srcQkdProfileName")
    dst_qkd_profile_name: Optional[str] = Field(default=None, alias="dstQkdProfileName")
    src_trustpoint_label: Optional[str] = Field(default=None, alias="srcTrustpointLabel")
    dst_trustpoint_label: Optional[str] = Field(default=None, alias="dstTrustpointLabel")


class EbgpPasswordMixin(BaseModel):
    """eBGP password / auth fields."""

    enable_ebgp_password: Optional[bool] = Field(default=None, alias="enableEbgpPassword")
    ebgp_password: Optional[str] = Field(default=None, alias="ebgpPassword")
    ebgp_auth_key_encryption_type: Optional[str] = Field(default=None, alias="ebgpAuthKeyEncryptionType")
    inherit_ebgp_password_msd_settings: Optional[bool] = Field(default=None, alias="inheritEbgpPasswordMsdSettings")


class TtagMixin(BaseModel):
    """TTAG fabric setting inheritance flag."""

    inherit_ttag_fabric_setting: Optional[bool] = Field(default=None, alias="inheritTtagFabricSetting")


class NetflowMixin(BaseModel):
    """Netflow monitoring fields for DCI links."""

    netflow_on_src_interface: Optional[bool] = Field(default=None, alias="netflowOnSrcInterface")
    netflow_on_dst_interface: Optional[bool] = Field(default=None, alias="netflowOnDstInterface")
    src_netflow_monitor_name: Optional[str] = Field(default=None, alias="srcNetflowMonitorName")
    dst_netflow_monitor_name: Optional[str] = Field(default=None, alias="dstNetflowMonitorName")


class LinkTemplateBase(NDNestedModel):
    """Base for all policy specific template input models.

    ``extra="forbid"`` ensures fields that don't belong to the selected policy
    type (e.g. ``ebgp_multihop`` on a numbered link) are rejected by Pydantic
    instead of silently dropped. ``UserDefinedTemplateInputs`` overrides this
    back to ``extra="allow"`` because its shape is open.
    """

    model_config = ConfigDict(extra="forbid")

    def to_payload(self, **kwargs) -> Dict[str, Any]:
        """Emit every declared field, substituting typed empties for ``None``.

        ND's template engine rejects payloads that omit known fields. The UI
        works around this by sending ``""`` / ``false`` / ``0`` for anything
        the user didn't set; we mirror that here.
        """
        data = self.model_dump(
            by_alias=True,
            exclude_none=False,
            mode="json",
            context={"mode": "payload"},
            exclude=self.payload_exclude_fields or None,
        )
        for field_name, field_info in self.__class__.model_fields.items():
            alias = field_info.alias or field_name
            if alias in data and data[alias] is None:
                data[alias] = self._empty_for_annotation(field_info.annotation)
        return data

    @staticmethod
    def _empty_for_annotation(annotation: Any) -> Any:
        """Pick an empty value matching an ``Optional[...]`` field's underlying type."""
        if get_origin(annotation) is Union:
            non_none = [a for a in get_args(annotation) if a is not type(None)]
            if non_none:
                annotation = non_none[0]
        if annotation is bool:
            return False
        if annotation is int:
            return 0
        if annotation is float:
            return 0.0
        return ""
