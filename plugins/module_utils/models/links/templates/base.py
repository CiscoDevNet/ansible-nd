# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared base class and field group mixins for link template input models.

Policy specific models compose the mixins they need instead of redeclaring
common fields (interface basics, descriptions, MACsec, QKD, etc.).
"""

from __future__ import annotations

import types
from typing import Any, Union, get_args, get_origin

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict, Field
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


class InterfaceBasicsMixin(BaseModel):
    """Common interface level settings shared by most policy types."""

    interface_admin_state: bool | None = Field(default=None, alias="interfaceAdminState")
    mtu: int | None = Field(default=None, alias="mtu")
    speed: str | None = Field(default=None, alias="speed")
    fec: str | None = Field(default=None, alias="fec")


class InterfaceDescriptionsMixin(BaseModel):
    """Source/destination interface descriptions and freeform config strings."""

    src_interface_description: str | None = Field(default=None, alias="srcInterfaceDescription")
    dst_interface_description: str | None = Field(default=None, alias="dstInterfaceDescription")
    src_interface_config: str | None = Field(default=None, alias="srcInterfaceConfig")
    dst_interface_config: str | None = Field(default=None, alias="dstInterfaceConfig")


class DhcpRelayMixin(BaseModel):
    """DHCP relay toggles for numbered/unnumbered links."""

    dhcp_relay_on_src_interface: bool | None = Field(default=None, alias="dhcpRelayOnSrcInterface")
    dhcp_relay_on_dst_interface: bool | None = Field(default=None, alias="dhcpRelayOnDstInterface")


class BfdEchoMixin(BaseModel):
    """BFD echo toggles for numbered links."""

    bfd_echo_on_src_interface: bool | None = Field(default=None, alias="bfdEchoOnSrcInterface")
    bfd_echo_on_dst_interface: bool | None = Field(default=None, alias="bfdEchoOnDstInterface")


class MacsecCoreMixin(BaseModel):
    """MACsec on/off toggle."""

    macsec: bool | None = Field(default=None, alias="macsec")


class MacsecFullMixin(MacsecCoreMixin):
    """Full MACsec configuration for DCI style links (cipher/keys/override)."""

    macsec_cipher_suite: str | None = Field(default=None, alias="macsecCipherSuite")
    macsec_primary_cryptographic_algorithm: str | None = Field(default=None, alias="macsecPrimaryCryptographicAlgorithm")
    macsec_primary_key_string: str | None = Field(default=None, alias="macsecPrimaryKeyString", json_schema_extra={"secret": True})
    macsec_fallback_cryptographic_algorithm: str | None = Field(default=None, alias="macsecFallbackCryptographicAlgorithm")
    macsec_fallback_key_string: str | None = Field(default=None, alias="macsecFallbackKeyString", json_schema_extra={"secret": True})
    override_fabric_macsec: bool | None = Field(default=None, alias="overrideFabricMacsec")


class QkdMixin(BaseModel):
    """Quantum Key Distribution fields for DCI links."""

    qkd: bool | None = Field(default=None, alias="qkd")
    ignore_certificate: bool | None = Field(default=None, alias="ignoreCertificate")
    src_kme_server_ip: str | None = Field(default=None, alias="srcKmeServerIp")
    dst_kme_server_ip: str | None = Field(default=None, alias="dstKmeServerIp")
    src_macsec_key_chain_prefix: str | None = Field(default=None, alias="srcMacsecKeyChainPrefix")
    dst_macsec_key_chain_prefix: str | None = Field(default=None, alias="dstMacsecKeyChainPrefix")
    src_qkd_profile_name: str | None = Field(default=None, alias="srcQkdProfileName")
    dst_qkd_profile_name: str | None = Field(default=None, alias="dstQkdProfileName")
    src_trustpoint_label: str | None = Field(default=None, alias="srcTrustpointLabel")
    dst_trustpoint_label: str | None = Field(default=None, alias="dstTrustpointLabel")


class EbgpPasswordMixin(BaseModel):
    """eBGP password / auth fields."""

    enable_ebgp_password: bool | None = Field(default=None, alias="enableEbgpPassword")
    ebgp_password: str | None = Field(default=None, alias="ebgpPassword", json_schema_extra={"secret": True})
    ebgp_auth_key_encryption_type: str | None = Field(default=None, alias="ebgpAuthKeyEncryptionType")
    inherit_ebgp_password_msd_settings: bool | None = Field(default=None, alias="inheritEbgpPasswordMsdSettings")


class TtagMixin(BaseModel):
    """TTAG fabric setting inheritance flag."""

    inherit_ttag_fabric_setting: bool | None = Field(default=None, alias="inheritTtagFabricSetting")


class NetflowMixin(BaseModel):
    """Netflow monitoring fields for DCI links."""

    netflow_on_src_interface: bool | None = Field(default=None, alias="netflowOnSrcInterface")
    netflow_on_dst_interface: bool | None = Field(default=None, alias="netflowOnDstInterface")
    src_netflow_monitor_name: str | None = Field(default=None, alias="srcNetflowMonitorName")
    dst_netflow_monitor_name: str | None = Field(default=None, alias="dstNetflowMonitorName")


class LinkTemplateBase(NDNestedModel):
    """Base for all policy specific template input models.

    ``extra="forbid"`` ensures fields that don't belong to the selected policy
    type (e.g. ``ebgp_multihop`` on a numbered link) are rejected by Pydantic
    instead of silently dropped. ``UserDefinedTemplateInputs`` overrides this
    back to ``extra="allow"`` because its shape is open.
    """

    model_config = ConfigDict(extra="forbid")

    @classmethod
    def secret_field_keys(cls, by_alias: bool = True) -> set[str]:
        """Keys of secret fields (tagged ``json_schema_extra={"secret": True}``).

        Returns aliases when ``by_alias`` is True (payload/diff shape), else the
        Python field names (config/output shape). Used to scrub secrets from
        module output and diffs while keeping them in the controller payload.
        """
        keys: set[str] = set()
        for field_name, field_info in cls.model_fields.items():
            extra = field_info.json_schema_extra
            if isinstance(extra, dict) and extra.get("secret"):
                keys.add((field_info.alias or field_name) if by_alias else field_name)
        return keys

    def to_payload(self, **kwargs: Any) -> dict[str, Any]:
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
        if get_origin(annotation) in (Union, types.UnionType):
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
