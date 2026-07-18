# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared base class and field group mixins for link template input models.

Policy specific models compose the mixins they need instead of redeclaring
common fields (interface basics, descriptions, MACsec, QKD, etc.).

Fields that ND documents with a default carry that default via
``json_schema_extra={"payload_default": <value>}`` (see ``pd()``). ND's Jython
template engine requires every declared key to be present, so on create/update
the payload fill sends the documented default for any field the user did not set
(``mtu 9216`` / ``speed auto`` instead of the schema-violating ``mtu: 0`` /
``speed: ""``) and a typed empty for every field that has no documented default,
including secrets. Secrets are still excluded from the diff, so an unset secret
sent as ``""`` never triggers an update; re-supply it on update or it is blanked.
"""

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict, Field
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel

# Sentinel: a field with no documented ND default (sent as a typed empty when unset).
_NO_DEFAULT = object()


def pd(default: Any, **extra: Any) -> dict[str, Any]:
    """Build a ``json_schema_extra`` dict tagging a field's documented ND default."""
    return {"payload_default": default, **extra}


class InterfaceBasicsMixin(BaseModel):
    """Common interface level settings shared by most policy types."""

    interface_admin_state: bool | None = Field(default=None, alias="interfaceAdminState", json_schema_extra=pd(True))
    mtu: int | None = Field(default=None, alias="mtu", json_schema_extra=pd(9216))
    speed: str | None = Field(default=None, alias="speed", json_schema_extra=pd("auto"))
    fec: str | None = Field(default=None, alias="fec", json_schema_extra=pd("auto"))


class InterfaceDescriptionsMixin(BaseModel):
    """Source/destination interface descriptions and freeform config strings."""

    src_interface_description: str | None = Field(default=None, alias="srcInterfaceDescription")
    dst_interface_description: str | None = Field(default=None, alias="dstInterfaceDescription")
    src_interface_config: str | None = Field(default=None, alias="srcInterfaceConfig")
    dst_interface_config: str | None = Field(default=None, alias="dstInterfaceConfig")


class DhcpRelayMixin(BaseModel):
    """DHCP relay toggles for numbered/unnumbered links."""

    dhcp_relay_on_src_interface: bool | None = Field(default=None, alias="dhcpRelayOnSrcInterface", json_schema_extra=pd(False))
    dhcp_relay_on_dst_interface: bool | None = Field(default=None, alias="dhcpRelayOnDstInterface", json_schema_extra=pd(False))


class BfdEchoMixin(BaseModel):
    """BFD echo toggles for numbered links."""

    bfd_echo_on_src_interface: bool | None = Field(default=None, alias="bfdEchoOnSrcInterface", json_schema_extra=pd(False))
    bfd_echo_on_dst_interface: bool | None = Field(default=None, alias="bfdEchoOnDstInterface", json_schema_extra=pd(False))


class MacsecCoreMixin(BaseModel):
    """MACsec on/off toggle."""

    macsec: bool | None = Field(default=None, alias="macsec", json_schema_extra=pd(False))


class MacsecFullMixin(MacsecCoreMixin):
    """Full MACsec configuration for DCI style links (cipher/keys/override)."""

    macsec_cipher_suite: str | None = Field(default=None, alias="macsecCipherSuite")
    macsec_primary_cryptographic_algorithm: str | None = Field(default=None, alias="macsecPrimaryCryptographicAlgorithm")
    macsec_primary_key_string: str | None = Field(default=None, alias="macsecPrimaryKeyString", json_schema_extra={"secret": True})
    macsec_fallback_cryptographic_algorithm: str | None = Field(default=None, alias="macsecFallbackCryptographicAlgorithm")
    macsec_fallback_key_string: str | None = Field(default=None, alias="macsecFallbackKeyString", json_schema_extra={"secret": True})
    override_fabric_macsec: bool | None = Field(default=None, alias="overrideFabricMacsec", json_schema_extra=pd(False))


class QkdMixin(BaseModel):
    """Quantum Key Distribution / MACsec key-management fields for DCI links."""

    qkd: bool | None = Field(default=None, alias="qkd", json_schema_extra=pd(False))
    ignore_certificate: bool | None = Field(default=None, alias="ignoreCertificate", json_schema_extra=pd(False))
    src_kme_server_ip: str | None = Field(default=None, alias="srcKmeServerIp")
    dst_kme_server_ip: str | None = Field(default=None, alias="dstKmeServerIp")
    src_kme_server_port_number: int | None = Field(default=None, alias="srcKmeServerPortNumber")
    dst_kme_server_port_number: int | None = Field(default=None, alias="dstKmeServerPortNumber")
    src_macsec_key_chain_prefix: str | None = Field(default=None, alias="srcMacsecKeyChainPrefix")
    dst_macsec_key_chain_prefix: str | None = Field(default=None, alias="dstMacsecKeyChainPrefix")
    src_qkd_profile_name: str | None = Field(default=None, alias="srcQkdProfileName")
    dst_qkd_profile_name: str | None = Field(default=None, alias="dstQkdProfileName")
    src_trustpoint_label: str | None = Field(default=None, alias="srcTrustpointLabel")
    dst_trustpoint_label: str | None = Field(default=None, alias="dstTrustpointLabel")


class EbgpPasswordMixin(BaseModel):
    """eBGP password / auth fields."""

    enable_ebgp_password: bool | None = Field(default=None, alias="enableEbgpPassword", json_schema_extra=pd(True))
    ebgp_password: str | None = Field(default=None, alias="ebgpPassword", json_schema_extra={"secret": True})
    ebgp_auth_key_encryption_type: str | None = Field(default=None, alias="ebgpAuthKeyEncryptionType", json_schema_extra=pd("3des"))
    inherit_ebgp_password_msd_settings: bool | None = Field(default=None, alias="inheritEbgpPasswordMsdSettings", json_schema_extra=pd(True))


class TtagMixin(BaseModel):
    """TTAG fabric setting inheritance flag."""

    inherit_ttag_fabric_setting: bool | None = Field(default=None, alias="inheritTtagFabricSetting", json_schema_extra=pd(True))


class NetflowMixin(BaseModel):
    """Netflow monitoring fields for DCI links."""

    netflow_on_src_interface: bool | None = Field(default=None, alias="netflowOnSrcInterface", json_schema_extra=pd(False))
    netflow_on_dst_interface: bool | None = Field(default=None, alias="netflowOnDstInterface", json_schema_extra=pd(False))
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

    @staticmethod
    def _documented_default(field_info: Any) -> Any:
        """Return the field's documented ND default, or ``_NO_DEFAULT`` if none."""
        extra = field_info.json_schema_extra
        if isinstance(extra, dict) and "payload_default" in extra:
            return extra["payload_default"]
        return _NO_DEFAULT

    @classmethod
    def apply_payload_defaults(cls, template_inputs: dict[str, Any], tmpl_cls: type) -> None:
        """Fill an aliased ``templateInputs`` dict for a create/update request.

        ND's Jython template engine references every known field by key, so a
        missing key raises during template execution: the payload must carry all
        declared fields. For each field the user did not set:

        - fields with a documented ND default are sent with that default, so we
          send ``mtu 9216`` / ``interface_admin_state true`` / ``fec auto`` /
          ``speed auto`` instead of the schema-violating typed empties
          ``0`` / ``false`` / ``""``;
        - every other field (including secrets) is sent as a typed empty so the
          key is present. Secrets are still excluded from the diff, so a
          secret-only change never triggers an update; re-supply a secret when
          updating a link, otherwise it is written empty.
        """
        for field_name, field_info in tmpl_cls.model_fields.items():
            if field_info.exclude:
                continue
            alias = field_info.alias or field_name
            if template_inputs.get(alias) is not None:
                continue  # user-provided value; keep as-is
            default = cls._documented_default(field_info)
            if default is not _NO_DEFAULT:
                template_inputs[alias] = default
            else:
                template_inputs[alias] = cls._empty_for_annotation(field_info.annotation)

    @staticmethod
    def _empty_for_annotation(annotation: Any) -> Any:
        """Typed empty matching an ``Optional[...]`` field's underlying type."""
        import types
        from typing import Union, get_args, get_origin

        if get_origin(annotation) in (Union, types.UnionType):
            non_none = [candidate for candidate in get_args(annotation) if candidate is not type(None)]
            if non_none:
                annotation = non_none[0]
        if annotation is bool:
            return False
        if annotation is int:
            return 0
        if annotation is float:
            return 0.0
        return ""

    def to_payload(self, **kwargs: Any) -> dict[str, Any]:
        """Serialize for POST/PUT, sending ND's documented defaults for unset fields."""
        data = self.model_dump(
            by_alias=True,
            exclude_none=True,
            mode="json",
            context={"mode": "payload"},
            exclude=self.payload_exclude_fields or None,
        )
        self.apply_payload_defaults(data, self.__class__)
        return data
