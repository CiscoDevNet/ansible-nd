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

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict, Field, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel

# Sentinel: a field with no documented ND default (sent as a typed empty when unset).
_NO_DEFAULT = object()

# Shared OpenAPI enum value sets (links_spec.json). Reused across policy types.
SPEED_CHOICES = ("auto", "10Mb", "100Mb", "1Gb", "2.5Gb", "5Gb", "10Gb", "25Gb", "40Gb", "50Gb", "100Gb", "200Gb", "400Gb", "800Gb")
FEC_CHOICES = ("auto", "fcFec", "off", "rsCons16", "rsFec", "rsIeee")
BGP_AUTH_KEY_ENCRYPTION_CHOICES = ("3des", "type6", "type7")


def pd(default: Any, **extra: Any) -> dict[str, Any]:
    """Build a ``json_schema_extra`` dict tagging a field's documented ND default,
    plus any write-contract constraints (``choices``/``minimum``/``maximum``/
    ``max_length``/``required``) enforced by :meth:`LinkTemplateBase._enforce_write_contract`.
    """
    return {"payload_default": default, **extra}


def con(**extra: Any) -> dict[str, Any]:
    """Like :func:`pd` but for a field with no documented ND default: carries only
    write-contract constraints (``choices``/``minimum``/``maximum``/``max_length``/
    ``required``). Used where the OpenAPI spec constrains a field but gives no default.
    """
    return dict(extra)


class InterfaceBasicsMixin(BaseModel):
    """Common interface level settings shared by the intra-fabric addressed policies
    (numbered, unnumbered, ipv6LinkLocal). ``mtu`` is required by the OpenAPI write
    contract for all three; the module still fills the documented default (9216) when
    the user omits it, so requiredness only bites a field with no default."""

    interface_admin_state: bool | None = Field(default=None, alias="interfaceAdminState", json_schema_extra=pd(True))
    mtu: int | None = Field(default=None, alias="mtu", json_schema_extra=pd(9216, minimum=576, maximum=9216, required=True))
    speed: str | None = Field(default=None, alias="speed", json_schema_extra=pd("auto", choices=SPEED_CHOICES))
    fec: str | None = Field(default=None, alias="fec", json_schema_extra=pd("auto", choices=FEC_CHOICES))


class InterfaceDescriptionsMixin(BaseModel):
    """Source/destination interface descriptions and freeform config strings."""

    src_interface_description: str | None = Field(default=None, alias="srcInterfaceDescription", json_schema_extra=con(max_length=254))
    dst_interface_description: str | None = Field(default=None, alias="dstInterfaceDescription", json_schema_extra=con(max_length=254))
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
    src_kme_server_port_number: int | None = Field(default=None, alias="srcKmeServerPortNumber", json_schema_extra=con(minimum=0, maximum=65535))
    dst_kme_server_port_number: int | None = Field(default=None, alias="dstKmeServerPortNumber", json_schema_extra=con(minimum=0, maximum=65535))
    src_macsec_key_chain_prefix: str | None = Field(default=None, alias="srcMacsecKeyChainPrefix")
    dst_macsec_key_chain_prefix: str | None = Field(default=None, alias="dstMacsecKeyChainPrefix")
    src_qkd_profile_name: str | None = Field(default=None, alias="srcQkdProfileName", json_schema_extra=con(max_length=63))
    dst_qkd_profile_name: str | None = Field(default=None, alias="dstQkdProfileName", json_schema_extra=con(max_length=63))
    src_trustpoint_label: str | None = Field(default=None, alias="srcTrustpointLabel", json_schema_extra=con(max_length=64))
    dst_trustpoint_label: str | None = Field(default=None, alias="dstTrustpointLabel", json_schema_extra=con(max_length=64))


class EbgpPasswordMixin(BaseModel):
    """eBGP password / auth fields."""

    enable_ebgp_password: bool | None = Field(default=None, alias="enableEbgpPassword", json_schema_extra=pd(True))
    ebgp_password: str | None = Field(default=None, alias="ebgpPassword", json_schema_extra={"secret": True})
    ebgp_auth_key_encryption_type: str | None = Field(
        default=None, alias="ebgpAuthKeyEncryptionType", json_schema_extra=pd("3des", choices=BGP_AUTH_KEY_ENCRYPTION_CHOICES)
    )
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

    @model_validator(mode="before")
    @classmethod
    def _drop_unknown_on_read(cls, data: Any, info: Any) -> Any:
        """Keep controller reads tolerant of forward/legacy response fields.

        ``extra="forbid"`` is the write-time guard that rejects a field belonging to
        another policy. On a controller read (``from_response`` marks
        ``source="response"``) that same strictness would misclassify a *supported*
        policy carrying an extra response field as an opaque unsupported link (it once
        did for a valid ``preprovision`` link returning ``mtu``/``speed``). Drop the
        unknown keys on read only, so the link resolves to its real policy model and
        stays mutable. Write input keeps every key, so ``extra="forbid"`` still
        rejects a wrong field. ``extra="allow"`` models (userDefined) are exempt.
        """
        context = info.context or {}
        if context.get("source") != "response" or not isinstance(data, dict):
            return data
        if cls.model_config.get("extra") == "allow":
            return data
        known = {"policy_type_marker"}
        for field_name, field_info in cls.model_fields.items():
            known.add(field_name)
            if field_info.alias:
                known.add(field_info.alias)
        return {key: value for key, value in data.items() if key in known}

    @model_validator(mode="after")
    def _enforce_write_contract(self, info: Any) -> LinkTemplateBase:
        """Enforce the OpenAPI write contract (required / enum / numeric bounds /
        string length) on user writes only.

        Write states thread ``context["state"]``; controller reads mark
        ``source="response"``. Enforcement runs only for writes so invalid intent
        fails before check mode proposes a change or any mutating request is sent,
        while gathered stays tolerant of legacy / forward-compatible / already-invalid
        controller records. A required field that carries a documented default is not
        forced on the user (the payload fill supplies it); only a required field with
        no default must be provided, otherwise it would be sent as a typed empty and
        rejected by ND.
        """
        context = info.context or {}
        if not context.get("state") or context.get("source") == "response":
            return self
        policy = getattr(self, "policy_type_marker", type(self).__name__)
        for field_name, field_info in type(self).model_fields.items():
            extra = field_info.json_schema_extra
            if not isinstance(extra, dict):
                continue
            alias = field_info.alias or field_name
            value = getattr(self, field_name, None)
            if value is None:
                if extra.get("required") and "payload_default" not in extra:
                    raise ValueError("'{0}' is required for policy_type '{1}'.".format(alias, policy))
                continue
            choices = extra.get("choices")
            if choices is not None and value not in choices:
                raise ValueError("'{0}'={1!r} is not a valid choice for policy_type '{2}'. Valid choices: {3}.".format(alias, value, policy, list(choices)))
            minimum = extra.get("minimum")
            if minimum is not None and isinstance(value, int) and not isinstance(value, bool) and value < minimum:
                raise ValueError("'{0}'={1} is below the minimum {2} for policy_type '{3}'.".format(alias, value, minimum, policy))
            maximum = extra.get("maximum")
            if maximum is not None and isinstance(value, int) and not isinstance(value, bool) and value > maximum:
                raise ValueError("'{0}'={1} exceeds the maximum {2} for policy_type '{3}'.".format(alias, value, maximum, policy))
            max_length = extra.get("max_length")
            if max_length is not None and isinstance(value, str) and len(value) > max_length:
                raise ValueError("'{0}' exceeds the maximum length of {1} characters for policy_type '{2}'.".format(alias, max_length, policy))
        return self

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
