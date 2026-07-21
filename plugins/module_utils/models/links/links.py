# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, ValidationError, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.links.templates.base import LinkTemplateBase
from ansible_collections.cisco.nd.plugins.module_utils.models.links.templates.discriminated_union import LinkTemplateInputs, all_secret_template_input_keys
from ansible_collections.cisco.nd.plugins.module_utils.models.links.templates.unsupported import UnsupportedTemplateInputs
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.utils import NO_LOG_PLACEHOLDER


class LinkConfigDataModel(NDNestedModel):
    """configData block: policy_type drives which templateInputs subclass parses."""

    policy_type: str | None = Field(default=None, alias="policyType")
    template_inputs: LinkTemplateInputs | None = Field(default=None, alias="templateInputs")
    template_name: str | None = Field(default=None, alias="templateName")

    def merge(self, other: LinkConfigDataModel) -> LinkConfigDataModel:
        """Reject inline policy_type changes; ND requires delete and recreate for those."""
        if isinstance(other, LinkConfigDataModel) and self.policy_type and other.policy_type and self.policy_type != other.policy_type:
            raise Exception(
                "Cannot change policy_type from '{0}' to '{1}' on an existing link. "
                "ND requires deleting the link first and recreating with the new "
                "policy_type. Run this module with state=deleted for this link, "
                "then re-run with state=merged.".format(self.policy_type, other.policy_type)
            )
        return super().merge(other)

    @model_validator(mode="wrap")
    @classmethod
    def _tolerate_unsupported_on_read(cls, data: Any, handler: Any, info: Any) -> LinkConfigDataModel:
        """Preserve genuinely unsupported controller links instead of aborting the read.

        Strict parsing (discriminated union + write-contract validation) is kept for
        user input -- write states thread ``context["state"]`` -- so bad config still
        fails fast. On a controller read a policy type this module does not model
        (no matching discriminator) is captured as an opaque ``UnsupportedTemplateInputs``
        record rather than raising ``ValidationError`` and aborting ``query_all``.

        A *supported* policy carrying extra or out-of-range response fields no longer
        reaches this fallback: ``LinkTemplateBase._drop_unknown_on_read`` strips unknown
        keys on reads and the write-contract checks are skipped for responses, so such a
        link resolves to its real policy model and stays mutable.
        """
        try:
            return handler(data)
        except ValidationError:
            context = info.context or {}
            # Tolerate only controller reads (from_response marks source="response").
            # User input -- and any direct construction -- stays strictly validated.
            if context.get("source") != "response" or not isinstance(data, dict):
                raise
            return cls._build_unsupported(data)

    @classmethod
    def _build_unsupported(cls, data: dict[str, Any]) -> LinkConfigDataModel:
        """Build a fallback config_data preserving the raw policy type and inputs."""
        policy_type = data.get("policy_type") or data.get("policyType")
        template_name = data.get("template_name") or data.get("templateName")
        raw = data.get("template_inputs")
        if raw is None:
            raw = data.get("templateInputs")
        template_inputs = dict(raw) if isinstance(raw, dict) else {}
        template_inputs.pop("policy_type_marker", None)
        fallback = UnsupportedTemplateInputs.model_validate(template_inputs)
        return cls.model_construct(policy_type=policy_type, template_name=template_name, template_inputs=fallback)

    @model_validator(mode="after")
    def _require_template_name_for_user_defined(self, info: Any) -> LinkConfigDataModel:
        """userDefined requires template_name (ND schema / OpenAPI).

        Enforced only on user-supplied config -- write states thread
        ``context["state"]`` through validation -- so a controller read that
        somehow omits it is tolerated rather than aborting ``query_all``.
        """
        context = info.context or {}
        if context.get("state") and self.policy_type == "userDefined" and not self.template_name:
            raise ValueError("template_name is required when config_data.policy_type is 'userDefined'.")
        return self

    @model_validator(mode="before")
    @classmethod
    def _inject_policy_marker(cls, data: Any) -> Any:
        """Copy the public ``policy_type`` into ``template_inputs`` as the internal
        discriminator so the discriminated union resolves.

        The documented ``policy_type`` is the sole authority for schema selection:
        any caller-supplied ``policy_type_marker`` is overwritten, so free-form
        input cannot select a different template model than the declared policy.
        ``template_inputs`` is located by key presence (not truthiness) so an
        explicit empty dict validates identically under the snake_case and the
        API-alias spelling.

        Returns a shallow copy rather than mutating in place: ``data`` is a
        reference into ``module.params``, so an in-place write would leak the
        internal marker back into the invocation echo.
        """
        if not isinstance(data, dict):
            return data
        policy_type = data.get("policy_type") or data.get("policyType")
        if not policy_type:
            return data
        key = "template_inputs" if "template_inputs" in data else "templateInputs" if "templateInputs" in data else None
        if key is None:
            return data
        template_inputs = data.get(key)
        if not isinstance(template_inputs, dict):
            return data
        return {**data, key: {**template_inputs, "policy_type_marker": policy_type}}


class NDLinkModel(NDBaseModel):
    """Nexus Dashboard Link configuration model.

    Identity is the composite (src_cluster, dst_cluster, src_fabric, dst_fabric,
    src_switch, dst_switch, src_intf, dst_intf). The module overwrites
    ``identifiers`` at runtime from the active strategy's ``identifier_fields``
    (see ``nd_manage_links.main``); single-cluster (manage) scope drops the
    cluster-name keys.
    """

    identifiers: ClassVar[list[str] | None] = [
        "src_cluster_name",
        "dst_cluster_name",
        "src_fabric_name",
        "dst_fabric_name",
        "src_switch_name",
        "dst_switch_name",
        "src_interface_name",
        "dst_interface_name",
    ]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "composite"

    unwanted_keys: ClassVar[list] = [
        ["linkId"],
        ["linkState"],
        ["linkDiscovered"],
        ["linkPlanned"],
        ["linkPresent"],
        ["portChannel"],
        ["srcSwitchInfo"],
        ["dstSwitchInfo"],
    ]

    exclude_from_diff: ClassVar[set] = {
        "link_id",
        "link_type",
        "src_switch_id",
        "dst_switch_id",
        "src_switch_ip",
        "dst_switch_ip",
    }

    payload_exclude_fields: ClassVar[set] = {
        "link_id",
        "link_type",
        "src_switch_ip",
        "dst_switch_ip",
    }

    src_cluster_name: str | None = Field(default=None, alias="srcClusterName")
    dst_cluster_name: str | None = Field(default=None, alias="dstClusterName")
    src_fabric_name: str | None = Field(default=None, alias="srcFabricName")
    dst_fabric_name: str | None = Field(default=None, alias="dstFabricName")
    src_switch_name: str | None = Field(default=None, alias="srcSwitchName")
    dst_switch_name: str | None = Field(default=None, alias="dstSwitchName")
    src_interface_name: str | None = Field(default=None, alias="srcInterfaceName")
    dst_interface_name: str | None = Field(default=None, alias="dstInterfaceName")

    link_type: str | None = Field(default=None, alias="linkType")
    link_id: str | None = Field(default=None, alias="linkId")
    src_switch_id: str | None = Field(default=None, alias="srcSwitchId")
    dst_switch_id: str | None = Field(default=None, alias="dstSwitchId")
    src_switch_ip: str | None = Field(default=None, alias="srcSwitchIp")
    dst_switch_ip: str | None = Field(default=None, alias="dstSwitchIp")

    config_data: LinkConfigDataModel | None = Field(default=None, alias="configData")

    @property
    def is_unsupported_policy(self) -> bool:
        """True when this link uses a policy type the module does not model.

        Such links are read from ND as opaque records (see
        ``LinkConfigDataModel._tolerate_unsupported_on_read``); the module keeps
        them visible but never modifies or implicitly deletes them.
        """
        template_inputs = getattr(self.config_data, "template_inputs", None)
        return isinstance(template_inputs, UnsupportedTemplateInputs)

    def describe_unsupported_policy(self) -> str:
        """Human-readable identity + policy type for an unsupported link."""
        policy_type = getattr(self.config_data, "policy_type", None)
        identity = self.link_id or self.get_identifier_value()
        return "Link {0} uses unsupported policy type '{1}'".format(identity, policy_type)

    # --- Orientation independence (physical links, intra- and inter-fabric) ----
    # A physical link has no inherent direction: ND can return it with the
    # endpoints reversed relative to the playbook, whether the two ends are in the
    # same fabric (numbered/unnumbered) or different fabrics (VRF lite, DCI,
    # multisite, MPLS). For every link the identity is made order-independent and
    # the diff view is canonicalized, so a reversed cable is matched (not duplicated
    # on merged, found on deleted, not delete+recreated on overridden) and compares
    # equal. Payloads keep the user's orientation; canonicalization is comparison
    # only. The directional template pairs are derived per policy from the model's
    # own fields, so each policy gets its own src/dst set.
    #
    # Known limitation: a few inter-fabric policies pair a masked source address
    # with a plain destination (srcIpAddressMask / dstIpAddress); the mask lives on
    # the field, not the endpoint, so a value swap would move it to the wrong end.
    # Those asymmetric address fields are deliberately NOT reoriented -- identity is
    # still orientation-independent, but declare such a link in ND's orientation to
    # stay idempotent on the addressing fields.

    _IDENTITY_ALIAS_PAIRS: ClassVar[list] = [
        ("srcClusterName", "dstClusterName"),
        ("srcFabricName", "dstFabricName"),
        ("srcSwitchName", "dstSwitchName"),
        ("srcInterfaceName", "dstInterfaceName"),
    ]

    @staticmethod
    def _dst_counterpart(alias: str) -> str | None:
        """The destination alias paired with a source-side alias, or None.

        Handles a leading ``src`` prefix (``srcIp`` -> ``dstIp``) and an infix
        ``Src`` (``dhcpRelayOnSrcInterface`` -> ``dhcpRelayOnDstInterface``). Only a
        clean src<->dst rename is treated as directional, so asymmetric address/mask
        pairs (whose two aliases are not a rename of each other) are left alone.
        """
        if alias.startswith("src"):
            return "dst" + alias[3:]
        if "Src" in alias:
            return alias.replace("Src", "Dst")
        return None

    def _template_directional_pairs(self) -> list:
        """The (srcAlias, dstAlias) template-input pairs to swap when this link is
        reversed, derived from this link's own policy model so each policy gets its
        own directional set (every symmetric src/dst field the model declares)."""
        template_inputs = getattr(self.config_data, "template_inputs", None)
        if template_inputs is None:
            return []
        aliases = {(field_info.alias or name) for name, field_info in type(template_inputs).model_fields.items()}
        pairs: list = []
        paired: set = set()
        for alias in sorted(aliases):
            counterpart = self._dst_counterpart(alias)
            if counterpart and counterpart != alias and counterpart in aliases and alias not in paired and counterpart not in paired:
                pairs.append((alias, counterpart))
                paired.update((alias, counterpart))
        return pairs

    def _endpoints(self) -> tuple:
        ids = self.identifiers or []
        src = tuple(getattr(self, f, None) for f in ids if f.startswith("src_"))
        dst = tuple(getattr(self, f, None) for f in ids if f.startswith("dst_"))
        return src, dst

    @staticmethod
    def _endpoint_key(endpoint: tuple) -> tuple:
        return tuple("" if value is None else str(value) for value in endpoint)

    def get_identifier_value(self) -> Any:
        """Composite identity, made orientation-independent for every physical link
        (intra- and inter-fabric) so a reversed cable resolves to one identity."""
        src, dst = self._endpoints()
        if not any(src) and not any(dst):
            return super().get_identifier_value()
        low, high = sorted((src, dst), key=self._endpoint_key)
        return low + high

    @staticmethod
    def _swap_keys(data: dict[str, Any], first: str, second: str) -> None:
        """Swap two keys in place, preserving exclude_none (drop None results)."""
        if first not in data and second not in data:
            return
        first_value, second_value = data.get(first), data.get(second)
        data.pop(first, None)
        data.pop(second, None)
        if second_value is not None:
            data[first] = second_value
        if first_value is not None:
            data[second] = first_value

    def _canonicalize_orientation(self, data: dict[str, Any]) -> None:
        """Reorient a diff dict to a canonical endpoint order for any physical link.

        Comparison-only: payloads keep the user's orientation. Because both existing
        and proposed links canonicalize identically, a reversed cable compares equal
        instead of showing a spurious change. Both the endpoint identity fields and
        the policy's directional template fields are swapped.
        """
        src, dst = self._endpoints()
        if self._endpoint_key(src) <= self._endpoint_key(dst):
            return  # already in canonical order
        for first, second in self._IDENTITY_ALIAS_PAIRS:
            self._swap_keys(data, first, second)
        template_inputs = (data.get("configData") or {}).get("templateInputs")
        if isinstance(template_inputs, dict):
            for first, second in self._template_directional_pairs():
                self._swap_keys(template_inputs, first, second)

    # User-managed interface fields that survive the preprovision->numbered
    # realization: after ND converts the link, the preprovision declaration still
    # governs these (persistent declarative intent). ND-assigned addresses and
    # numbered-only fields are preserved and never compared against the declaration.
    _PREPROVISION_MANAGED_FIELDS: ClassVar[tuple] = (
        "src_interface_description",
        "dst_interface_description",
        "src_interface_config",
        "dst_interface_config",
    )

    def _is_realized_preprovision_of(self, other: Any) -> bool:
        """True when ``self`` (existing, from ND) is the realized ``numbered`` form
        of ``other`` (proposed, a ``preprovision`` declaration).

        After a planned ``preprovision`` link comes up and ND runs
        Save/Recalculate, ND converts it to a ``numbered`` link with
        controller-assigned addresses. Reapplying the ``preprovision`` source must
        recognise this expected lifecycle rather than treating it as a policy change.
        """
        self_policy = getattr(self.config_data, "policy_type", None)
        other_policy = getattr(getattr(other, "config_data", None), "policy_type", None)
        return self_policy == "numbered" and other_policy == "preprovision"

    def _preprovision_managed_fields_match(self, other: Any) -> bool:
        """True when every user-managed field the proposed ``preprovision`` declaration
        actually set already matches this realized ``numbered`` link.

        Only fields the user explicitly declared are compared (merged semantics), so
        an omitted field is never a change. ND-assigned addresses and numbered-only
        fields are ignored entirely.
        """
        existing_ti = getattr(self.config_data, "template_inputs", None)
        proposed_ti = getattr(getattr(other, "config_data", None), "template_inputs", None)
        declared = getattr(proposed_ti, "model_fields_set", set())
        for field_name in self._PREPROVISION_MANAGED_FIELDS:
            if field_name not in declared:
                continue
            if getattr(existing_ti, field_name, None) != getattr(proposed_ti, field_name, None):
                return False
        return True

    def get_diff(self, other: Any, exclude_unset: bool = False) -> bool:
        """Diff comparison.

        Persistent-intent lifecycle for a realized ``preprovision``->``numbered`` link:
        the link stays ``numbered`` on ND, but the ``preprovision`` declaration still
        governs the interface description/config fields. Report no diff only when those
        user-managed fields are unchanged; a later edit to one of them is a real change
        (so the module keeps ND's realized numbered link and its assigned addresses,
        yet still applies description/config updates).
        """
        if self._is_realized_preprovision_of(other):
            return self._preprovision_managed_fields_match(other)
        return super().get_diff(other, exclude_unset=exclude_unset)

    def merge(self, other: Any) -> "NDBaseModel":
        """Merge a proposed declaration into this existing link.

        For a realized ``preprovision``->``numbered`` link, overlay only the
        user-managed interface description/config fields onto the existing
        ``numbered`` link and keep it ``numbered``, so the resulting update is a valid
        ``numbered`` PUT that preserves ND-assigned addresses and numbered-only fields
        (never a rejected policy change). Every other case uses the standard merge.
        """
        if self._is_realized_preprovision_of(other):
            existing_ti = self.config_data.template_inputs
            proposed_ti = getattr(other.config_data, "template_inputs", None)
            declared = getattr(proposed_ti, "model_fields_set", set())
            for field_name in self._PREPROVISION_MANAGED_FIELDS:
                if field_name in declared:
                    setattr(existing_ti, field_name, getattr(proposed_ti, field_name, None))
            return self
        return super().merge(other)

    @classmethod
    def collect_secret_values(cls, config_item: dict[str, Any]) -> set[str]:
        """Secret values for no_log masking, including free-form template_inputs.

        Extends the base (top-level secret fields) to also cover the secret keys
        nested inside the free-form ``config_data.template_inputs`` dict, which
        Ansible cannot mark ``no_log`` in the argument spec.
        """
        values = super().collect_secret_values(config_item)
        if isinstance(config_item, dict):
            config_data = config_item.get("config_data") or {}
            template_inputs = config_data.get("template_inputs") or {}
            if isinstance(template_inputs, dict):
                for key in all_secret_template_input_keys(by_alias=False):
                    value = template_inputs.get(key)
                    if value:
                        values.add(value)
        return values

    def to_diff_dict(self, **kwargs: Any) -> dict[str, Any]:
        """Serialize for diff comparison and strip noise keys ND returns on read."""
        data = self.model_dump(
            by_alias=True,
            exclude_none=True,
            exclude=self.exclude_from_diff or None,
            mode="json",
            **kwargs,
        )
        for key_path in self.unwanted_keys:
            self._remove_nested_key(data, key_path)
        self._strip_secret_template_inputs(data, by_alias=True)
        self._canonicalize_orientation(data)
        return data

    def to_config(self, **kwargs: Any) -> dict[str, Any]:
        """Config/output view with secret template_inputs fields scrubbed.

        Secrets are kept only in to_payload() (the controller request); they are
        removed from after/before/proposed output and from the diff.
        """
        data = super().to_config(**kwargs)
        self._strip_secret_template_inputs(data, by_alias=False, mask=True)
        return data

    def _strip_secret_template_inputs(self, data: dict[str, Any], by_alias: bool, mask: bool = False) -> None:
        """Handle secret template_inputs fields in an output/diff dict in place.

        ``mask=True`` (output) replaces a present secret with ``NO_LOG_PLACEHOLDER``
        so the key stays visible; ``mask=False`` (diff) pops it entirely so a
        secret-only change is never detected.
        """
        if self.config_data is None or self.config_data.template_inputs is None:
            return
        config_data_key = "configData" if by_alias else "config_data"
        template_inputs_key = "templateInputs" if by_alias else "template_inputs"
        config_data = data.get(config_data_key)
        if not isinstance(config_data, dict):
            return
        template_inputs = config_data.get(template_inputs_key)
        if not isinstance(template_inputs, dict):
            return
        for key in type(self.config_data.template_inputs).secret_field_keys(by_alias=by_alias):
            if mask:
                if key in template_inputs:
                    template_inputs[key] = NO_LOG_PLACEHOLDER
            else:
                template_inputs.pop(key, None)

    @staticmethod
    def _remove_nested_key(data: dict, key_path: list[str]) -> None:
        """Remove a key from a dict by path (noop if any segment is missing)."""
        current = data
        for key in key_path[:-1]:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return
        if isinstance(current, dict) and key_path[-1] in current:
            del current[key_path[-1]]

    def to_payload(self, **kwargs: Any) -> dict[str, Any]:
        """Serialize for POST/PUT, sending ND's documented defaults for unset template fields."""
        data = super().to_payload(**kwargs)
        self._fill_template_inputs_defaults(data)
        return data

    def _fill_template_inputs_defaults(self, data: dict[str, Any]) -> None:
        """Fill every unset template field so the payload carries all keys.

        ND's Jython template engine references every declared field by key, so a
        missing key raises during template execution. Each field the user did not
        set is sent with its documented ND default when it has one (``mtu 9216``,
        ``speed auto``), otherwise as a typed empty (``""`` / ``0`` / ``false``).
        Secrets have no documented default, so an unset secret is sent as ``""``;
        it is still excluded from the diff, so a secret-only change never triggers
        an update. Re-supply a secret when updating a link, or it is written empty.
        """
        if self.config_data is None or self.config_data.template_inputs is None:
            return
        config_data = data.get("configData")
        if not isinstance(config_data, dict):
            return
        template_inputs = config_data.get("templateInputs")
        if not isinstance(template_inputs, dict):
            return
        tmpl_cls = type(self.config_data.template_inputs)
        LinkTemplateBase.apply_payload_defaults(template_inputs, tmpl_cls)

    @classmethod
    def get_argument_spec(cls) -> dict:
        """Ansible argument spec; template_inputs is a generic dict (Pydantic validates)."""
        return dict(
            config=dict(
                type="list",
                elements="dict",
                required=False,
                options=dict(
                    src_cluster_name=dict(type="str"),
                    dst_cluster_name=dict(type="str"),
                    # Fabric and interface names on both ends are mandatory parts of
                    # every link's composite identity (Manage and OneManage). Requiring
                    # them here fails an incomplete item early at the Ansible boundary
                    # with a field-specific message, instead of later with an
                    # implementation-oriented composite-identifier exception. The
                    # top-level ``config`` stays optional so ``state: gathered`` (no
                    # config) still runs. Cluster identity for OneManage is scope
                    # dependent and validated at runtime once ``link_scope`` resolves.
                    src_fabric_name=dict(type="str", required=True),
                    dst_fabric_name=dict(type="str", required=True),
                    src_switch_name=dict(type="str"),
                    dst_switch_name=dict(type="str"),
                    src_interface_name=dict(type="str", required=True),
                    dst_interface_name=dict(type="str", required=True),
                    src_switch_id=dict(type="str"),
                    dst_switch_id=dict(type="str"),
                    src_switch_ip=dict(type="str"),
                    dst_switch_ip=dict(type="str"),
                    config_data=dict(
                        type="dict",
                        options=dict(
                            policy_type=dict(
                                type="str",
                                choices=[
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
                                ],
                            ),
                            template_name=dict(type="str"),
                            template_inputs=dict(type="dict"),
                        ),
                    ),
                ),
                required_one_of=[
                    ["src_switch_name", "src_switch_ip", "src_switch_id"],
                    ["dst_switch_name", "dst_switch_ip", "dst_switch_id"],
                ],
            ),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "overridden", "deleted", "gathered"],
            ),
        )
