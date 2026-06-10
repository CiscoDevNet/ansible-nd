# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.links.templates.discriminated_union import LinkTemplateInputs
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


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

    @model_validator(mode="before")
    @classmethod
    def _inject_policy_marker(cls, data: Any) -> Any:
        """Copy policy_type into template_inputs so the discriminated union resolves."""
        if not isinstance(data, dict):
            return data
        policy_type = data.get("policy_type") or data.get("policyType")
        template_inputs = data.get("template_inputs") or data.get("templateInputs")
        if policy_type and isinstance(template_inputs, dict):
            template_inputs.setdefault("policy_type_marker", policy_type)
        return data


class NDLinkModel(NDBaseModel):
    """Nexus Dashboard Link configuration model.

    Identity is the composite (src_cluster, dst_cluster, src_fabric, dst_fabric,
    src_switch, dst_switch, src_intf, dst_intf). For single-cluster scope, the
    module swaps in MANAGE_SCOPE_IDENTIFIERS (no cluster names) at runtime.
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

    MANAGE_SCOPE_IDENTIFIERS: ClassVar[list[str]] = [
        "src_fabric_name",
        "dst_fabric_name",
        "src_switch_name",
        "dst_switch_name",
        "src_interface_name",
        "dst_interface_name",
    ]

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
        return data

    def to_config(self, **kwargs: Any) -> dict[str, Any]:
        """Config/output view with secret template_inputs fields scrubbed.

        Secrets are kept only in to_payload() (the controller request); they are
        removed from after/before/proposed output and from the diff.
        """
        data = super().to_config(**kwargs)
        self._strip_secret_template_inputs(data, by_alias=False)
        return data

    def _strip_secret_template_inputs(self, data: dict[str, Any], by_alias: bool) -> None:
        """Remove secret template_inputs fields from an output/diff dict in place."""
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
        """Serialize for POST/PUT with every declared template field present.

        ND's template engine rejects payloads that omit known fields; the UI
        works around this by sending type-appropriate empties for anything
        the user didn't set. We mirror that after normal serialization.
        """
        data = super().to_payload(**kwargs)
        self._fill_template_inputs_defaults(data)
        return data

    def _fill_template_inputs_defaults(self, data: dict[str, Any]) -> None:
        """Restore template fields stripped by exclude_none with typed empties."""
        if self.config_data is None or self.config_data.template_inputs is None:
            return
        config_data = data.get("configData")
        if not isinstance(config_data, dict):
            return
        template_inputs = config_data.get("templateInputs")
        if not isinstance(template_inputs, dict):
            return
        tmpl_cls = type(self.config_data.template_inputs)
        for field_name, field_info in tmpl_cls.model_fields.items():
            if field_info.exclude:
                continue
            alias = field_info.alias or field_name
            if template_inputs.get(alias) is None:
                template_inputs[alias] = self._empty_for_annotation(field_info.annotation)

    @staticmethod
    def _empty_for_annotation(annotation: Any) -> Any:
        """Pick an empty value matching an Optional[...] field's underlying type."""
        import types
        from typing import Union, get_args, get_origin

        # Under ``from __future__ import annotations`` Pydantic resolves ``X | None``
        # fields to ``types.UnionType`` rather than ``typing.Union``; accept both.
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
                    src_fabric_name=dict(type="str"),
                    dst_fabric_name=dict(type="str"),
                    src_switch_name=dict(type="str"),
                    dst_switch_name=dict(type="str"),
                    src_interface_name=dict(type="str"),
                    dst_interface_name=dict(type="str"),
                    src_switch_id=dict(type="str"),
                    dst_switch_id=dict(type="str"),
                    src_switch_ip=dict(type="str"),
                    dst_switch_ip=dict(type="str"),
                    link_type=dict(type="str", default="multi_cluster_planned_link"),
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
