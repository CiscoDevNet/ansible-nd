# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import re
from math import isfinite
from collections.abc import Sequence
from typing import Any, ClassVar, get_args

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    SecretStr,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.release_metadata import (
    NDMinimumVersion,
)

ND_COLLECTION_MINIMUM_VERSION = (4, 2, 1, 0)
ND_4_3_1 = (4, 3, 1, 0)
NO_ND_CONTROLLER_DEFAULT = object()


def parse_controller_product_version(value: object) -> tuple[int, int, int, int] | None:
    """Parse an ND product version, ordering lettered bug-fix releases after the base release."""
    product_version = re.sub(
        r"^(\d+)\.(\d+)\((\d+)([a-z]*)\)$",
        r"\1.\2.\3\4",
        str(value or "").strip().lower(),
    )
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)([a-z]*)", product_version)
    if match is None:
        return None
    major, minor, patch, suffix = match.groups()
    suffix_order = 0
    for character in suffix:
        suffix_order = suffix_order * 26 + ord(character) - ord("a") + 1
    return int(major), int(minor), int(patch), suffix_order


class ManageFabricReleaseValidationMixin:
    """Apply release-specific field rules declared in Pydantic metadata."""

    rest_send: Any
    release_gate_family: ClassVar[str] = "fabric"

    @staticmethod
    def _minimum_nd_version(model: NDBaseModel, field_name: str) -> tuple[tuple[int, int, int, int], str] | None:
        """Return a field's declared minimum ND version, if it is later than the collection floor."""
        field_info = type(model).model_fields.get(field_name)
        field_metadata = getattr(field_info, "metadata", ()) if field_info is not None else ()
        minimum_metadata = next(
            (item for item in field_metadata if isinstance(item, NDMinimumVersion)),
            None,
        )
        if minimum_metadata is None:
            return None

        minimum = parse_controller_product_version(minimum_metadata.value)
        if minimum is None:
            raise ValueError(f"Invalid ND minimum product version {minimum_metadata.value!r} on field {field_name!r}")
        if minimum <= ND_COLLECTION_MINIMUM_VERSION:
            return None
        return minimum, minimum_metadata.value

    @staticmethod
    def _all_model_fields(model: NDBaseModel, prefix: str = ""):
        """Yield declared fields recursively, including fields with defaults."""
        for field_name, field_info in type(model).model_fields.items():
            path = f"{prefix}.{field_name}" if prefix else field_name
            value = getattr(model, field_name, None)
            yield (
                model,
                field_name,
                field_info,
                value,
                path,
                field_name in model.model_fields_set,
            )
            if isinstance(value, NDBaseModel):
                yield from ManageFabricReleaseValidationMixin._all_model_fields(value, path)
            elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                for index, child in enumerate(value):
                    if isinstance(child, NDBaseModel):
                        yield from ManageFabricReleaseValidationMixin._all_model_fields(child, f"{path}[{index}]")

    @staticmethod
    def _release_constraint_errors(value: Any, constraint: dict[str, Any], path: str) -> list[str]:
        """Check supported JSON-schema-extra constraints without echoing values."""
        raw = value.get_secret_value() if isinstance(value, SecretStr) else value
        errors = []
        choices = constraint.get("choices")
        if choices is not None and raw not in choices:
            errors.append(f"{path} must be one of {', '.join(map(str, choices))}")
        pattern = constraint.get("pattern")
        if pattern is not None and (not isinstance(raw, str) or re.fullmatch(pattern, raw) is None):
            errors.append(f"{path} does not match its ND release-specific format")
        minimum_length = constraint.get("min_length")
        maximum_length = constraint.get("max_length")
        if minimum_length is not None and (not isinstance(raw, str) or len(raw) < minimum_length):
            errors.append(f"{path} must contain at least {minimum_length} characters")
        if maximum_length is not None and (not isinstance(raw, str) or len(raw) > maximum_length):
            errors.append(f"{path} must contain at most {maximum_length} characters")
        minimum = constraint.get("minimum")
        maximum = constraint.get("maximum")
        if minimum is not None and (not isinstance(raw, (int, float)) or isinstance(raw, bool) or raw < minimum):
            errors.append(f"{path} must be at least {minimum}")
        if maximum is not None and (not isinstance(raw, (int, float)) or isinstance(raw, bool) or raw > maximum):
            errors.append(f"{path} must be at most {maximum}")
        multiple_of = constraint.get("multiple_of")
        if multiple_of is not None and (not isinstance(raw, (int, float)) or isinstance(raw, bool) or raw % multiple_of != 0):
            errors.append(f"{path} must be a multiple of {multiple_of}")
        return errors

    @staticmethod
    def _controller_default_intervals(rules: Any, path: str) -> list[tuple]:
        """Validate disjoint product-version intervals for non-null scalar defaults."""
        if not isinstance(rules, list) or not rules:
            raise ValueError(f"nd_controller_defaults on {path!r} must be a nonempty list")
        intervals = []
        for rule in rules:
            if not isinstance(rule, dict):
                raise ValueError(f"nd_controller_defaults on {path!r} must contain mappings")
            if "value" not in rule or rule["value"] is None or not isinstance(rule["value"], (str, int, float, bool)):
                raise ValueError(f"Controller default on {path!r} must declare a non-null scalar value")
            if isinstance(rule["value"], float) and not isfinite(rule["value"]):
                raise ValueError(f"Controller default on {path!r} must be finite")
            minimum_text = rule.get("minimum_version")
            maximum_text = rule.get("maximum_exclusive_version")
            minimum = parse_controller_product_version(minimum_text) if minimum_text is not None else None
            maximum = parse_controller_product_version(maximum_text) if maximum_text is not None else None
            if minimum_text is not None and minimum is None:
                raise ValueError(f"Invalid controller-default minimum_version on {path!r}")
            if maximum_text is not None and maximum is None:
                raise ValueError(f"Invalid controller-default maximum_exclusive_version on {path!r}")
            if minimum is None and maximum is None:
                raise ValueError(f"Controller default on {path!r} must declare a version boundary")
            if minimum is not None and maximum is not None and minimum >= maximum:
                raise ValueError(f"Controller default on {path!r} has an invalid version interval")
            for previous_minimum, previous_maximum, _ in intervals:
                separated = (maximum is not None and previous_minimum is not None and maximum <= previous_minimum) or (
                    previous_maximum is not None and minimum is not None and previous_maximum <= minimum
                )
                if not separated:
                    raise ValueError(f"Overlapping ND controller defaults on {path!r}")
            intervals.append((minimum, maximum, rule["value"]))
        return intervals

    @classmethod
    def _controller_default(
        cls,
        rules: Any,
        field_info: Any,
        schema_extra: dict,
        version: tuple | None,
        path: str,
    ) -> Any:
        """Resolve comparison policy without supplying an outbound field value."""
        if "[" in path:
            raise ValueError(f"Controller-default comparison on {path!r} cannot use an indexed collection path")
        if (
            field_info.is_required()
            or field_info.default is not None
            or field_info.default_factory is not None
            or type(None) not in get_args(field_info.annotation)
        ):
            raise ValueError(f"Controller-default comparison on {path!r} requires a nullable default=None field")
        if schema_extra.get("secret") or "SecretStr" in str(field_info.annotation):
            raise ValueError(f"Controller-default comparison on {path!r} cannot apply to a secret field")
        intervals = cls._controller_default_intervals(rules, path)
        if version is None:
            return NO_ND_CONTROLLER_DEFAULT
        for minimum, maximum, value in intervals:
            if (minimum is None or version >= minimum) and (maximum is None or version < maximum):
                return value
        return NO_ND_CONTROLLER_DEFAULT

    def preflight(self, model_instances: Sequence[NDBaseModel]) -> None:
        """Reject supplied fields unsupported by the controller's product release."""
        affected = []
        raw_version = None
        version = None
        version_resolved = False
        for item in model_instances:
            comparison_defaults = getattr(item, "_nd_controller_default_comparisons", None)
            if comparison_defaults is not None:
                comparison_defaults = {}
                item._nd_controller_default_comparisons = comparison_defaults
            management = getattr(item, "management", None)
            if management is None:
                continue
            unsupported_fields = []
            for (
                model,
                field,
                field_info,
                value,
                path,
                was_supplied,
            ) in self._all_model_fields(management, "management"):
                minimum_info = self._minimum_nd_version(model, field)
                schema_extra = field_info.json_schema_extra if isinstance(field_info.json_schema_extra, dict) else {}
                release_constraints = schema_extra.get("nd_release_constraints", [])
                has_controller_defaults = "nd_controller_defaults" in schema_extra
                if minimum_info is None and not release_constraints and not has_controller_defaults:
                    continue
                if not version_resolved:
                    raw_version = self.rest_send.controller_product_version
                    version = parse_controller_product_version(raw_version)
                    version_resolved = True
                if minimum_info is not None:
                    minimum, minimum_text = minimum_info
                    if version is None or version < minimum:
                        if was_supplied:
                            unsupported_fields.append(f"{path} (requires ND {minimum_text} or later)")
                        elif value is not None:
                            # A Pydantic default for a newer-release field must
                            # not leak into payloads sent to an older controller.
                            # Keep the field unset so merged-state omission
                            # semantics are preserved as well.
                            if type(None) not in get_args(field_info.annotation):
                                raise ValueError(
                                    f"Release-gated field {path!r} with a non-None default " "must allow None so it can be omitted on older ND releases"
                                )
                            setattr(model, field, None)
                            model.model_fields_set.discard(field)
                if has_controller_defaults:
                    selected = self._controller_default(
                        schema_extra["nd_controller_defaults"],
                        field_info,
                        schema_extra,
                        version,
                        path,
                    )
                    field_available = minimum_info is None or (version is not None and version >= minimum_info[0])
                    if field_available and selected is not NO_ND_CONTROLLER_DEFAULT and not was_supplied and value is None:
                        if comparison_defaults is None:
                            raise ValueError(f"Model cannot retain controller-default comparison policy for {path!r}")
                        comparison_defaults[tuple(path.split("."))] = selected
                # Release-specific constraints validate user input. Defaults
                # are governed by their model definition and are not input.
                if not was_supplied:
                    continue
                if not isinstance(release_constraints, list):
                    raise ValueError(f"nd_release_constraints on {path!r} must be a list")
                for constraint in release_constraints:
                    if not isinstance(constraint, dict):
                        raise ValueError(f"nd_release_constraints on {path!r} must contain mappings")
                    minimum_text = constraint.get("minimum_version")
                    maximum_text = constraint.get("maximum_exclusive_version")
                    minimum = parse_controller_product_version(minimum_text) if minimum_text is not None else None
                    maximum = parse_controller_product_version(maximum_text) if maximum_text is not None else None
                    if minimum_text is not None and minimum is None:
                        raise ValueError(f"Invalid minimum_version {minimum_text!r} on field {path!r}")
                    if maximum_text is not None and maximum is None:
                        raise ValueError(f"Invalid maximum_exclusive_version {maximum_text!r} on field {path!r}")
                    if minimum is None and maximum is None:
                        raise ValueError(f"Release constraint on {path!r} must declare a version boundary")
                    if minimum is not None and maximum is not None and minimum >= maximum:
                        raise ValueError(f"Release constraint on {path!r} has an invalid version interval")
                    if version is None:
                        unsupported_fields.append(f"{path} (controller product version is required for release-specific validation)")
                        continue
                    active = (minimum is None or version >= minimum) and (maximum is None or version < maximum)
                    if active:
                        unsupported_fields.extend(self._release_constraint_errors(value, constraint, path))
            if unsupported_fields:
                affected.append(f"{item.get_identifier_value()} ({', '.join(sorted(unsupported_fields))})")

        if affected:
            reported = raw_version or "unknown"
            raise RuntimeError(
                f"{self.release_gate_family} settings require their declared minimum ND product versions; "
                f"controller product version is {reported!r} for fabric(s): "
                f"{', '.join(affected)}"
            )

        super().preflight(model_instances)


class ManageFabricIbgpReleaseValidationMixin(ManageFabricReleaseValidationMixin):
    """Release-validation error context for iBGP and AI iBGP VXLAN."""

    release_gate_family = "iBGP VXLAN"


class ManageFabricEbgpReleaseValidationMixin(ManageFabricReleaseValidationMixin):
    """Release-validation error context for eBGP and AI eBGP VXLAN."""

    release_gate_family = "eBGP VXLAN"


class ManageFabricExternalReleaseValidationMixin(ManageFabricReleaseValidationMixin):
    """Release-validation error context for External Connectivity fabrics."""

    release_gate_family = "External Connectivity"
