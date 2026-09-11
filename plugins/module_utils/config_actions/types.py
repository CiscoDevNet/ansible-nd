# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Shared dataclasses for repository-wide config action parsing, validation, planning, and result reporting.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ConfigActionsDefaults:
    """
    # Summary

    Default values for a config action policy. `None` means the option is not defaulted by that policy.

    ## Raises

    None
    """

    save: bool | None = None
    deploy: bool | None = None
    type: str | None = None


@dataclass(frozen=True)
class ConfigActionsPolicy:
    """
    # Summary

    Module-family config action capabilities and compatibility defaults.

    ## Raises

    None
    """

    name: str
    supported: frozenset[str]
    defaults: ConfigActionsDefaults
    allowed_types: frozenset[str] = frozenset()
    deploy_requires_save: bool = False
    resource_interaction: str = "none"
    resource_deploy_type: str = "resource"
    read_only_states: frozenset[str] = frozenset({"gathered"})
    config_key: str = "config"
    resource_deploy_key: str = "deploy"


@dataclass(frozen=True)
class ConfigActions:
    """
    # Summary

    Normalized config action intent after policy defaults and validation.

    ## Raises

    None
    """

    save: bool
    deploy: bool
    type: str | None
    provided: bool
    explicit_options: frozenset[str] = frozenset()
    resource_deploy_provided: bool = False
    resource_deploy_indexes: tuple[int, ...] = ()
    resource_deploy_overrides: tuple[bool | None, ...] = ()

    def deploy_requested(self) -> bool:
        """
        # Summary

        Return whether any top-level or per-resource deploy action is enabled.

        ## Raises

        None
        """
        return self.deploy or any(override is True for override in self.resource_deploy_overrides)

    def resource_deploy_enabled(self, index: int) -> bool:
        """
        # Summary

        Return the effective deploy decision for a resource item.

        ## Raises

        ### IndexError

        - If `index` is outside the normalized resource override tuple.
        """
        override = self.resource_deploy_overrides[index]
        return self.deploy if override is None else override

    def to_result(self) -> dict[str, Any]:
        """
        # Summary

        Return a serializable representation suitable for module output.

        ## Raises

        None
        """
        return {
            "save": self.save,
            "deploy": self.deploy,
            "type": self.type,
            "provided": self.provided,
            "explicit_options": sorted(self.explicit_options),
            "resource_deploy_provided": self.resource_deploy_provided,
            "resource_deploy_indexes": list(self.resource_deploy_indexes),
        }


@dataclass(frozen=True)
class ConfigActionsContext:
    """
    # Summary

    Runtime context supplied by a module workflow to the config actions controller.

    ## Raises

    None
    """

    fabric_names: tuple[str, ...]
    state: str | None = None
    check_mode: bool = False
    eligible: bool = True
    reason: str = "actions_requested"
    switch_ids: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    switch_ids_by_fabric: Mapping[str, Sequence[str]] = field(default_factory=dict)
    resources_by_fabric: Mapping[str, Sequence[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class ConfigActionStepResult:
    """
    # Summary

    Result for one save or deploy action step.

    ## Raises

    None
    """

    action: str
    status: str
    scope: str | None = None
    target: str | None = None
    response: Any = None
    error: str | None = None
    error_type: str | None = None
    http_status: int | None = None
    request_payload: Any = None
    response_payload: Any = None
    raw: Any = None

    def to_result(self) -> dict[str, Any]:
        """
        # Summary

        Return a serializable action-step result.

        ## Raises

        None
        """
        result: dict[str, Any] = {
            "action": self.action,
            "status": self.status,
        }
        if self.scope is not None:
            result["scope"] = self.scope
        if self.target is not None:
            result["target"] = self.target
        if self.response is not None:
            result["response"] = self.response
        if self.error is not None:
            result["error"] = self.error
        if self.error_type is not None:
            result["error_type"] = self.error_type
        if self.http_status is not None:
            result["http_status"] = self.http_status
        if self.request_payload is not None:
            result["request_payload"] = self.request_payload
        if self.response_payload is not None:
            result["response_payload"] = self.response_payload
        if self.raw is not None:
            result["raw"] = self.raw
        return result


@dataclass(frozen=True)
class ConfigActionsResult:
    """
    # Summary

    Common config action result object produced by the controller.

    ## Raises

    None
    """

    requested: ConfigActions
    effective: ConfigActions
    status: str
    reason: str
    targets: Mapping[str, Sequence[str]] = field(default_factory=dict)
    actions: tuple[ConfigActionStepResult, ...] = ()

    def to_result(self) -> dict[str, Any]:
        """
        # Summary

        Return a serializable config action result for module output.

        ## Raises

        None
        """
        return {
            "requested": self.requested.to_result(),
            "effective": self.effective.to_result(),
            "status": self.status,
            "reason": self.reason,
            "targets": {key: list(value) for key, value in self.targets.items()},
            "actions": [step.to_result() for step in self.actions],
        }
