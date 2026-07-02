# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Pydantic feature models for the `nd_maintenance_mode` module.

The endpoint backing this module is a switch *action* (not a CRUD resource):
`POST /api/v1/manage/fabrics/{fabric_name}/switchActions/changeSystemMode`. A single
invocation sets one `mode` for a list of `switchIds`. The Ansible-facing `config` is a
dict (not a list) and is wrapped into a 1-item list by the module's `main()` so it can
flow through the standard `NDStateMachine` driver as a singleton.
"""

from __future__ import annotations

from typing import Any, ClassVar, Dict, List, Literal, Optional, Set

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


class MaintenanceModeSwitchModel(NDNestedModel):
    """
    # Summary

    Single switch entry in `config.switches`. The user supplies `switch_ip`; the orchestrator resolves
    it to the switch serial number (`switchId`) from the bulk `EpManageSwitchesListGet` snapshot cached
    by `query_all()` before building the `switchIds` array in the POST body.

    ## Raises

    None
    """

    switch_ip: str = Field(alias="switchIp", description="Switch management IP")


class MaintenanceModeModel(NDBaseModel):
    """
    # Summary

    Singleton model for a `changeSystemMode` operation. One model instance describes one POST: a
    target `mode`, optional deploy / blocking / ticket_id query params, and the set of switches
    to which the mode applies.

    The model is used in two flavors:

    - **Proposed** — built from the user's Ansible `config` dict via `from_config`. Populates `mode`,
      `deploy`, `blocking`, `ticket_id`, `switches`. `switch_modes` is `None`.
    - **Snapshot** — built from the orchestrator's `query_all()` response via `from_response`. Populates
      `switches` (same set the user asked about) and `switch_modes` (per-IP current `intendedSystemMode`
      read from the live wire). `mode` is left unset on the snapshot.

    The custom `get_diff` compares the proposed `mode` against each switch's snapshot
    `intendedSystemMode` and returns `True` (no diff) only when every requested switch already has
    intent matching the desired mode.

    ## Raises

    None
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[Optional[List[str]]] = []
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "singleton"

    # --- Serialization Configuration ---

    # The wire POST body is just `{"mode": ..., "switchIds": [...]}`. Everything else is either a
    # query param (deploy/blocking/ticket_id) or client-side metadata (switches, switch_modes).
    # `switchIds` itself is injected by the orchestrator after resolving switch_ip -> switchId.
    payload_exclude_fields: ClassVar[Set[str]] = {"deploy", "blocking", "ticket_id", "switches", "switch_modes"}

    # Query params do not influence whether a state change is needed.
    exclude_from_diff: ClassVar[Set[str]] = {"deploy", "blocking", "ticket_id", "switch_modes"}

    # --- Fields ---

    # Optional so a snapshot built from query_all can omit it; argspec enforces required for users.
    mode: Optional[Literal["maintenance", "normal"]] = Field(default=None, alias="mode")
    deploy: bool = Field(default=False, alias="deploy")
    blocking: bool = Field(default=False, alias="blocking")
    ticket_id: Optional[str] = Field(default=None, alias="ticketId")
    switches: List[MaintenanceModeSwitchModel] = Field(default_factory=list, alias="switches")

    # Snapshot-only: map of switch_ip -> current intendedSystemMode. Populated by query_all().
    switch_modes: Optional[Dict[str, str]] = Field(default=None, exclude=True)

    # --- Validators ---

    @model_validator(mode="after")
    def _require_switches_when_mode_set(self) -> "MaintenanceModeModel":
        """
        # Summary

        Reject `switches: []` when a target `mode` is requested. The Ansible argspec marks `switches`
        as `required=True`, but `required=True` only enforces key presence — not non-empty content.
        Without this check, a user submitting `switches: []` would silently produce a no-op against
        the `changeSystemMode` action endpoint (which itself requires `switchIds` with `minItems=1`)
        and the module would report `changed=False` instead of telling the user the request was
        malformed.

        Snapshots built by `query_all` (and other `mode=None` callers) are exempt; the gate is
        keyed on `mode` so only proposed-config instances are checked.

        ## Raises

        ### ValueError

        - If `mode` is set and `switches` is empty.
        """
        if self.mode is not None and not self.switches:
            raise ValueError("config.switches must contain at least one switch when 'mode' is set.")
        return self

    # --- Custom Diff (per-switch mode comparison) ---

    def get_diff(self, other: "NDBaseModel", exclude_unset: bool = False) -> bool:
        """
        # Summary

        Return `True` ("no_diff") iff every switch in the proposed config already has its current
        `intendedSystemMode` (from the snapshot) equal to the proposed `mode`.

        `self` is the snapshot (existing); `other` is the proposed config. Default `NDBaseModel.get_diff`
        does a generic subset check that does not understand the per-switch mode comparison we need.

        ## Raises

        None
        """
        if not isinstance(other, MaintenanceModeModel):
            return False
        if other.mode is None or not other.switches:
            return True
        snapshot_modes = self.switch_modes or {}
        for switch in other.switches:
            if snapshot_modes.get(switch.switch_ip) != other.mode:
                return False
        return True

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> Dict[str, Any]:
        """
        # Summary

        Return the Ansible argspec for the `config` and `state` parameters. `config` is a dict
        (matching the underlying ND API body shape); `state` is restricted to `merged`. A future
        `gathered` state will be added when Gaspard's framework support lands.

        ## Raises

        None
        """
        return dict(
            fabric_name=dict(type="str", required=True),
            config=dict(
                type="dict",
                required=True,
                options=dict(
                    mode=dict(type="str", required=True, choices=["maintenance", "normal"]),
                    deploy=dict(type="bool", default=False),
                    blocking=dict(type="bool", default=False),
                    ticket_id=dict(type="str"),
                    switches=dict(
                        type="list",
                        elements="dict",
                        required=True,
                        options=dict(
                            switch_ip=dict(type="str", required=True),
                        ),
                    ),
                ),
            ),
            state=dict(type="str", default="merged", choices=["merged"]),
        )
