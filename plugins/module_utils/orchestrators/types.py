# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.nd_state_reconciliation import MutationResult

# Pylint's sanity version cannot infer runtime PEP 604 unions of generic aliases.
# pylint: disable=unsupported-binary-operation
ResponseType = list[dict[str, Any]] | dict[str, Any] | None
MutationResponseType = list[dict[str, Any]] | dict[str, Any] | MutationResult | None
