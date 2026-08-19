# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Typed failures raised by the REST transport boundary."""

from __future__ import annotations


class RestTransportError(ValueError):
    """A legacy-compatible transport failure with no HTTP response."""
