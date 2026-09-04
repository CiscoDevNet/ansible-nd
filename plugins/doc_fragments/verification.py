# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations


class ModuleDocFragment:
    """Documentation shared by modules that support post-write verification."""

    DOCUMENTATION = r"""
options:
  verify:
    description:
    - Controls an optional controller readback after all write, deploy, save, and attachment actions finish.
    - When omitted, C(after) remains the locally predicted state for backward compatibility.
    - Supplying an empty dictionary does not enable verification; set O(verify.enabled=true) explicitly.
    - Verification is never performed in check mode; C(after) remains predictive in check mode.
    - A successful readback is a controller-backed snapshot, not a guarantee of operational convergence.
    type: dict
    suboptions:
      enabled:
        description:
        - Enables or disables the final controller readback.
        type: bool
        default: false
      attempts:
        description:
        - Maximum attempts for each eligible HTTP request, including the initial request.
        type: int
        default: 5
      interval:
        description:
        - Delay, in seconds, between attempts. C(0) means no delay.
        type: int
        default: 1
"""
