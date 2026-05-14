# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from typing import Any


class VrfLiteResourceError(Exception):
    """Structured error for nd_manage_vrf_lite workflows."""

    def __init__(self, msg: str, **details: Any) -> None:
        super().__init__(msg)
        self.msg = msg
        self.details = details or {}
