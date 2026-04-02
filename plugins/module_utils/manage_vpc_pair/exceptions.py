# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

from typing import Any


class VpcPairResourceError(Exception):
    """Structured error raised by vpc_pair runtime layers."""

    def __init__(self, msg: str, **details: Any):
        """
        Initialize VpcPairResourceError.

        Args:
            msg: Human-readable error message
            **details: Arbitrary keyword args for structured error context
                (e.g. fabric, vpc_pair_key, missing_switches)
        """
        super().__init__(msg)
        self.msg = msg
        self.details = details
