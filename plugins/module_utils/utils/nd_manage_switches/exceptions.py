# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat Chengam Saravanan (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Custom exceptions for ND Switch Resource operations."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class SwitchOperationError(Exception):
    """Raised when a switch operation fails."""


__all__ = [
    "SwitchOperationError",
]
