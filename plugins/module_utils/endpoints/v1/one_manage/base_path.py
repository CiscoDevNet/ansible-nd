# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Final


class BasePath:
    """Builds absolute paths anchored at /api/v1/manage for multi cluster link endpoints."""

    API: Final = "/api/v1/manage"

    @classmethod
    def path(cls, *segments: str) -> str:
        """Join ``segments`` onto the base API path; returns the bare base if none given."""
        if not segments:
            return cls.API
        return "{0}/{1}".format(cls.API, "/".join(segments))
