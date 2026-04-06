# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

API = "/api/v1/manage"


class BasePath:
    """Builds absolute paths anchored at /api/v1/manage for manage-scope endpoints."""

    @staticmethod
    def path(*segments: str) -> str:
        """Join ``segments`` onto the base API path."""
        tail = "/".join(segments)
        return "{0}/{1}".format(API, tail)


# Alias retained for links endpoints that import ``BasePathLinks`` directly.
BasePathLinks = BasePath
