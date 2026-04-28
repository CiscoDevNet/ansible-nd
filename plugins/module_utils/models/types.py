# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Shared Pydantic Annotated types for ND model fields.

These types layer custom validators on top of standard Pydantic types so that cross-cutting input rules can be
applied consistently across model files (e.g. all `description` fields share the same ASCII-only constraint).

## Available types

- `AsciiDescription` — `str | None` that rejects any non-ASCII character. Use for interface `description` fields
  on any policy model that maps to an ND CLI-generated config line. The Cisco backend pipes these descriptions
  through CLI generators that fail with a generic 500 ("unexpected error during policy execution") when given
  UTF-8 input. Catching this client-side gives users a clear error instead of a confusing server fault.
"""

from __future__ import annotations

from typing import Annotated

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import AfterValidator


def ascii_only(value: str | None) -> str | None:
    """
    # Summary

    Validate that `value` contains only ASCII characters. Returns the value unchanged if it passes, or raises
    `ValueError` with a position indicator on the first non-ASCII character.

    Used as the `AfterValidator` payload for the `AsciiDescription` Annotated type.

    ## Raises

    ### ValueError

    - If `value` contains any non-ASCII character.
    """
    if value is None:
        return value
    try:
        value.encode("ascii")
    except UnicodeEncodeError as e:
        raise ValueError(
            f"description must contain only ASCII characters; got non-ASCII at position {e.start}: {value[e.start]!r}. "
            "The ND backend currently returns a generic 500 for non-ASCII descriptions."
        ) from None
    return value


AsciiDescription = Annotated[str | None, AfterValidator(ascii_only)]
"""ASCII-only `str | None`. Layer with `Field(...)` for `max_length` / `min_length` / aliases as usual."""
