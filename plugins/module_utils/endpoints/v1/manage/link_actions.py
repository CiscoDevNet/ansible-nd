# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePathLinks
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class LinkActionsRemovePost(NDEndpointBaseModel):
    """POST /api/v1/manage/linkActions/remove for bulk delete by linkId."""

    class_name: Literal["LinkActionsRemovePost"] = Field(
        default="LinkActionsRemovePost", frozen=True, description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        return BasePathLinks.path("linkActions", "remove")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST
