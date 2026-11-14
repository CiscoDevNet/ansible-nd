# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field

from .base import LinkTemplateBase, con, pd


class CsrBgpOverIpsecTemplateInputs(LinkTemplateBase):
    """CSR BGP over IPsec inputs, including its required shared secret.

    ND 4.3.1 adds nonnegative 32-bit bounds and zero defaults to the loopback and
    tunnel identifiers. Those values also satisfy the unconstrained ND 4.2.1
    integer properties; the shared contract enforces the bounded range.
    """

    policy_type_marker: Literal["csrBgpOverIpsec"] = Field(default="csrBgpOverIpsec", exclude=True)

    ip_sec_shared_key: str | None = Field(default=None, alias="ipSecSharedKey", json_schema_extra=con(secret=True, required=True))
    loopback_id: int | None = Field(default=None, alias="loopbackId", json_schema_extra=pd(0, minimum=0, maximum=2147483647))
    on_prem_device_ip_bgp_peering: str | None = Field(default=None, alias="onPremDeviceIpBgpPeering", json_schema_extra=con(required=True))
    cloud_csr_ip_bgp_peering: str | None = Field(default=None, alias="cloudCsrIpBgpPeering", json_schema_extra=con(required=True))
    tunnel_id: int | None = Field(default=None, alias="tunnelId", json_schema_extra=pd(0, minimum=0, maximum=2147483647))
    on_prem_device_tunnel_ip: str | None = Field(default=None, alias="onPremDeviceTunnelIp", json_schema_extra=con(required=True))
    cloud_csr_tunnel_ip: str | None = Field(default=None, alias="cloudCsrTunnelIp", json_schema_extra=con(required=True))
    on_prem_device_remote_domain: str | None = Field(default=None, alias="onPremDeviceRemoteDomain", json_schema_extra=con(required=True))
    on_prem_device_fqdn: str | None = Field(default=None, alias="onPremDeviceFqdn", json_schema_extra=con(required=True))
    cloud_csr_remote_domain: str | None = Field(default=None, alias="cloudCsrRemoteDomain", json_schema_extra=con(required=True))
    cloud_csr_fqdn: str | None = Field(default=None, alias="cloudCsrFqdn", json_schema_extra=con(required=True))
