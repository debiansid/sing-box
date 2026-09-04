---
icon: material/lan-connect
---

# eBPF

!!! quote "Changes in sing-box 1.14.0"

    eBPF inbound is experimental and only available in Linux and Android builds
    with the `with_ebpf` build tag.

The eBPF inbound transparently intercepts selected local or downstream TCP and
UDP traffic. Intercepted connections enter the normal sing-box routing pipeline.
Required system network state is installed and removed automatically.

The eBPF inbound does not use [Listen Fields](/configuration/shared/listen/).

### Structure

```json
{
  "type": "ebpf",
  "tag": "ebpf-in",
  "network": ["tcp", "udp"],
  "udp_timeout": "5m",
  "tc_priority": 1,
  "bypass_rule_set": [],
  "local": {
    "enabled": true,
    "data_plane": "cgroup",
    "dns_mode": "respect_policy",
    "ipv6": true,
    "bypass_private_address": true,
    "include_uid": [],
    "include_uid_range": [],
    "exclude_uid": [],
    "exclude_uid_range": [],
    "include_android_user": [],
    "include_package": [],
    "exclude_package": [],
    "bypass_port": [],
    "bypass_port_range": [],
    "endpoint_connected_bypass": {
      "enabled": false,
      "ip_cidr": [],
      "port": []
    }
  },
  "shared": {
    "enabled": true,
    "data_plane": "packet_rewrite",
    "dns_mode": "respect_policy",
    "interface": ["wlan1"],
    "ipv6": true,
    "bypass_private_address": true,
    "include_source_cidr": [],
    "exclude_source_cidr": [],
    "include_mac_address": [],
    "exclude_mac_address": [],
    "bypass_port": [],
    "bypass_port_range": []
  }
}
```

### Fields

#### network

Enabled transport protocols, `tcp` and/or `udp`. Both are enabled by default.

#### udp_timeout

UDP session timeout. Default is `5m`.

#### tc_priority

TC filter priority in the range 1 through 65535. Default is `1`. Change it only
when coordinating with other TC filters on the same interfaces.
When left at the default, TCX links are used when supported; a custom priority
keeps the traditional `clsact` attachment so its numeric ordering remains effective.

#### bypass_rule_set

Traffic to destination IP CIDRs contained in these rule sets bypasses this
inbound. Non-IP rules are ignored.

### local

#### local.enabled

Enable interception of traffic generated on this host. When either path uses
the new `enabled` field, an omitted `enabled` field on the other path means
`false`. At least one path must be enabled.

The default cgroup data plane intercepts sockets in the visible cgroup v2
hierarchy and does not follow a network interface. The optional TC data plane
follows the current system default network interface and moves when it changes.
During a short handoff, the previous attachment remains active until the
replacement is ready.

#### local.data_plane

Selects the local interception backend. `cgroup` is the default and intercepts
sockets in the visible cgroup v2 hierarchy. Set `tc` explicitly to intercept
traffic on the current default interface instead.

When `local.endpoint_connected_bypass.enabled` is `true`, omitting
`local.data_plane` selects `tc` automatically. Explicit `cgroup` and
`local.cgroup_path` are incompatible with this TC-only policy.

#### local.cgroup_path

Limits `data_plane: cgroup` interception to the specified absolute cgroup v2
subtree. When omitted, the visible cgroup v2 root and all its descendants are
intercepted. This is not the path of the sing-box service unless only that
service subtree should be intercepted.

#### local.dns_mode

| Value | Behavior |
| --- | --- |
| `hijack` | Intercept enabled TCP/UDP traffic to destination port 53. |
| `respect_policy` | Apply local UID and package selection before intercepting destination port 53. |
| `off` | Do not intercept destination port 53. |

Default is `respect_policy`. This setting applies only to enabled TCP/UDP
protocols and does not identify DoH or DoT traffic.

#### local.ipv6

Enable local IPv6 interception. Default is `true`. When disabled, local IPv6
traffic bypasses this inbound.

#### local.bypass_private_address

Bypass private and special-use destinations. Default is `true`.

#### local.include_uid

UIDs to intercept. Once an include UID, range, or package is configured, other
UIDs bypass by default.

#### local.include_uid_range

UID ranges to intercept, in `start:end` format.

#### local.exclude_uid

UIDs to bypass. Exclude policy takes precedence over include policy.

#### local.exclude_uid_range

UID ranges to bypass, in `start:end` format.

#### local.include_android_user

Android user IDs to intercept. Android only.

#### local.include_package

Android package names to intercept. Android only.

#### local.exclude_package

Android package names to bypass. Android only. Packages sharing one UID cannot
be distinguished.

#### local.bypass_port

Destination ports to bypass local interception. This option is supported by
both local data planes (`tc` and `cgroup`) and applies independently to TCP and
UDP when those protocols are enabled by `network`. It matches the destination
port only. FakeIP always forces interception. DNS handling also has precedence:
`hijack` always intercepts port 53, `respect_policy` applies UID policy before
DNS interception, and `off` already bypasses DNS. sing-box emits a startup
warning when port 53 is listed.

#### local.bypass_port_range

Destination port ranges to bypass, in `start:end` format. The range is
inclusive.

#### local.endpoint_connected_bypass

The first version supports one local VPN endpoint policy configuration group.

This policy is implemented only by the local TC data plane. Enabling it selects
`tc` when `local.data_plane` is omitted; it cannot be combined with an explicit
local `cgroup` data plane or `local.cgroup_path`.

When enabled, `ip_cidr` and `port` are required. A local flow must match both a
destination CIDR and destination port. While no matching VPN interface is ready,
matching traffic is forced through this inbound, even if ordinary UID/package,
bypass-port, host, private, or destination-CIDR policy would bypass it. Routing
then follows the normal sing-box Router, `route.rules`, `clash_mode`, and
default outbound.

An ordinary `tun*` interface becomes ready after it is up and has a
global-unicast address. Its first packet-counter sample only establishes the
RX/TX baseline; a later one-second sample must observe RX or TX growth. An
active `ipsec*` interface becomes ready when it has a non-local-table unicast
default route. While ready, matching endpoint traffic native-bypasses TC.

READY remains active while at least one matching interface is active, even if a
sample shows no new packets or counters reset. It is revoked immediately when a
sample observes zero active matching interfaces. There is no grace or debounce
period. The endpoint decision is tri-state: an unmatched flow keeps the
original local policy; a matched flow while NOT READY is forced through the
inbound; and a matched flow while READY native-bypasses TC. FakeIP and DNS
mandatory interception precedence is unchanged. If this object is absent or
`enabled` is `false`, the original local policy applies. This option affects
only local traffic; shared traffic is completely unchanged.

### shared

#### shared.enabled

Enable interception of traffic arriving from the configured downstream
interfaces.

#### shared.data_plane

| Value | Behavior |
| --- | --- |
| `socket_assign` | Assign selected traffic directly to the internal transparent listener. |
| `packet_rewrite` | Rewrite selected traffic to an internal token address and restore reply packets on the downstream interface. This is the default. |

`packet_rewrite` requires Ethernet-framed downstream interfaces and does not
use the policy routing required by `socket_assign`. Neither shared data plane
creates the delivery veth used by local TC. Local and shared data planes are
selected independently.

#### shared.dns_mode

Uses the same values as `local.dns_mode`. In `respect_policy` mode, source CIDR
and MAC selection is applied before destination port 53 is intercepted.

#### shared.interface

==Required when shared interception is enabled==

Downstream interfaces where client traffic enters the host. The default
`packet_rewrite` data plane requires Ethernet framing. Set `socket_assign`
explicitly for Ethernet/IPoE, raw-IP (including Android rmnet), PPP/PPPoE, or
IPIP/SIT/GRE tunnel interfaces.
Multiple interfaces may be specified; interfaces that are temporarily absent
are retried after network updates. An interface is temporarily excluded from
shared interception while it is the current default upstream, then restored
when it becomes downstream again. Loopback is not accepted.

#### shared.ipv6

Enable shared IPv6 interception. Default is `true`. When disabled, IPv6 traffic
on shared interfaces bypasses this inbound.

#### shared.bypass_private_address

Bypass private and special-use destinations. Default is `true`.

#### shared.include_source_cidr

Client source CIDRs to intercept. When non-empty, non-matching sources bypass.

#### shared.exclude_source_cidr

Client source CIDRs to bypass. Exclude policy takes precedence over include
policy.

#### shared.include_mac_address

48-bit client source MAC addresses to intercept.

This option is available only on Ethernet-framed shared interfaces.

#### shared.exclude_mac_address

48-bit client source MAC addresses to bypass. Exclude policy takes precedence
over include policy.

This option is available only on Ethernet-framed shared interfaces.

#### shared.bypass_port

Destination ports to bypass shared interception. This option is supported by
both shared data planes (`socket_assign` and `packet_rewrite`) and applies
independently to TCP and UDP when those protocols are enabled by `network`. It
matches the destination port only. FakeIP and DNS handling have the same
precedence described for `local.bypass_port`; listing port 53 in this mode is
therefore warned about at startup.

#### shared.bypass_port_range

Destination port ranges to bypass, in `start:end` format. The range is
inclusive.

!!! note

    Shared mode does not enable IP forwarding or provide NAT, DHCP, IPv6 router
    advertisements, or hotspot management. Configure these functions in Android,
    Linux, or the router operating system. Multiple downstream interfaces may be
    configured for Wi-Fi, USB tethering, and similar links.

### Limitations

- A sing-box instance may contain only one eBPF inbound with local interception
  enabled. Additional eBPF inbounds must be shared-only.
- Fragmented IPv4 and IPv6 datagrams bypass interception. IPv6 atomic fragments
  are processed as ordinary IPv6 packets.
- Interception state is restored automatically after network changes.

See [eBPF kernel requirements](/manual/misc/ebpf-kernel-requirements/) before
enabling this inbound on vendor or Android kernels.
