---
icon: material/new-box
---

# Route

!!! quote "Feature in this fork"

    :material-plus: [prefer_use_fqdn](#prefer_use_fqdn)
    :material-plus: [always_resolve_udp](#always_resolve_udp)

!!! quote "Changes in sing-box 1.11.0"

    :material-plus: [default_network_strategy](#default_network_strategy)  
    :material-plus: [default_network_type](#default_network_type)  
    :material-plus: [default_fallback_network_type](#default_fallback_network_type)  
    :material-plus: [default_fallback_delay](#default_fallback_delay)

!!! quote "Changes in sing-box 1.8.0"

    :material-plus: [rule_set](#rule_set)  
    :material-delete-clock: [geoip](#geoip)  
    :material-delete-clock: [geosite](#geosite)

### Structure

```json
{
  "route": {
    "geoip": {},
    "geosite": {},
    "rules": [],
    "rule_set": [],
    "final": "",
    "prefer_use_fqdn": false,
    "always_resolve_udp": false,
    "auto_detect_interface": false,
    "override_android_vpn": false,
    "default_interface": "",
    "default_mark": 0,
    "default_network_strategy": "",
    "default_network_type": [],
    "default_fallback_network_type": [],
    "default_fallback_delay": ""
  }
}
```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

### Fields

#### rules

List of [Route Rule](./rule/)

#### rule_set

!!! question "Since sing-box 1.8.0"

List of [rule-set](/configuration/rule-set/)

#### final

Default outbound tag. the first outbound will be used if empty.

#### prefer_use_fqdn

!!! question "Feature in this fork"

Prefer use fqdn when dialing.

#### always_resolve_udp

!!! question "Feature in this fork"

Always resolve udp domain when routing, except action then reject route rule action.

If set, `prefer_use_fqdn` will not work on udp.

#### auto_detect_interface

!!! quote ""

    Only supported on Linux, Windows and macOS.

Bind outbound connections to the default NIC by default to prevent routing loops under tun.

Takes no effect if `outbound.bind_interface` is set.

#### override_android_vpn

!!! quote ""

    Only supported on Android.

Accept Android VPN as upstream NIC when `auto_detect_interface` enabled.

#### default_interface

!!! quote ""

    Only supported on Linux, Windows and macOS.

Bind outbound connections to the specified NIC by default to prevent routing loops under tun.

Takes no effect if `auto_detect_interface` is set.

#### default_mark

!!! quote ""

    Only supported on Linux.

Set routing mark by default.

Takes no effect if `outbound.routing_mark` is set.

#### default_network_strategy

!!! question "Since sing-box 1.11.0"

See [Dial Fields](/configuration/shared/dial/#network_strategy) for details.

Takes no effect if `outbound.bind_interface`, `outbound.inet4_bind_address` or `outbound.inet6_bind_address` is set.

Can be overrides by `outbound.network_strategy`.

Conflicts with `default_interface`.

#### default_network_type

!!! question "Since sing-box 1.11.0"

See [Dial Fields](/configuration/shared/dial/#network_type) for details.

#### default_fallback_network_type

!!! question "Since sing-box 1.11.0"

See [Dial Fields](/configuration/shared/dial/#fallback_network_type) for details.

#### default_fallback_delay

!!! question "Since sing-box 1.11.0"

See [Dial Fields](/configuration/shared/dial/#fallback_delay) for details.
