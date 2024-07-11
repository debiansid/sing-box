# sing-box

The universal proxy platform.

[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

## Documentation

Port Hopping Strategies:

1. Empty or `both`:
    - Changes both client and server ports.
    - Even if `server_ports` is a fixed range (e.g., `443:443`), the changing client port still alters the connection's
      5-tuple (source IP, source port, destination IP, destination port, protocol).
    - This can potentially bypass Quality of Service (QoS) policies.

2. `server`:
    - Changes only the server port; the client port remains constant.
    - This strategy modifies only the destination port in the 5-tuple.
    - Originated from the `mohomo` implementation.
    - May be sufficient to bypass certain restrictions targeting specific server ports.

---

端口跳跃策略:

1. 空 或 `both` (Empty or `both`):

   原始的端口跳跃行为，**同时改变客户端端口和服务端端口**。 这意味着每次连接尝试，客户端和服务器都会使用新的端口组合。
   即使 `server_ports` 设置为相同的端口范围 (例如 `443:443`)，由于 **客户端端口也会被随机改变**， 仍然会改变连接的五元组，从而可能达到绕过
   QOS 的效果。

2. `server`:

   **仅改变服务端端口**，客户端端口保持不变。 这种策略只修改五元组中的目的端口部分。 该策略源自 `mohomo` 的实现。
   在某些场景下，只改变服务端端口可能足以达到绕过某些针对特定服务端端口的限制的目的。

## Dialer

```json
{
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct",
      "tcp_keep_alive_interval": "15s",
      "tcp_keep_alive_idle": "10min"
    }
  ]
}
```

TCP Keep alive options.

## Inbound TLS

```json
{
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-in",
      "tls": {
        "enabled": true,
        "server_name": "sekai.love",
        "certificate_path": "cert.pem",
        "key_path": "key.key",
        "reject_unknown_sni": true
      }
    }
  ]
}
```

Reject unknown sni: If the server name of connection is not equal to `server_name` and not be included in certificate,
it will be rejected.

拒绝未知 SNI：如果连接的 server name 与 `server_name` 不符 且 证书中不包含它，则拒绝连接。

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```