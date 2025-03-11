### Structure

```json
{
  "type": "fallback",
  "tag": "fallback",
  
  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "providers": [
    "provider-a",
    "provider-b"
  ],
  "exclude": "",
  "include": "",
  "url": "",
  "interval": "",
  "recovery_interval": "",
  "idle_timeout": "",
  "max_attempts": 0,
  "use_all_providers": false,
  "interrupt_exist_connections": false
}
```

Selects the first available outbound in listed order. When the currently selected outbound is detected as unavailable, it switches to the next available one immediately; when a higher-priority outbound recovers, it falls back automatically.

A dial that fails is retried on the following outbounds in order, so a run of consecutively unavailable outbounds stays transparent to the client instead of surfacing as failed connections.

Unlike `urltest`, latency never influences selection: the URL test only determines whether an outbound is available.

### Fields

#### outbounds

List of outbound tags, in priority order.

#### providers

List of [Provider](/configuration/provider) tags, in priority order.

Outbounds of the providers are appended after `outbounds`, in the order the nodes appear in the provider.

#### exclude

Exclude regular expression to filter `providers` nodes.

#### include

Include regular expression to filter `providers` nodes.

#### url

The URL to test. `https://www.gstatic.com/generate_204` will be used if empty.

#### interval

The test interval. `3m` will be used if empty.

#### recovery_interval

The interval at which outbounds ranked before the current one are re-tested, that is, how fast the group falls back after a higher-priority outbound recovers.

`30s` will be used if empty, capped to `interval`. Must be less or equal than `interval`.

No test is performed while the first outbound is in use, so this setting costs nothing until the group is degraded.

#### idle_timeout

The idle timeout. `30m` will be used if empty.

#### max_attempts

The maximum number of outbounds attempted per dial. `3` will be used if empty.

Set to `1` to disable retrying and return the error of the selected outbound directly.

#### use_all_providers

Whether to use all providers. `false` will be used if empty.

#### interrupt_exist_connections

Interrupt existing connections when the selected outbound has changed.

Only inbound connections are affected by this setting, internal connections will always be interrupted.
