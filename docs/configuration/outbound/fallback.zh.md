### 结构

```json
{
  "type": "fallback",
  "tag": "fallback",
  
  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "url": "",
  "interval": "",
  "recovery_interval": "",
  "idle_timeout": "",
  "max_attempts": 0,
  "interrupt_exist_connections": false
}
```

按列表顺序选择第一个可用的出站。当检测到当前出站不可用时，立即切换到下一个可用出站；当排位更靠前的出站恢复时，自动回退。

拨号失败时会按顺序在后续出站上重试，因此连续多个出站不可用对客户端是透明的，不会表现为多次失败的连接。

与 `urltest` 不同，延迟不影响选择：URL 测试仅用于判定出站是否可用。

### 字段

#### outbounds

==必填==

按优先级排序的出站标签列表。

#### url

用于测试的链接。默认使用 `https://www.gstatic.com/generate_204`。

#### interval

测试间隔。 默认使用 `3m`。

#### recovery_interval

重新测试排位在当前出站之前的出站的间隔，即排位更靠前的出站恢复后多久回退。

默认使用 `30s`，并以 `interval` 为上限。必须小于或等于 `interval`。

使用第一个出站时不会产生任何测试，因此该设置仅在降级运行时才有开销。

#### idle_timeout

空闲超时。默认使用 `30m`。

#### max_attempts

单次拨号最多尝试的出站数量。默认使用 `3`。

设为 `1` 可禁用重试，直接返回所选出站的错误。

#### interrupt_exist_connections

当选定的出站发生更改时，中断现有连接。

仅入站连接受此设置影响，内部连接将始终被中断。
