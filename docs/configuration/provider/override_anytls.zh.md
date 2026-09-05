### 结构

```json
{
  "client_metadata": ""
}
```

### 字段

`client_metadata` 详情参阅 [AnyTLS 出站](/zh/configuration/outbound/anytls/)。

未配置的字段保留订阅中的值。显式配置空的 `client_metadata` 会清空元数据。
`disable_reuse` 应在 AnyTLS 节点本身配置，不属于 provider 覆盖字段。
