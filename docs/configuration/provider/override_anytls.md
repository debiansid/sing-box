### Structure

```json
{
  "client_metadata": ""
}
```

### Fields

`client_metadata` see [AnyTLS outbound](/configuration/outbound/anytls/).

Omitted fields preserve the subscription's values. An explicit empty `client_metadata`
clears the metadata. Set `disable_reuse` on the AnyTLS node itself; it is not a provider override field.
