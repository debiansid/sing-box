# sing-box

这是一个第三方 Fork 仓库，在原有基础上添加一些强大功能

### Outbound Provider

允许从远程获取 ```Outbound``` ，支持普通链接、Clash订阅、Sing-box订阅。并在此基础上对 ```Outbound``` 进行配置修改

编译请加入 ```with_outbound_provider```

#### 配置实例

```json5
{
  "outbounds": [
    {
      "tag": "direct-out",
      "type": "direct"
    },
    {
      "tag": "direct-mark-out", // 该 Outbound 流量会打上 SO_MARK 0xff
      "type": "direct",
      "routing_mark": 255
    },
    {
      "tag": "global",
      "type": "selector",
      "outbounds": [
        "Sub1", // 使用 Outbound Provider 暴露的同名 Selector Outbound
        "Sub2"
      ]
    }
  ],
  "outbound_providers": [
    {
      "tag": "Sub1", // Outbound Provider 标签，必填，用于区分不同 Outbound Provider 以及创建同名 Selector Outbound
      "url": "http://example.com", // 订阅链接
      "cache_tag": "", // 保存到缓存的 Tag，请开启 CacheFile 以使用缓存，若为空，则使用 tag 代替
      "update_interval": "", // 自动更新间隔，Golang Duration 格式，默认为空，不自动更新
      "request_timeout": "", // HTTP 请求的超时时间
      "http3": false, // 使用 HTTP/3 请求
      "selector": { // 暴露的同名 Selector Outbound 配置
        // 与 Selector Outbound 配置一致
      },
      "actions": [], // 生成 Outbound 时对配置进行的操作，具体见下
      // Outbound Dial 配置，用于获取 Outbound 的 HTTP 请求
    },
    {
      "tag": "Sub2",
      "url": "http://2.example.com",
      "detour": "Sub1" // 使用 Sub1 的 Outbound 进行请求
    }
  ]
}
```

#### Action

```action``` 提供强大的对 ```Outbound``` 配置的自定义需求，```action``` 可以定义多个，按顺序执行，目前有以下操作：

##### 1. Filter

过滤 ```Outbound``` ，建议放置在最前面

```json5
{
  "type": "filter",
  "rules": [], // Golang 正则表达式，匹配到的 Outbound 会被剔除
  "white_mode": false, // 白名单模式，没有匹配到的 Outbound 才会被剔除
}
```

##### 2. TagFormat

对 ```Outbound``` 标签进行格式化，对于拥有多个 ```Outbound Provider``` ，并且 ```Outbound Provider``` 间 ```Outbound``` 存在命名冲突，可以使用该 action 进行重命名

```json5
{
  "type": "tagformat",
  "rules": [], // Golang 正则表达式，匹配到的 Outbound 会被执行操作
  "black_mode": false, // 黑名单模式，没有匹配到的 Outbound 才会被执行操作
  "format": "Sub1 - %s", // 格式化表达式，%s 代表旧的标签名
}
```

##### 3. Group

对 ```Outbound``` 进行筛选分组，仅支持 ```Selector Outbound``` 和 ```URLTest Outbound```

```json5
{
  "type": "group",
  "rules": [], // Golang 正则表达式，匹配到的 Outbound 会被执行操作
  "black_mode": false, // 黑名单模式，没有匹配到的 Outbound 才会被执行操作
  "outbound": {
    "tag": "group1",
    "type": "selector", // 使用 Selector 分组
    // "outbounds": [], 筛选的 Outbound 会自动添加到 Outbounds 中
  }
}
```
