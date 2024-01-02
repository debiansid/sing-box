# sing-box

这是一个第三方 Fork 仓库，在原有基础上添加一些强大功能

### Outbound Provider

允许从远程获取 ```Outbound``` ，支持普通链接、Clash订阅、Sing-box订阅。并在此基础上对 ```Outbound``` 进行配置修改

编译请加入 ```with_outbound_provider```

#### 配置详解

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
      "headers": {}, // HTTP Header 头，键值对
      "optimize": false, // 自动优化
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

###### 全局文档 - Rules

```json5
{
  "type": "...",
  "rules": [], // 匹配 Outbound 的规则，具体见下
  "logical": "or", // 匹配逻辑，要求全部匹配还是任一匹配
}
```
```
Rules 支持匹配 Tag 或 Type：

1. 若匹配 Tag ，格式：`tag:HK$`，以 `tag:` 开头，后面是 Golang 正则表达式
2. 若匹配 Type，格式：`type:trojan`，以 `type:` 开头，后面是 Outbound 类型名
3. 若无 `$*:` 开头，则默认以 `tag:` 开头
```

##### 1. Filter

过滤 ```Outbound``` ，建议放置在最前面

```json5
{
  "type": "filter",
  //
  "rules": [],
  "logical": "or", // 默认为 or
  //
  "invert": false, // 默认为 false ，对匹配到规则的 Outbound 进行过滤剔除；若为 true ，对未匹配到规则的 Outbound 进行过滤剔除
}
```

##### 2. TagFormat

对 ```Outbound``` 标签进行格式化，对于拥有多个 ```Outbound Provider``` ，并且 ```Outbound Provider``` 间 ```Outbound``` 存在命名冲突，可以使用该 action 进行重命名

```json5
{
  "type": "tagformat",
  //
  "rules": [],
  "logical": "or", // 默认为 or
  //
  "invert": false, // 默认为 false ，对匹配到规则的 Outbound 进行格式化；若为 true ，对未匹配到规则的 Outbound 进行格式化
  "format": "Sub1 - %s", // 格式化表达式，%s 代表旧的标签名
}
```

##### 3. Group

对 ```Outbound``` 进行筛选分组，仅支持 ```Selector Outbound``` 和 ```URLTest Outbound```

```json5
{
  "type": "group",
  //
  "rules": [],
  "logical": "or", // 默认为 or
  //
  "invert": false, // 默认为 false ，对匹配到规则的 Outbound 加入分组；若为 true ，对未匹配到规则的 Outbound 加入分组
  "outbound": {
    "tag": "group1",
    "type": "selector", // 使用 Selector 分组，也可以使用 URLTest 分组
    // "outbounds": [], 筛选的 Outbound 会自动添加到 Outbounds 中，可以预附加 Outbound ，造成的预期外问题自负
    // "default": "" // 仅 Selector 可用，默认为空，可以预附加 Outbound ，造成的预期外问题自负
  }
}
```

##### 4. SetDialer

对 ```Outbound``` 进行筛选修改 ```Dial``` 配置
```json5
{
  "type": "setdialer",
  //
  "rules": [],
  "logical": "and", // 默认为 and
  //
  "invert": false, // 默认为 false ，匹配到的 Outbound 才会被执行操作；若为 true ，没有匹配到的 Outbound 才会被执行操作
  "dialer": {
    "set_$tag": ..., // 以 set_ 开头，覆写原配置 $tag 项，覆写注意值类型
    "del_$tag": null // 以 del_ 开头，删除原配置 $tag 项，键值任意
  }
}
```

#### 示例配置

```json5
{
  "log": {
    "timestamp": true,
    "level": "info"
  },
  "experimental": {
    "cache_file": { // 开启缓存，缓存 Outbound Provider 数据
      "enabled": true,
      "path": "/etc/sing-box-cache.db"
    }
  },
  "outbounds": [
    {
      "tag": "direct-out",
      "type": "direct"
    },
    {
      "tag": "proxy-out",
      "type": "selector",
      "outbounds": [
        "sub"
      ]
    }
  ],
  "outbound_providers": [
    {
      "tag": "sub",
      "url": "http://example.com", // 订阅链接
      "update_interval": "24h",
      "actions": [
        {
          "type": "filter",
          "rules": [
            "剩余",
            "过期",
            "更多"
          ]
        },
        {
          "type": "group",
          "rules": [
            "香港",
            "Hong Kong",
            "HK"
          ],
          "outbound": {
            "tag": "sub - HK",
            "type": "selector"
          }
        }
      ],
      "detour": "direct-out",
      "selector": {
        "default": "sub - HK"
      }
    }
  ],
  "route": {
    "rule_set": [
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-cn.srs",
        "update_interval": "24h",
        "download_detour": "sub"
      },
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-cn.srs",
        "update_interval": "24h",
        "download_detour": "sub"
      }
    ],
    "rules": [
      {
        "rule_set": [
          "geosite-cn",
          "geoip-cn"
        ],
        "outbound": "direct-out"
      },
      {
        "inbound": [
          "mixed-in"
        ],
        "outbound": "sub"
      }
    ]
  },
  "inbounds": [
    {
      "tag": "mixed-in",
      "type": "mixed",
      "listen": "::",
      "listen_port": 2080,
      "sniff": true
    }
  ]
}
```

### Group Outbound 添加 Outbound Provider 中的 Outbound

#### 示例配置
```json5
{
  "outbounds": [
    {
      "tag": "HK",
      "type": "selector", // 支持 Selector 和 URLTest
      // "outbounds": [
      //   ...
      // ]
      "providers": [ // 添加 Outbound Provider 中的 Outbound
        {
          "tag": "sub", // Outbound Provider Tag
          // 参考上面
          "rules": ["HK"],
          "logical": "or", // 默认为 or
          //
          "invert": false // 默认为 false ，匹配到的 Outbound 才会被添加；若为 true ，没有匹配到的 Outbound 才会被添加
        }
        // 上述配置会把 Tag 为 HK 的 Outbound 添加到 Group Outbound 中
      ]
    }
  ],
  "outbound_providers": [
    {
      "tag": "sub",
      "url": "http://example.com", // 订阅链接
      "update_interval": "24h",
      "actions": [
        {
          "type": "filter",
          "rules": [
            "剩余",
            "过期",
            "更多"
          ]
        }
      ]
    }
  ]
}
```

### Rule Provider Clash API

```RuleSet``` 适配了 ```Clash API```
