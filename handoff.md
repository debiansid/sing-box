# sing-box / sing-ebpf 开发交接（供 agy 接手）

更新日期：2026-09-15。本文记录用户已确认的来源、边界和流程；不是授权自动升级、改写远端历史或发布的指令。后续以用户最新要求、实际代码和固定依赖为准。短哈希仅用于定位，更新前重新核实远端。

## 1. 项目目标与仓库

我们维护一个基于官方 sing-box、Yuu 功能底座和 reF1nd 协议兼容修复的分支，接入 CHIZI-0618 的 eBPF inbound，并保留自己的 endpoint-connected bypass 扩展。不是另起一套代理核心或 eBPF 实现。

| 仓库 / 分支 | 用途 |
| --- | --- |
| [debiansid/sing-box · testing-base](https://github.com/debiansid/sing-box/tree/testing-base) | 干净基础分支：官方/Yuu/reF1nd 底座及必要兼容修复；不含 eBPF、endpoint 扩展、Android Wi-Fi 本地功能和已删除的 FakeIP 补丁 |
| [debiansid/sing-box · testing-ebpf](https://github.com/debiansid/sing-box/tree/testing-ebpf) | 当前产品开发分支，包含 eBPF 和本地扩展 |
| [debiansid/sing-ebpf · endpoint-connected-bypass](https://github.com/debiansid/sing-ebpf/tree/endpoint-connected-bypass) | CHIZI 库 main 加一个本地扩展提交 |

本机主工作目录是 `/home/ezhang/sing-box`，库目录是 `/home/ezhang/sing-ebpf`，位于 WSL Debian。Windows 入口分别为 `\\wsl$\Debian\home\ezhang\sing-box` 和 `\\wsl$\Debian\home\ezhang\sing-ebpf`。工具或目录不存在时应在接手环境重新定位，不假设必须使用此机器。

## 2. 底座来历与明确取舍

来源链条：

```text
SagerNet/sing-box testing（当前 1.15.0-alpha.4）
  → Yuu518/testing-Yuu 的基础功能，排除统一延迟和 Build
  → 既有 daemon / 网络启动修复 + reF1nd AnyTLS / Snell 兼容修复
  → testing-base（另有模块依赖整理）

上述公共代码底座
  → Android Wi-Fi 状态支持
  → CHIZI-0618/ebpf-inbound：代码 + 文档
  → 我们的 endpoint-connected bypass：代码 + 文档
  → testing-ebpf
```

### 上游来源

- 官方：[SagerNet/sing-box testing](https://github.com/SagerNet/sing-box/tree/testing)，当前基准 `4566ef0890e0cde8448000e8aa3223fb286daa94`，版本 `1.15.0-alpha.4`。
- 直接功能底座：[Yuu518/sing-box testing-Yuu](https://github.com/Yuu518/sing-box/commits/testing-Yuu/)，本轮检查的 tip 是 `d1287523`。它已跟进上述官方版本。
- 协议补丁：[reF1nd/sing-box reF1nd-testing](https://github.com/reF1nd/sing-box/tree/reF1nd-testing)。按需要移植 AnyTLS / Snell 兼容修复，不整分支合并所有额外功能。
- eBPF 消费端：[CHIZI-0618/sing-box ebpf-inbound](https://github.com/CHIZI-0618/sing-box/tree/ebpf-inbound)，当前上游基础代码 `6a0c1f91`、文档 `b85e0cbc`（分别与此前 `af9f572c`、`b5ee1f48` 树一致），其后新增 UDP 优化 `f5ebfd09`、`8d7e23b3`、`f5b74643`；当前 tip 为 `f5b74643`。
- eBPF 库：[CHIZI-0618/sing-ebpf main](https://github.com/CHIZI-0618/sing-ebpf/tree/main)，当前基准 `c52c21d4066a6e9e92fef2cf13bbf681357f2d78`（sing 依赖对齐稳定版，无 native/ABI 变更）。

这里的“eBPF 官方实现”指 CHIZI 维护的上游实现，不代表已进入 SagerNet 官方主线。

### 必须保留的取舍

1. 排除 Yuu 的 `urltest: unify latency measurements over reused connections`（本轮来源 `5e8f43e0`）与 `Build`（`d1287523`）。后续哈希可能改变，要按内容识别，不能只按旧哈希过滤。
2. Yuu 底座仍保留 sniffer、resolve `match_only`、DNS group/cache、Android package name、Clash API restart、provider/rule-provider、并发 TCP dial、selector 中断等功能。
3. 保留既有 daemon API、网络启动竞态修复以及 reF1nd AnyTLS/Snell 兼容；移植时保留 provider 解析/覆盖行为和相应测试。
4. sing-tun 曾暂用 CHIZI 所用的官方版本；2026-09-15 核实 reF1nd `7512d34` 完整包含官方 `3a0d387`（落后 0、额外 6 个修复），用户随后明确授权切换依赖并验证集成。当前 testing-ebpf 主模块与测试模块使用下面固定的 reF1nd 版本；testing-base 尚未随此次切换更新。
5. **FakeIP 旧缓存补丁已按用户要求删除。** `1c6d4a3d67d987c183345d4d9c27152cbf76db60` 源自 CHIZI 旧提交 `d16c6099`，后经 `e3ce5a3a` 重放；最新 CHIZI ebpf-inbound 不含它。不要从旧备份、旧分支或 cherry-pick 队列重新带回。此决定仅针对该补丁，不是删除 eBPF 的 FakeIP/DNS 集成。
6. 不恢复历史 `common/ebpf`、`endpoint_relay`、强制 outbound 选择或 relay 连通性判定 VPN ready 的旧设计。

## 3. 交接文档提交前的代码基线

| 项目 | 文档提交前已推送的代码基线 |
| --- | --- |
| sing-box testing-base | `ffe26fa0a95b00058e13d1822e058b65f856a2a6` |
| sing-box testing-ebpf | `6124ebea1599dcbb5a09dd7a5bfa21da8de12c6d` |
| sing-ebpf endpoint-connected-bypass | `cc73cfd511da3d3fbd1f1cf9731f104743883696` |

### testing-ebpf 尾部结构（从旧到新）

| 提交 | 内容 |
| --- | --- |
| `ae4f8b27` | Snell 兼容；公共功能底座边界 |
| `0144d33b` | Android Wi-Fi 状态支持，独立的本地功能 |
| `36e3fd15` | CHIZI eBPF inbound 代码重放 |
| `5caf676f` | CHIZI eBPF 文档重放 |
| `018a4bb4` | 我们的 endpoint-connected bypass 代码与依赖集成 |
| `6124ebea` | 我们的 endpoint 文档与 schema |

用户要求“我们的 sing-box 两个 commit”指最后的 endpoint 扩展层：**一个代码提交、一个文档提交**；不是把整个 fork 的全部底座压成两个提交。库则是 **上游 main + 一个本地扩展提交**。

`testing-base` 从 `ae4f8b27` 取干净底座，再加 `ffe26fa0` 整理 root/test 模块依赖。它不是 testing-ebpf 的直接祖先；testing-ebpf 的相应依赖整理在扩展代码提交中。不要为追求分支形状而机械 merge，先比较实际树与依赖。

### 固定依赖

- root `go.mod` require CHIZI sing-ebpf：`v0.1.0-alpha.8.0.20260915062432-c52c21d4066a`。
- root 与 `test/go.mod` 均 replace 该模块到 debiansid sing-ebpf：`v0.0.0-20260915110011-98c82044b9ec`。
- testing-ebpf sing-tun：require `github.com/sagernet/sing-tun v0.9.4-0.20260914145202-3a0d3878577a`，root/test 均 replace 到 `github.com/reF1nd/sing-tun v0.9.4-0.20260915103927-7512d34d3229`。testing-base 仍使用原官方版本。
- AnyTLS replace：`github.com/reF1nd/sing-anytls v0.0.0-20260905062301-7eeaaeb4fb19`。
- Snell replace：`github.com/reF1nd/sing-snell v0.0.0-20260905064728-48a266fb2745`。

`test/` 是独立 Go module。主模块的 replace 不会自动继承到它；更新依赖时必须检查两个模块。testing-base 不应含 sing-ebpf require/replace。

## 4. 架构与代码入口

依赖方向：`sing-box → sing-ebpf/runtime → sing-ebpf`。

| 层 | 所有权与职责 | 主要入口 |
| --- | --- | --- |
| sing-box | 配置验证、策略翻译、listener、UDP NAT/session、进程信息、Router、日志与诊断 | `option/ebpf.go`、`protocol/ebpf/`、`include/ebpf*.go` |
| sing-box 的耦合路径 | 自身 socket 绕过、网络事件、FakeIP/DNS 语义与 CLI/Clash API | `common/dialer/ebpf_self_bypass*`、`common/listener/`、`route/network_ebpf*`、`dns/transport/fakeip/store_ebpf.go`、`experimental/clashapi/ebpf*`、`cmd/sing-box/cmd_tools_ebpf.go` |
| sing-ebpf 根包 | BPF C 源码、生成对象、ABI、maps/programs、能力探测、通用策略、cgroup/self-bypass | `api.go`、`native/`、`internal/`、`generate.go` |
| sing-ebpf/runtime | TC/TCX/clsact attachment、delivery links、路由与 rules、sysctl、shared rewrite、拓扑协调、回滚清理 | `runtime/` |

### 数据路径

- local 与 shared 独立启用、独立选后端、独立持有资源。默认 local=`cgroup`，shared=`packet_rewrite`；另有 local=`tc`、shared=`socket_assign`。
- local cgroup：以私有 token 目标转交本机 listener，再恢复原始对端。
- local TC：在上行接口 egress 判断策略，经 delivery veth 交给本机；排除转发流量身份与本进程 self-bypass socket。
- shared socket_assign：在下游 ingress 接收并保持原始 tuple；按接口 framing 选择 Ethernet/raw-IP 对象。
- shared packet_rewrite：改写并恢复 Ethernet 流量，不支持 raw-IP。
- 用户态最终交给正常 sing-box Router；路由规则、Clash mode、默认 outbound 仍决定出口。
- 热点/tethering bridge 是相邻应用功能，不是 eBPF ABI 或 runtime 资源的拥有者。

## 5. 我们的 endpoint-connected bypass

配置入口：`local.endpoint_connected_bypass`，详见 [配置文档](docs/configuration/inbound/ebpf.zh.md)。实现重点是 `protocol/ebpf/config.go`、`vpn_ready.go`、`interface_monitor.go`、`inbound_lifecycle.go` 与库的公开控制 API。

- 只支持 **local TC**、一个 endpoint 配置组；该组可以列多个 CIDR/端口。匹配条件是目标 **CIDR AND 端口**，再按配置筛选 TCP/UDP。
- 启用时省略 local data_plane 会选择 TC；显式 cgroup、cgroup_path 或关闭 local 均无效。
- 未 ready：匹配流量进入正常 Router；ready：匹配流量在 local TC 原生 bypass。
- 不匹配流量走原策略；shared 策略不变；FakeIP/DNS 的优先语义必须保留。
- 这不是 outbound selector。不能引入路由出口覆盖、全局 protect/mark 或让普通 VPN payload 失去进入 VPN 的资格。
- 该扩展是我们自己的库/消费端协议，不能假设 CHIZI README 承诺支持。通过公开 `SetEndpointVPNReady` API 控制，不能访问私有 map 或复制 ABI。

### VPN readiness 规则

1. 候选为 UP 的 `tun*` / `ipsec*` 接口，有 global-unicast 地址，排除 sing-box 自己的接口。
2. TUN 首次 RX/TX 样本只建立基线；后续增长才 ready。状态按 **接口名 + ifindex** 标识，接口存续期间锁存 ready。
3. IPsec 要有非 local table 的 unicast 默认路由。
4. 没有 ready 候选立即清除 ready，不新增 grace/debounce。
5. 单一 interface worker 在网络事件及每秒采样时更新。采样只更新 READY 控制位，不周期性重建拓扑/maps/attachments。
6. 后端控制写入失败时，不能提前提交用户态 ready；相同状态是 no-op。
7. core/endpoint socket 保留原 underlying/protect，再附加 eBPF self-bypass；不是对所有 VPN 流量全局绕过。

## 6. 开发边界

### 所有权与生命周期

- sing-box 使用库公开 API，不复制 C 结构、map key/value 或另写一套 TC 资源管理。
- runtime 接管 backend 后，消费端不得另留一份 owner 独立关闭。
- 启动最后才启用控制；回滚失败仍要保留 runtime/资源所有权，供后续 Close 重试，不能丢引用后声称清理完成。
- 停止消费端回调/listener/session，再释放 runtime。不能持有 worker 需要的锁等待 worker 退出。
- 接口重建要核对 name/ifindex/framing/role；事件触发协调，不能靠每秒全量重挂代替正确生命周期。
- 保留无默认接口时的启动/等待行为、共享接口首次出现时的懒初始化行为。
- 路由、mark、sysctl 只处理自己拥有的状态；保留已有 mark 位，不覆盖其他程序 attachment/路由。Android 的两条 `/1` local routes 不要简化成 `/0`。

### BPF 与兼容性

- 能力探测只覆盖实际选择的数据平面、对象和 framing，不因未选对象失败拒绝整个配置，也不只凭内核版本判断支持。
- 修改 native 字段布局、flags、section、map key/value、对象变体均属于 ABI 修改，需同步源代码、大小端对象及 manifest。
- 当前生成工具链为 Android NDK r29 / Clang 21；以库 Makefile 为准。正常消费 checked-in 对象不要求安装 NDK。
- 保持 verifier 有界路径、热路径分配约束、分片及 IPv6 扩展头处理，不以“简化”为由删掉这些条件。
- 修改公共函数先查所有调用者，避免只修单一路径。改动限于需求相关范围，不顺手加入其他 fork 功能或恢复已排除提交。

## 7. 后续开发与同步流程

1. **先确认状态**：读本文、用户最新指令、受影响的配置文档与测试；`git status`、`git worktree list`、远端 refs、root/test go.mod。不要覆盖未提交改动或别的任务 worktree。
2. **定位范围**：先区分底座、CHIZI 上游、我们消费端扩展、我们库扩展、Android 相邻功能。追踪配置 → 策略 → backend/native → 用户态 session → cleanup。
3. **获取上游事实**：fetch 指定仓库/分支，记录来源 commit；比较 patch/tree，识别上游已吸收、重写或删除的补丁，不能盲目重放旧队列。
4. **底座更新**：跟进 Yuu 已采用的官方版本，排除统一延迟与 Build，重放必要 reF1nd 兼容；检查 daemon/provider/启动行为。单独生成不含 eBPF/本地功能的 testing-base。
5. **库更新优先**：以 CHIZI sing-ebpf main 为基准保留一个本地扩展提交；检查公开 API/ABI，必要时生成对象并测试。确定并发布库 hash 后才固定消费端 pseudo-version。
6. **消费端更新**：重放 CHIZI inbound 代码/文档，保留独立 Android Wi-Fi 功能，再将我们的扩展归为代码、文档两个提交。不要重新带回 FakeIP `1c6d4a3d` 补丁。
7. **依赖与文档**：两套 module 分别 tidy；不能提交临时本地路径 replace。配置改动同时更新中英文文档及 `docs/schema.json`。
8. **验证与复核**：先 focused tests，再按改动范围选择 race、cross-build、ABI generation、特权内核测试。检查最终 diff 只有预期改动；保留最小有效回归。
9. **提交与推送**：遵守下面的签名与历史规则。改写前建本地 backup ref；授权推送时使用明确远端旧哈希的 force-with-lease，成功后核实远端新哈希。
10. **交付**：说明 changed/why/tests/未验证项，更新交接中的当前状态；不要把旧测试结果冒充本轮结果。

### 提交规则

- 交互开发提交必须 GPG 签名：`56BBBCE870EF17D9`。例如 `git commit -S56BBBCE870EF17D9`；重放使用 `git cherry-pick -x -S56BBBCE870EF17D9` 保留来源。
- 不修改全局或仓库 GPG 配置。只有无人值守且被交互口令阻塞时，才允许 `git commit --no-gpg-sign`；按既有规则登记 unsigned hash 到 `.codex/HANDOFF.md`，不得之后只为补签重写该提交。交互恢复后恢复签名。
- `.codex/` 是已有本地工作状态，不纳入产品提交。本文件是根目录项目交接文档，不替代 `.codex/HANDOFF.md`。
- 正式记忆写入遵循既有 write gateway：先核对无未完成事务；若其他任务拥有冲突内容，只暂停受影响写入，不接管覆盖。
- 新建工作分支默认用 `codex/` 前缀。备份和其他工作树可能包含已废弃实现，不可仅因它们存在就作为正确来源。
- 用户要求的历史整理不能靠新增 revert 留下待删除提交；但未获相应授权时，不自行改写共享远端历史。

## 8. 验证命令与验收范围

以下在 Linux/WSL Bash 执行，按修改范围选用，不要求每次跑全部。当前验证工具链为 Go 1.26.8；go.mod 仍声明 1.25.5，不应为测试工具链顺手修改最低版本。

### sing-box focused tests

```bash
export GOTOOLCHAIN=go1.26.8
go test -tags with_ebpf,with_quic ./protocol/ebpf ./common/listener ./common/dialer ./option ./experimental/cachefile
go test -race -tags with_ebpf,with_quic ./protocol/ebpf
# 底座、provider 或协议相关变动时：
go test -tags with_quic ./protocol/anytls ./protocol/snell ./protocol/group ./provider/... ./adapter/... ./route/... ./daemon
# test 是独立模块；这个子 shell 不改变调用者目录。
(cd test && go test -tags with_quic -run '^Test(AnyTLSSelf|AnyTLSFallback|SnellSelf|SnellUDPDomainMapping)$' .)
git diff --check
```

### Linux / Android 交叉构建与 schema

```bash
export GOTOOLCHAIN=go1.26.8
tags="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_ebpf"
CGO_ENABLED=0 go build -tags "$tags" -o /tmp/sing-box-linux ./cmd/sing-box
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -tags "$tags" -o /tmp/sing-box-android-arm64 ./cmd/sing-box
/tmp/sing-box-linux schema -o /tmp/sing-box-schema.json
cmp /tmp/sing-box-schema.json docs/schema.json
```

testing-base 构建去掉 `,with_ebpf`。这里用 `DEFAULT_BUILD_TAGS_OTHERS` 的非 cgo 路径，不代表验证了包含 Naive/cronet 静态库的完整构建；本机直接使用 `DEFAULT_BUILD_TAGS` 曾遇到 libcronet.a 链接不兼容，不能报告为代码测试失败或完整构建通过。

### sing-ebpf

```bash
export GOTOOLCHAIN=go1.26.8
go test -tags with_ebpf ./...
go test -race -tags with_ebpf ./...
go vet -tags with_ebpf ./...
# 仅 native/ABI/generated 相关变更需要，先准备 Makefile 指定的 NDK：
make generate
make check
# 在安全的隔离测试环境、具备授权和权限时才运行：
sudo env SING_EBPF_INTEGRATION=1 go test -tags 'with_ebpf ebpf_integration' ./...
```

特权 opt-in 为库的 `SING_EBPF_INTEGRATION`，不要套用旧变量。先检查测试实际使用的 namespace/interface/cgroup 与筛选项，避免把真实宿主网络当测试夹具。

### 本轮已验证 / 未验证

- alpha.4 整合时：相关协议/provider/adapter/route/daemon/dialer/DNS/cache/Clash API 测试、相关 race 测试、AnyTLS/Snell 自测、非 cgo Linux/Android arm64 构建及 eBPF schema 比对通过。
- 期间已修复 provider manager 返回内部 slice 导致的并发问题、Snell TTL 测试真实时钟不稳定、AnyTLS provider 覆盖兼容与 Snell 测试类型不匹配；修复已归入相应底座提交，不应在重放时丢失。
- testing-base `ffe26fa0`：协议/provider/adapter/route/daemon/dialer/option、自测、非 cgo Linux/Android arm64 构建通过。
- 删除 FakeIP 后的 testing-ebpf `6124ebea`：检查差异只撤销该补丁的四个文件；FakeIP 包编译、cachefile 和 protocol/ebpf 测试通过。删除后没有重新宣称完成全套构建/内核验收。
- sing-ebpf `cc73cfd` 的此前整合验证包含 NDK 生成检查及相关 TC/endpoint/shared/FakeIP/IPv6/fragment 内核测试；这不是接手后新改动的验收凭证。
- **尚无 Android 真机验收。** TUN/IPsec 建连、断开重连、接口替换、热点共享、IPv4/IPv6、UDP 500/4500 与实际 checksum offload 行为仍需设备验证。交叉编译和主机测试不能替代。

### 2026-09-15 reF1nd sing-tun 切换验证

固定版本为 `v0.9.4-0.20260915103927-7512d34d3229`，主模块与 test 模块使用相同 replace；没有升级其他依赖。

- 通过：sing-box eBPF/TUN/AnyTLS/Snell、dialer/listener、route/adapter/provider/group 的 `-race` 测试；AnyTLS/Snell 独立模块自测；非 cgo Linux / Android arm64 构建及 schema 一致性检查。
- 通过：在本项目依赖组合下，sing-tun 与 ping 的六项修复对应非特权回归（`-race -tags with_gvisor`）。筛选为 `^Test(ForwardNAT|UnprivilegedConn|BuildBypassRoutes|ReconcileBypass|IsDirectRedirectConnection|LocalICMP|SystemResponds|LocalDNSServer|SystemAcceptLoop|TCPNat)`。
- 限制：sing-tun 全包测试未通过，内核 TUN 用例报 `TUNSETIFF: operation not permitted`，ping `TestIsClosed` 报 `socket(): permission denied`。不能将上述 focused PASS 当作内核测试通过；Android 真机仍未验证。

### 2026-09-15 CHIZI UDP 上游更新

- 消费端同步到 `f5b74643` 的三项优化：内部 UDP socket 缓冲区、批量回复 writer 复用、重定向 UDP batch buffer 所有权转交。九个上游文件保持与上游内容一致，不改 endpoint readiness 或 shared/local 策略。
- sing-ebpf 上游 main 更新为 `c52c21d`，我们在其上重放一个 endpoint 扩展提交 `98c82044b9ecee67b449b8bb61999a023a7f028e`，已签名推送。库 `go test -race -tags with_ebpf ./...` 通过；未更改 native/生成对象，无需重新生成。
- root/test 固定新库版本，保留已授权的 reF1nd sing-tun `7512d34`。库自身 require sing 稳定版不意味着消费端也降级 sing；消费端仍按自身模块图选择版本。
- 本轮消费端验证通过：eBPF/listener/dialer/option/include/route/Clash API 的并发测试，非 cgo Linux/Android arm64 构建及 schema 比对。内核特权测试和 Android 真机未在本轮重跑。
- 此次消费端更新与上一轮 sing-tun 切换一并整理：三项 UDP 优化保留为上游层提交，依赖与扩展整合归入代码提交，交接记录归入文档提交；扩展层仍保持代码/文档两提交。第 3 节哈希是此前代码基线，当前发布 tip 以 Git 分支为准。

## 9. agy 接手的第一步

1. 对照第 3 节核实三个远端分支；本文合入文档提交会改变 testing-ebpf 的 tip 哈希，先区分文档变化和代码变化，再决定是否更新基线。
2. FakeIP 旧缓存补丁仍明确不保留。reF1nd sing-tun 已获用户授权切换，后续更新以固定版本和最新验证记录为准，不要恢复旧版本或重新引入旧补丁。
3. 阅读要修改路径的现有代码与测试；eBPF 细节以消费端固定的库 API、库 `ARCHITECTURE.md` / README 及配置文档为准。
4. 新任务先确认目标属于哪一层，保持 testing-base 干净、库一个扩展提交、消费端扩展代码/文档两个提交。
5. 真机或工具链不可用时明确记为未验证，继续能完成的独立工作，不编造 PASS。
