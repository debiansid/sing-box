# sing-box 维护约定（交接给 pi）

## 目标与分支

维护 debiansid/sing-box 自己的底座：沿用 CHIZI-0618 的裁剪范围，额外保留 reF1nd 的 TUN、AnyTLS 与 Snell 修复。

- `testing-base`：SagerNet testing 底座 + 挑选的 reF1nd 功能/修复 + CHIZI 的必要适配 + reF1nd TUN/AnyTLS/Snell。不得包含 eBPF inbound 或 endpoint-connected-bypass。
- `testing-ebpf`：严格建立在 `testing-base` 上。其上按顺序保留四笔提交：CHIZI 基础 eBPF 代码、CHIZI 基础 eBPF 文档、我们的 endpoint-bypass 代码、我们的 endpoint-bypass 文档。
- 不再等待 CHIZI 更新裁剪分支；直接对照 reF1nd 新代码自行裁剪维护。CHIZI 的旧分支是裁剪范围和基础 eBPF 的参考。
- 不要整体合并 reF1nd 分支，也不要把整份新树覆盖到现有分支。维护说明应随底座保存，并同步到 eBPF 分支。

## 上游来源

- `https://github.com/SagerNet/sing-box`，`testing`：核心底座。
- `https://github.com/reF1nd/sing-box`，`reF1nd-testing`：保留功能与修复的来源。
- `https://github.com/CHIZI-0618/sing-box`，`reF1nd-testing`：裁剪参考；该分支可能已经带有基础 eBPF，不能直接当无 eBPF 底座。
- 同仓库 `ebpf-inbound`：基础 eBPF 代码和文档。reF1nd 也可能收录同一补丁，不得重复应用。
- `https://github.com/CHIZI-0618/sing-ebpf`，`dev`：当前适配库的上游。先核实历史关系，不要因为 README 提到 main 就擅自更换分支。
- `https://github.com/debiansid/sing-ebpf`，`dev-endpoint-connected-bypass`：本项目实际使用的 endpoint 扩展库。

## 裁剪范围

保留并更新已有功能及其必要修复：

- sniffer、QUIC 嗅探缓存、resolve 的 `match_only`。
- Clash API 的 Android 包名显示、DNS rules、restart/reload、rule-provider、规则临时开关、多值 `clash_mode`。
- outbound provider、静态文件存储、订阅解析、provider 更新与代理组协作。
- DNS group 并发查询、hosts domain alias。
- Android 核心 Wi-Fi 状态与 `network_type: wifi`。
- 已保留功能的修复，例如 selector 切换时中断连接、资源下载保护、FakeIP 缓存清理、reload 前配置检查。
- CHIZI 为上述功能所做的 API 适配。

不因上游新增而自动加入：观测 API/Grafana、loadbalance/pass、额外 DNS/TLS 开关、外部 UI 自动更新、GSO 开关、进程查询优化等。只有保留功能确实依赖时才引入必要部分，并说明依赖证据。用户明确扩大范围时以用户要求为准。

### 必须额外保留：reF1nd TUN

- Android VPN route bypass 向平台传递。
- 核心负责创建 TUN 时的桌面 route address set 加载修复。
- reF1nd/sing-tun 的修复，包括虚拟 DNS 地址的本地 ICMP 应答及该库其他已有修复。
- 主模块与 `test/go.mod` 都使用相同的 reF1nd/sing-tun 版本替换。
- 不得回退到 `../../sing-tun` 等依赖机器目录布局的本地替换，也不得无意换回 SagerNet 库丢失修复。

### 必须额外保留：reF1nd AnyTLS

- 主模块与测试模块都使用同一 reF1nd/sing-anytls 版本。
- 保留 TFO、默认 fallback、ALPN fallback、`disable_reuse`、URLTest 复用行为及初始化前生命周期保护。
- `client_metadata` 的未配置、显式空字符串、指定值必须保持区别，不能直接改回普通 string 丢失语义。
- provider 的 AnyTLS 覆盖、Clash 订阅解析、schema、中英文文档、测试必须同步支持 `disable_reuse` 和 metadata。
- TLS 的 `certificate_server_name` 属于另一项被裁掉的功能，不要随 AnyTLS 恢复。

### 必须额外保留：reF1nd Snell

- 保留 `Extend Snell protocol compatibility`，源提交 `51fde25f637be8693177cf816f9761f3c82a2718`。
- 主模块和测试模块均替换到 reF1nd/sing-snell；本次版本为 `v0.0.0-20260917160408-d8a791bb5614`。
- 保留该提交的版本兼容、多用户认证、obfs、UDP/QUIC 代理、批量包读写、配置校验、文档和回归测试。
- Snell 所需的 simple-obfs 服务端实现随该补丁保留；不要因此引入独立的 Shadowsocks inbound simple-obfs 扩展。

### 提交顺序与适配清理

以 reF1nd 分支的祖先顺序为准（`git log --reverse`），不是作者日期，也不是发现补丁的先后。仅跳过不保留的功能，不能把 TUN/AnyTLS/Snell 全部追加到 provider 后面。

当前保留的 reF1nd 源提交顺序：

1. Android VPN route bypass → 桌面 TUN route address sets → 虚拟 DNS ICMP（sing-tun 替换）→ sing-tun 修复 → AnyTLS compatibility。
2. Improve sniffer → resolve match_only → Android 包名 → Clash DNS rules → DNS group → hosts domain alias。
3. Extend Snell protocol compatibility → Clash restart → outbound provider → reload → 静态文件存储 → rule-provider → 多值 clash_mode → 临时禁用规则。
4. selector 中断连接修复 → FakeIP 清理修复 → reload 前检查。
5. CHIZI 的 Android Wi-Fi 和必要 API 适配，以及本地裁剪适配，放在其依赖齐备的位置；最后是维护文档。然后才叠加四笔 eBPF/endpoint 提交。

旧 `fix: adapt trimmed provider and routing tests to current APIs` 与后来的 `fix(provider): preserve reF1nd AnyTLS options in trimmed base` 已在本轮重建中消除重复：不再先删除 AnyTLS 支持再恢复。只保留被裁掉的 TLS 字段清理、测试辅助对象及独立测试模块依赖整理。不要机械重放旧适配补丁。

## 更新步骤

1. 检查工作区、worktree、分支、远端和仓库内其他 AGENTS.md；保留用户未提交修改。
2. fetch 相关远端引用，先不 merge/rebase。核对分支重写、共同祖先、patch 等价关系和版本来源，不能仅根据提交标题判断。
3. 对照 CHIZI 已保留的功能，找出 reF1nd 中对应的新版提交。记录源 SHA、原作者、保留/排除理由及冲突适配。
4. 按上述源提交顺序，在独立工作分支或 worktree 重建底座，保留源提交作者和信息。必要适配独立、明确记录；不要把我们的 endpoint 代码混入原作者的提交。
5. 同步 TUN、AnyTLS、Snell 及 provider 适配。被裁掉功能的测试依赖应改成最小测试辅助对象，不能为了让测试编译就引入被裁掉的整个功能，也不能删除仍有意义的测试。
6. 验证无 eBPF 底座，然后接上 CHIZI 两笔 eBPF 提交，再接上我们的两笔 endpoint 提交。底座变更不能藏在 endpoint 提交里。
7. 库有上游更新时，先在适配库分支完成同步与验证，再更新 sing-box 主模块和测试模块的版本引用；库无更新时不制造无意义的版本变动。
8. 完成测试后更新本地 `testing-base`、`testing-ebpf`。重写前保留可恢复的旧引用。检查工作区与提交分层。
9. 用户要求推送时，先核实远端仍为预期 SHA；两个分支优先用 `git push --atomic` 和逐分支显式 `--force-with-lease=refs/heads/<branch>:<expected-sha>`。远端有新变化先审查，禁止直接覆盖。推送后核实远端 SHA 和本地领先/落后均为零。

## eBPF 与 endpoint 约束

- sing-ebpf 管 BPF 机制，runtime 管 TC 网络资源和回滚，sing-box 管配置、监听、会话与 Router。不得绕过公开 API 操作私有 map 或复制 ABI。
- `local.endpoint_connected_bypass` 只用于 local TC。匹配条件是 endpoint CIDR 与端口/协议同时命中。
- force-intercept 和 DNS 语义必须按设计处理；未 READY 的 endpoint 要进入 Router，不能被普通 bypass policy 放走。READY 后允许原生内核旁路。
- endpoint 不选择 outbound。正常路由、Clash mode、selector/provider 仍决定被拦截流量的出口。
- 不影响 shared 或普通 bypass 策略；不恢复旧 endpoint_relay、强制出口或用代理连通性替代 READY 的实现。
- 保留 READY 写内核失败时的状态回退、接口消失/重建处理，以及 TUN/IPsec 各自的 readiness 判定。
- 如改 native/ABI，必须同步生成大小端对象与 manifest，并进行对应验证；只改消费端时不要无故重新生成对象。

### 已知待专项处理项

截至下方快照，sing-ebpf 的 local TC `local_selected` 中，DNS off/hijack 已在 endpoint gate 前，但端口 53 的 `respect_policy` 分支仍在 gate 后，与旧版 DNS 优先顺序不一致。不能把之前测试通过解释为此问题已修复；专项处理时应同时修正优先级和相应测试预期。手机 Google VPN 的 endpoint 配置为 500/4500/2408，本次实测未验证 endpoint 端口 53。

## 验证

按实际改动选择相关检查；以下是此次维护使用过的命令模板，均在 Linux/WSL 的仓库根目录执行：

```bash
go test -tags with_ebpf ./protocol/ebpf ./common/listener ./common/dialer ./common/udpio ./common/process ./option ./route/... ./dns/... ./provider/... ./protocol/group ./experimental/clashapi ./daemon
go test -race -tags with_ebpf ./protocol/ebpf ./protocol/anytls ./protocol/snell ./protocol/tun ./transport/simple-obfs ./provider/... ./protocol/group ./route/... ./option
# libbox 的既有 runtime linkname 需要此链接参数；不要为它改业务代码。
go test -ldflags=-checklinkname=0 ./experimental/libbox
```

- AnyTLS/Snell 改动后，在 `test/` 运行 `go test -tags with_quic,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0 -run '^(TestAnyTLS|TestSnell)' -timeout 5m ./...`，覆盖本地 TCP/UDP、Snell 版本兼容与 AnyTLS fallback；这不是仅编译检查。
- 主程序验证使用 tags：`with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,badlinkname,tfogo_checklinkname0`。至少构建 Linux 和 Android arm64。
- Android 使用真实 NDK、`CGO_ENABLED=1 GOOS=android GOARCH=arm64` 与合适的 clang；从当前环境定位工具链，不硬编码前任机器路径。可参考 `.github/workflows/android-ebpf.yml`。
- 配置结构改动后，用同一版本程序的 `schema -o <临时文件>` 对照 `docs/schema.json`。
- 用 `go list -m` 分别核实主模块和测试模块的 sing-tun、sing-anytls、sing-snell、sing-ebpf 实际替换目标，运行 `git diff --check`。
- native/内核附着改动才扩大到对应 privileged/verifier 测试；应使用隔离环境。构建、单元测试不能替代 Android 真实设备验收。
- 不把未执行的检查写为 PASS，不因 NDK/网络阻塞就宣称运行行为已验证。不要擅自修改或重启手机上的服务来完成测试。

## Android 排查经验

- 分清三段：控制域名请求、未 READY 的 UDP/IPsec 握手、READY 后的内核直出。
- 已实测：UDP/4500 在建立前进入 eBPF/Router，连接建立后切换 Wi-Fi 原端口直出。这是用户要求保留的行为。
- Google VPN 控制域名 `phosphor-pa.googleapis.com`、`beryllium-pa.googleapis.com` 的分流会影响本场景观察到的出口地区。用户把它们也改走 GVPN_PROXY 后，确认出口随该组改变；只改 IPSEC selector 不足以保证同一结果。不要将此场景结论泛化为服务端地区分配保证。
- 先读实际连接链、selector 当前选择、接口/路由和抓包，再归因；不要仅凭配置里某个子组选择了日本就认为实际链经过日本。
- 不输出配置密钥。日志级别不足时明确证据边界；未直接读到 READY 位就不能声称已经读取。
- `/data/local/tmp/tcmapdump` 是特定 assignment-map 工具，不是通用 BPF map 读取器，禁止拿它读取 control map。

## 2026-09-25 补充 Snell 之前的已推送快照（仅供追溯）

- reF1nd 来源：`9fa48346156176fe4f39ea00c2666308581ed27c`。
- SagerNet 底座：`b609f959f57ce34416c51c7b87ce4a76f2e1df56`。
- `testing-base`：`568190ad5f22a62103f6c6dcf8f5b07834315861`。
- `testing-ebpf`：`8924643bcd4e49904d00148f22587e7d4a0bd8fc`。
- reF1nd/sing-tun：`v0.9.6-0.20260924150700-79c79595b99d`。
- reF1nd/sing-anytls：`v0.0.0-20260924145214-2a81df5d3e9f`。
- debiansid/sing-ebpf：`v0.0.0-20260923012317-4d66f051f6b9`。
- 上述版本通过相关单元/竞态测试、AnyTLS 本地端到端测试、libbox 测试以及 Linux/Android arm64 构建；该快照的新版 TUN/AnyTLS 尚未在手机实测。补充 Snell 后的分支 SHA 请以实际 git 引用为准，不使用此历史快照回退。

## 2026-09-25 诊断性能同步

- 本轮重新 fetch 后，reF1nd `reF1nd-testing` 仍为 `9fa48346156176fe4f39ea00c2666308581ed27c`，SagerNet testing 仍为 `b609f959f57ce34416c51c7b87ce4a76f2e1df56`，无需重放底座功能。
- CHIZI `ebpf-inbound` 更新至 `447efb8e9853649c8dc1a44442d1851d2891515d`。将 `7b411252367c4c2d7dd13acf7e784408bd7c31cd` 和 `447efb8e9853649c8dc1a44442d1851d2891515d` 的诊断优化折入基础 eBPF 代码层，保留 CHIZI 作者并记录 Yuu518 的贡献；四笔 eBPF 分层不变。
- sing-ebpf 上游 dev 更新至 `c3e95b329d35b6d11ae38d01b384308baa2edabc`；其上重放已有 DNS policy 与 endpoint 扩展，适配库为 `10a5811e67262f4ba5a6760acbb4acd31944406d`（`v0.0.0-20260925103234-10a5811e6726`）。主模块与测试模块同步引用。
- 上游删除 shared 普通 pass 计数器，保留 fragment pass；TC per-CPU 计数改为普通增量，map occupancy 仅遍历 key。消费端诊断 schema 升至 7，protobuf 保留已删除字段编号 9、10。
- native 源码、大小端对象与 manifest 同步生成并通过 `make check`；库竞态测试及隔离网络命名空间内的对象加载、map occupancy、TC endpoint/force-intercept/分片测试通过。这些测试不代表 Android 真机验收，也未修复上述 DNS `respect_policy` 待处理项。
- 适配库包含新提交时，发布顺序为先推送 sing-ebpf，再推送消费端；未发布前可用临时 modfile 的本地路径 replace 验证，但不能将临时 replace 或非标准 zip 的校验和提交。模块 zip 必须由 Go 工具或 golang.org/x/mod/zip 生成，禁止直接用 git archive 充当模块代理；发布后从独立缓存使用 go mod download 核对主模块与测试模块校验和。

## 提交签名与上下文

- 交互开发提交默认使用 GPG 密钥 `56BBBCE870EF17D9` 签名。用户在当前任务明确要求跳过时服从该要求，不把一次豁免写成永久免签规则。
- 无人值守时，只有交互口令阻塞签名才使用 `git commit --no-gpg-sign`；将每个未签名 hash 记入 `.codex/HANDOFF.md`，不要仅为补签重写已存在提交。
- 禁止修改全局或仓库 GPG 配置。恢复交互开发后恢复签名。
- 检索历史先定位相关条目，再读最小必要片段，不默认加载完整索引或会话。
- 正式记忆写入使用已有写入网关，先确认无未完成事务；有其他任务占用冲突内容时，只暂停受影响写入，继续独立工作。
