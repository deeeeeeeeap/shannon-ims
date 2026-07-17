# Shannon IMS v0.1.0-rc.1

## 中文

这是 Shannon IMS 首个可冻结的发布候选稳定基线。它保留已经验证的 Wi‑Fi Calling / IMS 行为，重点收口并发所有权、全量回归测试、持续集成和可验证发布包。

主要变化：

- `ipsec3gpp` 的每条 flow 明确拥有独立入站/出站 SA，不再复制包含 `sync.Mutex` 的第三方 SA；出站序列号使用原子状态，入站 SA 构建后只读，反重放窗口独立加锁。
- 增加并发双向 ESP 变换回归测试，关键并发模块通过 `go test -race`。
- 修复 QMI lazy-bootstrap 旧断言、匿名化后失配的 MCC/MNC、IMEI、GSMA URN 夹具，以及依赖本机绝对路径的数据库测试。
- push/PR CI 覆盖双 Go 模块全量 test/vet、关键 race、前端 lint/typecheck/build、隐私扫描、运行时脚本和 Linux amd64 bundle smoke。
- 发布包新增 `release-manifest.env`，并同时提供二进制 SHA-256、归档内 `SHA256SUMS` 和独立归档 `.sha256`。

兼容性承诺：本轮不修改 IMS-AKA、AUTS/SQN 重同步、3GPP IPsec 协商、短信发送/接收或 eSIM 操作语义。

已知限制：

- Release 归档不是完整 strongSwan 发行版；两个自定义插件仍必须针对目标机匹配的 configured source 构建。
- 当前运行方式需要 Linux/WSL2、设备访问权限以及 raw socket/TUN/路由所需权限。
- 运营商开户、区域策略、SIM 权限和模组固件能力仍决定真实网络是否可用。
- RC 稳定性验证不替代每种模组、SIM 和运营商组合的实机验收。

## English

This is the first freeze-ready Shannon IMS release-candidate baseline. It preserves the validated Wi‑Fi Calling / IMS behavior while closing concurrency ownership, full regression coverage, continuous integration, and verifiable release packaging.

Highlights:

- Every `ipsec3gpp` flow now owns distinct inbound and outbound SAs; the code no longer copies a third-party SA containing `sync.Mutex`. Outbound sequence state is atomic, inbound SAs are immutable after construction, and replay windows own their locks.
- Concurrent bidirectional ESP regression coverage was added, and critical packages pass `go test -race`.
- Stale QMI lazy-bootstrap assertions, anonymized MCC/MNC, IMEI and GSMA URN fixtures, and a machine-specific database test were corrected.
- Push/PR CI covers full test/vet for both Go modules, critical race tests, frontend lint/typecheck/build, privacy scanning, runtime script contracts, and Linux amd64 bundle smoke verification.
- Release archives now include `release-manifest.env`, a binary SHA-256, in-bundle `SHA256SUMS`, and a detached archive `.sha256`.

Compatibility statement: this round does not change IMS-AKA, AUTS/SQN resynchronization, 3GPP IPsec negotiation, SMS send/receive, or eSIM operation semantics.

Known limitations:

- A release archive is not a complete strongSwan distribution; both custom plugins must still be built against the target's matching configured source.
- The supported runtime requires Linux/WSL2, device access, and privileges for raw sockets, TUN, and routing.
- Subscription provisioning, regional policy, SIM authorization, and modem firmware still determine live-network availability.
- RC stability checks do not replace hardware acceptance for every modem, SIM, and network combination.
