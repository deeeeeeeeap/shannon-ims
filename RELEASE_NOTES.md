# Unreleased — SMS and runtime recovery

## 中文

- 修复短信 SIP 事务把临时响应当成失败的问题，接受最终 `200` / `202`；这两种响应都不会直接标记接收方已送达。
- SIP 与 RP-DATA 使用发送前读取的同一份 SMSC，避免启动时缺失或过期的短信中心阻断发送。
- 发送取消可中断阻塞写入；不会因为超时而自动提交第二条短信。
- IMS SMS-DELIVER 接入真实解码、持久化、乱序长短信重组、收件箱与通知。数据库事务成功后才返回 SIP 成功并安排 RP-ACK；临时存储失败返回 `503`。
- 投递/状态报告的临时写库错误不再被忽略；无匹配或歧义的报告不更新其他消息。
- 通道关闭、SWu 退出、注册到期会撤销就绪状态。已失败的实例可进入现有串行恢复流程，异步启动失败保留重试退避。

升级前备份运行数据库。新增 `sms_incoming_part_journals` 表保留未完成分片和去重记录；完整消息与联系人在同一事务中提交，完成分片不保留第二份正文。旧表不删除，旧二进制可忽略新表；回滚期间新接收的未完成分片需等支持此表的版本重新启动后才能继续重组。

当前到期恢复会重建链路，尚非无中断的受保护 REGISTER 续期，恢复时存在短暂不可用。默认使用现有 30 秒检查和 30/60/120 秒失败退避。实卡兼容性仍需逐运营商验证；Wi-Fi Calling 注册成功不等于短信业务授权。没有新增强制绕过、SIM 重置或发送失败自动重试。

## English

- SIP MESSAGE transactions wait past provisional responses and accept final 200/202 responses without claiming recipient delivery.
- SIP routing and RP-DATA share the SMSC read for the current submission instead of retaining a stale startup value.
- Cancellation interrupts a blocked request write; ambiguous outcomes are never automatically resubmitted.
- IMS SMS-DELIVER now reaches decoding, durable out-of-order multipart assembly, inbox storage and notifications. SIP success and RP-ACK follow durable storage; transient database failures receive 503.
- Delivery/status report persistence errors are propagated. Unmatched or ambiguous reports cannot update unrelated messages.
- Channel loss, SWu termination and registration expiry revoke readiness. Failed admitted instances can recover through the existing serialized lifecycle with failure backoff preserved across asynchronous startup.

Back up the runtime database before upgrading. The additive `sms_incoming_part_journals` table retains incomplete fragments and deduplication records. Inbox/contact updates commit atomically; completed fragments do not retain a second body copy. Older binaries ignore the new table; pending fragments resume assembly when a supporting version runs again.

Expiry recovery currently rebuilds the connection, with a service interruption; seamless protected REGISTER refresh is not implemented. Recovery uses the existing 30-second check and 30/60/120-second failure backoff. Carrier acceptance still requires live validation. Registration is not proof of SMS entitlement. No SIM reset, policy bypass or automatic SMS resubmission was added.

# Shannon IMS v0.1.0-rc.1

## 中文

这是 Shannon IMS 首个可冻结的发布候选稳定基线。它保留已经验证的 Wi‑Fi Calling / IMS 行为，重点收口并发所有权、全量回归测试、持续集成和可验证发布包。

主要变化：

- `ipsec3gpp` 的每条 flow 明确拥有独立入站/出站 SA，不再复制包含 `sync.Mutex` 的第三方 SA；出站序列号使用原子状态，入站 SA 构建后只读，反重放窗口独立加锁。
- 增加并发双向 ESP 变换回归测试，关键并发模块通过 `go test -race`。
- 修复 QMI lazy-bootstrap 旧断言、匿名化后失配的 MCC/MNC、IMEI、GSMA URN 夹具，以及依赖本机绝对路径的数据库测试。
- push/PR CI 覆盖双 Go 模块全量 test/vet、关键 race、前端 lint/typecheck/build、隐私扫描、运行时脚本和 Linux amd64 bundle smoke。
- 发布包新增 `release-manifest.env`，并同时提供二进制 SHA-256、归档内 `SHA256SUMS` 和独立归档 `.sha256`。
- 数据库、日志、运营商覆盖和 session secret 统一使用绝对 runtime root；卸载会在停止服务前验证数据目录、配置和可执行文件均为安装根的严格子路径，并拒绝 symlink/junction 造成的物理路径逃逸。
- ESP replay window 只在 ICV 校验与解密成功后提交序号，错误完整性的高序号包不能再推进窗口；ESP 序号 `0` 在首次初始化前也始终拒绝。
- 登录限流默认只使用 TCP peer 地址，显式禁用未配置代理头信任，并通过 TTL 清理和硬容量上限约束状态表。
- 移除缺少完整包配方、迁移和 CI 的陈旧 OpenWrt init/config 片段，并明确当前不提供受支持的 OpenWrt 包装。

兼容性承诺：本轮不修改 IMS-AKA、AUTS/SQN 重同步、3GPP IPsec 协商、短信发送/接收或 eSIM 操作语义。

已知限制：

- Release 归档不是完整 strongSwan 发行版；两个自定义插件仍必须针对目标机匹配的 configured source 构建。
- 当前运行方式需要 Linux/WSL2、设备访问权限以及 raw socket/TUN/路由所需权限。
- 当前不提供受支持的 OpenWrt 安装包；恢复支持前必须补齐单一 runtime root、数据迁移、包管理器卸载语义和目标布局 CI。
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
- Databases, logs, carrier overrides, and the session secret now share one absolute runtime root. Uninstall validates lexical and physical boundaries before stopping the service and rejects symlink/junction escapes.
- ESP sequence numbers are committed to the replay window only after successful integrity verification and decryption, preventing invalid high-sequence packets from advancing the window. ESP sequence `0` is rejected even before first-window initialization.
- Login throttling uses the direct TCP peer by default, disables unconfigured proxy-header trust, and bounds its state with TTL cleanup and a hard capacity.
- The stale OpenWrt init/config fragments were removed because they had no complete package recipe, migration contract, or CI; this release does not claim a supported OpenWrt package.

Compatibility statement: this round does not change IMS-AKA, AUTS/SQN resynchronization, 3GPP IPsec negotiation, SMS send/receive, or eSIM operation semantics.

Known limitations:

- A release archive is not a complete strongSwan distribution; both custom plugins must still be built against the target's matching configured source.
- The supported runtime requires Linux/WSL2, device access, and privileges for raw sockets, TUN, and routing.
- No supported OpenWrt package is currently provided; restoring one requires a single-runtime-root layout, data migration, package-manager uninstall semantics, and target-layout CI.
- Subscription provisioning, regional policy, SIM authorization, and modem firmware still determine live-network availability.
- RC stability checks do not replace hardware acceptance for every modem, SIM, and network combination.
