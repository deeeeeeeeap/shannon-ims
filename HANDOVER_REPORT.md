# Shannon IMS 出差归档与交接报告

- 仓库：`https://github.com/deeeeeeeeap/shannon-ims`
- 基线：`main` = `b25b46d`（开工时与 `origin/main` 一致）
- 工作分支：`feat/auto-optimization`，全部提交只在本地，**没有执行过 `git push`**
- 工作目录：`E:\11.10归档文档\shannonims`，目录之外没有写入任何文件

## 0. 一页结论

**交付了什么**

- 你指定的两条主线都已完成并提交：**代理链路与 VoWiFi 协同**（7 个提交，见 2.1）和**短信收发通用化**（4 个提交，见 2.2）。
- 体检中发现的另外三个模块的缺陷也已修复：配置文件并发写入与设置丢失（2.3）、串口与 AT 层（2.4）、通知渠道的凭据外泄与无限等待（2.5）。
- 为没有实物的环境写了仿真层：软件蜂窝模组、SOCKS5 代理模拟器、短信 PDU 生成器，以及 SMTP 和各通知服务的替身。新增 38 个测试文件、337 个测试函数。
- 新增 `scripts/verify-local.sh`，一条命令跑完 CI 的全部检查。
- 共 19 个本地提交，都在 `feat/auto-optimization` 分支上，没有推送。

**验证到什么程度**

- 最终的完整运行 23 步全部通过：前端的 lint、类型检查、测试、构建，三个 Go 模块的测试与 vet，带竞态检测的测试，隐私扫描与脚本测试，发布包冒烟构建（见 4.5）。
- 这说明：在软件替身上，代码按设计工作；CI 范围内原有的测试全部通过（其中 6 个既有测试文件随行为变化做了修改）。仓库内 sipgo fork 自带的测试不在 CI 范围里，也不在这 23 步里（见 1.5 的 G8）。
- 这**不**说明：与真实模组、真实代理、运营商网络、通知服务的行为一致。本次没有任何改动在实物上运行过。
- 新增测试里，只有两批确认过“在旧代码上会失败”（见 4.6）。1.5 里标为“读码”的缺陷是读代码得出的，没有在旧代码上复现。

**回来后建议先看**

1. **2.8 的行为变化表。** 其中三条升级时会直接碰到：串口参数现在生效（第 1 条）、模组里的旧短信会被读入并通知（第 2 条）、每分钟的 `AT+CPIN?` 不再唤醒 VoWiFi 恢复（第 3 条）。
2. **PushPlus 的成功码**（2.5）。这是凭记忆写的，是本次改动里把握最小的一处，有真实 token 时先验证。
3. **5.1 的 P0 清单**，11 项，合并前在实物上过一遍。
4. **1.5 的 G 组**：发现了但没有改的 8 个问题，原因在 3.5。其中 G8 是收尾时才发现的：仓库内 sipgo fork 自带的测试不在 CI 里，跑了一下有 2 个失败（基线状态，与本次改动无关）。

**没有做的**

- 没有写 ePDG / IMS 核心网模拟器，完整的 VoWiFi 拉起没有端到端仿真（见 4.1）。
- 前端没有改，新增的 `config_issues` 等信息控制台还没有展示。
- 没有逐个提交验证可构建性，没有测量覆盖率和性能。

---

## 1. 项目原貌与深度诊断总结

### 1.1 项目是什么

Shannon IMS 是一个运行在 Linux（含 WSL2）上的蜂窝模组管理平台，把模组控制、SIM 鉴权、SWu 隧道、IMS 注册、IMS 短信和 Web 控制台放在同一个进程里，目标是在宽带网络上建立一条可观察、可恢复的 Wi‑Fi Calling（VoWiFi）链路。

| 项 | 内容 |
|---|---|
| 语言与模块 | Go 1.26。CI 构建和测试的是三个 Go 模块：根模块 `github.com/1239t/vohive`、`vowifi-go`（VoWiFi 运行时）、`third_party/swu-go`（IKEv2/IPsec/SWu）。仓库里还有一份 sipgo 的 fork（`third_party/sipgo`），是独立的模块，由前两个模块通过 `replace` 引用；它自带的测试不在 CI 的范围内 |
| 前端 | `web/`，Vue 3 + TypeScript（36 个 `.vue`），构建产物嵌入根模块（`internal/web`） |
| 入口 | `cmd/vohive`（主程序）、`cmd/vohive-relay`（UDP 中继工具）、`cmd/mbimprobe` |
| 主要依赖 | gin（HTTP API）、gorm + SQLite、viper（配置）、zap（日志）、go.bug.st/serial（串口）、quectel-qmi-go、euicc-go（eSIM）、sipgo（仓库内有一份 fork）、Telegram / QQ / 飞书 SDK |
| 代码规模（基线） | 1215 个受管文件。三个模块合计：Go 非测试代码 474 个文件约 11.2 万行；测试 404 个文件约 7.6 万行、2099 个测试函数。sipgo fork 另有 49 个非测试文件约 1.3 万行、24 个测试文件，本次没有改动，下文的统计都不含它 |
| CI | `.github/workflows/ci.yml`：前端（lint / typecheck / test / build）、三模块 `go test` + `go vet`、三组竞态测试、隐私扫描与脚本测试、发布包冒烟构建 |

目录职责（只列与本次工作相关的）：

| 目录 | 职责 |
|---|---|
| `internal/modem` | AT 管理器：串口、命令队列、主动上报（URC）、短信收发的 AT 侧 |
| `internal/backend` | AT / QMI / MBIM 三种后端的统一接口 |
| `internal/device` | 设备池（Pool / Worker）：发现、健康检查、恢复、VoWiFi 启停编排、短信流水线 |
| `internal/upstreamproxy` | 上游 SOCKS5 代理：探测、UDP 中继、按国家选择代理的规则表 |
| `vowifi-go/runtimehost` | VoWiFi 运行时：ePDG 候选、SWu 传输适配、IMS 注册与短信 |
| `third_party/swu-go` | IKEv2 / ESP / SWu 会话 |
| `internal/config` | YAML 配置的加载、迁移、持久化 |
| `internal/db` | SQLite 数据层 |
| `internal/notify` | 通知渠道（Telegram、Bark、Webhook、邮件、PushPlus、飞书、QQ）与机器人指令 |
| `internal/api` | HTTP API 与 OpenAPI 描述 |
| `pkg/smscodec` | 短信 PDU 编解码 |

### 1.2 核心业务流

1. **设备接入**：设备池按配置打开模组（AT 串口、QMI 或 MBIM），读取模组与 SIM 身份，启动健康检查和短信读取。
2. **VoWiFi 启动**：按 SIM 的归属网络选择是否经上游代理 → 探测代理 → 解析 ePDG 域名 → 建立 SWu 隧道（IKEv2 + ESP，用 SIM 做 EAP-AKA）→ 在隧道内完成 IMS 注册。
3. **短信**：VoWiFi 会话在线时走 SMS over IMS，否则走模组；收到的短信写入历史并推送到通知渠道。
4. **管理**：Web 控制台与 HTTP API 修改设备、代理、通知等配置并写回 YAML；机器人指令可以发短信。

### 1.3 数据模型与外部依赖

- **SQLite 表**（`internal/db`，gorm 自动迁移）：`Device`、`CardPolicy`、`SIMCard`、`SIMSubscription`、`PendingPhoneNumber`、`ProxyInstance`、`UpstreamProxy`、`UpstreamProxyCountryRule`、`SMS`、`SMSContact`、`SMSDelivery`、`SMSDeliveryPart`、`SMSIncomingPartJournal`、`TrafficMinute` 等。
- **配置文件**：一份 YAML（示例见 `config/config.example.yaml`），控制台的修改直接写回这份文件。
- **外部依赖（全部是实物或外部服务）**：蜂窝模组与 SIM、运营商 ePDG 与 IMS 网络、上游 SOCKS5 代理、DNS、MCC/MNC 表的下载源、各通知服务、strongSwan 插件。本次工作现场一样都没有，全部用软件替身验证（见第 4 节）。

### 1.4 原有工程的长处

诊断前先说明：这不是一个质量差的仓库。基线已有 2099 个测试函数、带竞态检测的 CI、隐私扫描脚本、运行时日志脱敏，以及明确的“兼容契约”（协议线上行为不得改变）。本次所有改动都遵守该契约：REGISTER、SWu 候选顺序与预算、IKE/ESP 报文、受保护的 SIP 传输、短信/USSD 呈现均未改动。

项目自身的 Go 代码里只有 1 处 `TODO` 标记（其余 91 处都在仓库内的 sipgo fork 里），所以下面的问题基本不是靠搜标记找到的，而是读代码、写测试时发现的。

### 1.5 诊断发现

下表“依据”一列说明结论是怎么得来的：**运行** = 有测试在旧代码上实际跑出了该现象；**读码** = 只是读代码得出，没有在旧代码上运行复现。

#### A. 会丢数据或丢设置的缺陷

| # | 现象 | 位置 | 依据 |
|---|---|---|---|
| A1 | 配置文件的多个写入方各用各的锁（或没有锁），又共用同一个临时文件名；两次并发保存可能互相覆盖对方的配置段 | `internal/config` | 读码 |
| A2 | 三项设置重启后丢失：邮件的 `use_ssl`、手动选网的三个字段；在控制台编辑设备会抹掉它的串口参数和选网设置 | `internal/config`、`internal/api` | 读码 |
| A3 | 模组里的短信是“解码、推送、删除”一次做完：写历史失败也照样删除；长短信的分片只存在内存里，两片之间重启就丢 | `internal/device`、`internal/modem` | 读码 |
| A4 | AT 模式从不读取模组里已存的短信，程序没运行时到达的短信不会被取走 | `internal/device` | 读码 |
| A5 | `internal/sms` 里有一个没人调用的轮询器，一旦被启用会每 10 秒用 `AT+CMGD=1,4` 删光模组里的全部短信，且不写历史 | `internal/sms/poller.go` | 读码 |

#### B. 让 VoWiFi 在有代理时起不来或撑不住的缺陷

| # | 现象 | 位置 | 依据 |
|---|---|---|---|
| B1 | SOCKS5 握手有三份各自为政的实现（隧道传输、启动探测、中继工具），行为不一致：代理可能通过探测却在实际使用时失败，或反过来 | `vowifi-go/runtimehost/transport`、`internal/upstreamproxy` | 读码 |
| B2 | 代理的控制连接一旦闪断，隧道就结束，没有重建 UDP 关联 | `vowifi-go/runtimehost/transport` | 读码 |
| B3 | 传输适配层：没有 `Start` 就 `Stop` 会永远阻塞；500→4500 端口切换时原地改地址，与发送方有数据竞争；中继挂掉只表现为“没声音” | `vowifi-go/runtimehost/swu_transport.go` | 读码 |
| B4 | 中继重建后出口地址变了，ePDG 仍把下行发往旧地址；没有上行流量时（待机等电话或短信）隧道要到下一个 DPD 周期才恢复 | `third_party/swu-go/pkg/swu` | 读码 |
| B5 | 启动前的代理探测只试一次：代理正在重启或丢了一个连接，整次 VoWiFi 启动就失败 | `internal/upstreamproxy` | 读码 |
| B6 | 按国家选代理的 MCC/MNC 表只能靠下载得到：离线或网络受限时表为空，规则全部不命中，会话悄悄改为直连（只有启动时一条警告）；启动还要为 5 个下载源各等最多 10 秒 | `internal/upstreamproxy/country_table.go` | 读码 |
| B7 | 多国共用的 MCC 被归给“表里最后一行”的国家，结果随数据源行序变化 | 同上 | 读码 |
| B8 | ePDG 域名解析在使用代理之前进行：异地网络的本地 DNS 解析不了运营商域名时，启动在 DNS 这一步就结束了，代理根本没用上 | `vowifi-go/runtimehost/swu_candidates.go` | 读码 |

#### C. 短信收发的不一致

| # | 现象 | 位置 | 依据 |
|---|---|---|---|
| C1 | AT、QMI、MBIM、IMS 四条发送路径各自组 PDU、各自加封装；号码只做了去空格 | `internal/backend`、`internal/modem`、`internal/device` | 读码 |
| C2 | 超过 255 片的长文本会让分片计数回绕（计数只有一个字节） | `pkg/smscodec` | 读码 |
| C3 | 发短信有三个入口（Web API、一个没有路由的 VoWiFi 处理函数、机器人 `/send`），行为已经漂移：机器人不记录失败；Web API 对模组发送一律报“1 片”；无效号码返回 HTTP 500 并在历史里留一条发往该号码的失败记录 | `internal/api`、`internal/notify`、`internal/device` | 读码 |
| C4 | `ATBackend.ListSMS` 返回的是列表中的序号而不是存储索引 | `internal/backend/at_backend.go` | 读码 |

#### D. 串口与 AT 层

| # | 现象 | 位置 | 依据 |
|---|---|---|---|
| D1 | 设备配置里的波特率、数据位、停止位、校验位从未生效，端口一律按 115200 打开 | `internal/modem` | 读码 |
| D2 | 读线程报错时，管理器只认 4 种错误文本；串口库在设备拔出时报的是另一种文本，于是管理器没有读线程也继续“运行”，要等后续命令逐个超时才开始恢复 | `internal/modem/manager.go` | 读码（新代码有测试，旧代码没有对照运行） |
| D3 | 查询命令的应答被当成主动上报：设备池每分钟一次的 `AT+CPIN?` 应答都被当作“模组刚就绪”，每分钟打两条 info 日志并唤醒一次 VoWiFi 恢复；`AT+QSIMSTAT?` 的应答被吞掉，调用方从未收到 | `internal/modem/manager.go` | 运行（3 个测试在旧代码上失败） |
| D4 | 停止管理器要等当前命令超时；交互式命令第二段写失败被忽略；端口忙时的重试靠匹配一段串口库并不会给出的文本；手动 AT 会话在模组拒绝命令时只报“timeout” | `internal/modem` | 读码为主，部分有测试 |

#### E. 通知渠道：凭据外泄与无限等待

| # | 现象 | 位置 | 依据 |
|---|---|---|---|
| E1 | Bark 的设备密钥、Webhook 地址里的密钥、Telegram 的 bot token 会随失败请求的 URL 写进日志和错误信息；Telegram 代理地址连用户名密码一起写进日志；Telegram 库把带 token 的轮询失败信息打到标准错误 | `internal/notify` | 运行（对照运行，见 4.6） |
| E2 | PushPlus 用明文 HTTP 发送，账号 token 在请求正文里 | `internal/notify/pushplus.go` | 读码 |
| E3 | 邮件两条投递路径都没有时限：邮件服务器接了连接不说话，投递一直等；而重新加载通知设置要等在途投递结束，于是设置页也一起卡住 | `internal/notify/email.go` | 运行（40 秒后仍在等） |
| E4 | PushPlus、飞书的请求没有时限；PushPlus 只看 HTTP 状态码，而该服务拒绝请求时也返回 HTTP 200 | `internal/notify` | 读码；“拒绝也返回 200”是实测：不带 token 向该服务的 HTTPS 接口发请求，得到 HTTP 200，正文里 `code` 为 999 |
| E5 | 邮件：不开 SSL 时，遇到不提供认证的服务器（如本地中继）直接报错；主题和正文按 8 位原样发送；事件名或设备名里的换行可以注入邮件头 | `internal/notify/email.go` | 读码 |

#### F. 校验、可观测性与死代码

| # | 现象 | 位置 | 依据 |
|---|---|---|---|
| F1 | 配置加载没有校验；`device_backend` 写错会被静默当作 AT 运行 | `internal/config`、`internal/backend/factory.go` | 读码 |
| F2 | 中继状态、探测失败的原因只能靠错误字符串匹配来判断，日志里分不清“密码错”“代理不可达”“代理不支持 UDP” | `internal/upstreamproxy` | 读码 |
| F3 | 没人调用的代码：`internal/sms` 轮询器、`URCListener`、无路由的 VoWiFi 发短信处理函数及其包装 | 多处 | 读码 |

#### G. 发现了但没有改的（原因见 3.5，建议见 5.3）

| # | 现象 | 位置 |
|---|---|---|
| G1 | 设备池的关闭不等待它为每个设备启动的后台协程，也不停止 AT 管理器；AT 查询不可取消 | `internal/device/pool.go`、`pool_bootstrap.go` |
| G2 | 任务池里的任务如果 panic，没有 `recover`，会带崩整个进程 | `pkg/taskpool/taskpool.go` |
| G3 | 设置接口对共享配置对象 `s.fullCfg` 有 47 处引用，文件内没有任何加锁；并发修改设置有可能互相覆盖内存中的值（写文件本身已在本次改为串行）。是否真的会出问题没有验证过 | `internal/api/settings.go` |
| G4 | SIM 状态事件的处理函数只在 `startAllSynchronousLegacy` 里绑定，而这个函数没有任何调用方：等于 AT 模式下“拔卡 → 停止 VoWiFi”这条线没有接上 | `internal/device/pool.go` |
| G5 | `handleVoWiFiSMSStatus` 有实现但没有路由 | `internal/api/server.go` |
| G6 | IPv6 地址范围转 CIDR 只支持全网段或单个地址（项目里唯一的 `TODO`） | `third_party/swu-go/pkg/swu/session.go` |
| G7 | 调试日志把 `+CRSM` 的应答行记成“未分类 URC”（只影响日志，测试时观察到） | `internal/modem/manager.go` |
| G8 | 仓库内的 sipgo fork 自带的测试不在 CI 里，按现状也跑不通。收尾时实际运行过；fork 本次没有改动，所以这是基线状态。① 根包的测试（30 个函数）要先用 `testdata/generate_certs.sh` 生成证书才能编译，`go vet` 也因此失败；② `sip` 包 50 个测试里有 2 个失败：`TestTransportLayerClosing/UDP` 每次都失败（测试期望重复关闭 UDP 传输时报错，实际没有报错）；`TestTransportLayerClientConnectionNoReuse/WithClientHostPort` 单独跑通过，跟在其他测试后面跑时因 `127.0.0.1:12345` 仍被占用而失败（运行前该端口空闲，是同一进程里前面的测试留下的） | `third_party/sipgo` |

---

## 2. 本次改动详单（Changelog）

代码改动共 17 个提交：121 个文件，+23339 / −2372 行。Go 非测试代码净增约 7,000 行，测试代码净增约 13,900 行，测试函数从 2099 个增至 2435 个（按 CI 覆盖的三个模块统计）。此外有两个收尾提交（验证脚本、本报告）。前端 `web/` 没有改动。

下面按模块说明，每条标明类型（**修复** / **重构** / **新增** / **清理**）。每个提交的完整文件清单在附录 A，由 git 记录生成。

### 2.1 代理链路与 VoWiFi 协同（指定的核心方向 ①）

目标是三件事：导入代理后 VoWiFi **起得来**（探测、选代理、解析 ePDG 不因一次抖动而失败）、**撑得住**（代理闪断后自动恢复）、出问题时**说得清**（失败有类型、有日志、有计数）。报文在线上的格式、SWu 候选的顺序与预算都没有改。

#### 2.1.1 一份共享的 SOCKS5 实现（`3f627c5`）

文件：`vowifi-go/runtimehost/transport/socks5.go`、`socks5_udp.go`、`transport.go`

- **重构**：隧道传输、启动探测、中继工具原来各有一份握手代码，现在共用这一份。
- **握手适配**：配了账号时只提供“用户名/密码”认证；代理答复“没有可接受的认证方式”时，不带认证再试一次，适配按来源地址放行、不认账号的代理。
- **中继地址适配**：代理在 UDP ASSOCIATE 应答里给的中继地址经常不能直接用。现在的规则：

  | 代理给出的地址 | 处理 |
  |---|---|
  | `0.0.0.0` 或 `::` | 改用控制连接实际连到的代理地址 |
  | 回环地址，而代理不在本机 | 同上 |
  | 域名 | 解析；解析不出来就用代理地址 |
  | 内网地址，而代理是公网地址 | 照用，但打标记，供日志和探测结果提示 |
  | 端口为 0 或主机为空 | 按“应答格式错误”失败 |

- **失败有类型**：`Socks5Error` 带阶段、原因和代理应答码，调用方不再靠匹配错误字符串来判断。
- **UDP 关联自愈**（`socks5_udp.go`）：关联在第一次需要时建立；控制连接断开后自动重建，连续失败 5 次才放弃，间隔从 500 ms 翻倍到 8 s；存活不到 2 s 的关联按失败计，防止“接受后立刻断开”的代理引发重连风暴；状态变化有事件回调，收发与丢弃有计数；格式不对的中继报文直接丢弃。

#### 2.1.2 隧道在代理闪断后恢复（`ef278ad`、`b8a7bfc`）

文件：`vowifi-go/runtimehost/swu_transport.go`；`third_party/swu-go/pkg/ipsec/icmp_err.go`、`third_party/swu-go/pkg/swu/session.go`

- **修复**：没有 `Start` 就 `Stop` 不再永远阻塞。
- **修复**：500→4500 端口切换时，对端地址改为原子替换，消除与发送方的数据竞争。
- **新增**：中继彻底放弃时向会话报告 `EventNetworkDown`，不再只是没有数据；中继重建成功时报告新事件 `EventPathChanged`。
- **新增**（swu-go）：会话收到 `EventPathChanged` 后立即发一次普通 DPD，不等下一个 DPD 周期。用意是让 ePDG 尽快从新的出口地址收到一个通过校验的报文，把下行改发到新地址。**真实 ePDG 是否据此更新地址，只能实物验证**（见 5.1）。
- **可观测性**：中继状态变化带阶段和原因写日志（不写错误原文，因为里面有地址）；丢弃的报文有计数。

#### 2.1.3 启动探测与中继工具（`8ca3952`、`542baf8`）

文件：`internal/upstreamproxy/probe.go`、`probe_retry.go`（新）、`udprelay.go`、`cmd/vohive-relay/main.go`

- **重构**：探测和中继工具改用共享实现，“探测通过”和“实际能用”从此是同一套逻辑。
- **新增**：探测结果增加代理宣告的中继地址、改写后的地址、账号是否被代理忽略、警告列表；诊断结论从类型化的失败得出。
- **新增**：探测整体有时限，为单步超时的 2 倍。
- **新增**：`ProbeSOCKS5WithRetry`，12 秒内最多 3 次，间隔从 500 ms 翻倍。只对瞬时失败重试（代理不可达、读写错误或超时、对端关闭连接、应答码 0x01）；明确的答复（如认证失败、不支持 UDP）不重试。
- **修复**：中继工具在关联断开后自动重建（有界）；建不起来时带原因停止，进程以非零码退出；增加计数器。

#### 2.1.4 按归属网络选择代理（`5806dfd`）

文件：`internal/upstreamproxy/country_builtin.go`（新）、`country_table.go`、`cmd/vohive/country_table.go`（新）、`cmd/vohive/main.go`、`internal/db/upstream_proxy.go`、`internal/device/vowifi_proxy_probe.go`（新）、`internal/device/vowifi_start_orchestrator.go`

- **新增**：内置一份 ITU E.212 国家表（237 个 MCC）作兜底，由主程序显式启用。在线表下载不到时规则仍然能命中，会话不再悄悄变成直连。
- **修复**：启动时等待在线表最多 8 秒，之后在后台刷新（启动后 1、5、30 分钟各一次，此后每 6 小时）。
- **修复**：多国共用的 MCC 归给该 MCC 下网络数最多的国家，结果不再随数据源的行序变化；归属判断细化到 MCC+MNC（`GetHomeNetworkUpstreamProxy(mcc, mnc)`）。
- **修复**：缓存文件用唯一临时文件加 rename 写入，大小上限 16 MiB。
- **新增**：VoWiFi 启动按 SIM 的 MCC+MNC 选择代理，并使用带重试的探测。
- **已知取舍**：只有内置表可用时（它只到 MCC 一级），给共用 MCC 上某个属地配的规则，在主国家没有自己规则的情况下，也会匹配主国家的 SIM。

#### 2.1.5 ePDG 域名经代理解析（`dba2287`）

文件：`vowifi-go/runtimehost/epdg_dns.go`（新）、`epdg_proxy_resolver.go`（新）、`swu_candidates.go`

- **新增**：先用本机 DNS，且本机结果始终优先。只有在会话走代理、并且本机解析失败或 2 秒没有回答时，才通过代理的 UDP 关联向公共解析器查询 A/AAAA 记录。
- 环境变量 `VOHIVE_EPDG_DNS_RESCUE`：填解析器地址（最多 4 个；默认 `1.1.1.1` 和 `8.8.8.8`），或填 `off` / `0` / `false` / `no` / `disabled` 关闭。
- 实现是一个很小的 DNS 桩解析器（EDNS(0) 1232 字节，没有 TCP 回退）。
- **隐私提示**：救援查询会把运营商的 ePDG 域名（含 MCC/MNC，不含用户身份）经代理发给公共解析器。不希望这样就关掉开关。

### 2.2 短信收发通用化（指定的核心方向 ②）

目标：调用方只说“给谁、发什么”，不需要知道底下是 AT、QMI、MBIM 还是 IMS；收到的短信不因为程序重启或数据库暂时写不进去而丢失。

#### 2.2.1 一次准备，四种承载共用（`f3569a8`）

文件：`pkg/smscodec/submission.go`（新）、`pkg/smscodec/pdu.go`、`internal/backend/{sms.go,at_backend.go,qmi_backend.go,mbim_backend_sms.go}`、`internal/modem/manager.go`、`internal/device/vowifi_state_api.go`

- **重构**：`smscodec.PrepareSubmission(to, text, opts)` 一次完成号码校验与规范化、编码选择（文本能用 GSM 7 位就用，否则 UCS-2）和分片，得到一个 `Submission`。各承载从它取自己需要的形态：

  | 方法 | 用途 |
  |---|---|
  | `TPDU(i)` | 第 i 片的 SMS-SUBMIT TPDU |
  | `PDU(i)` | 模组 PDU 模式（3GPP TS 27.005），服务中心地址长度为零，由模组使用 SIM 里存的短信中心 |
  | `ATPDU(i)` | `AT+CMGS` 需要的长度参数和十六进制串 |
  | `RPData(i, …)` | SMS over IMS 的 RP-DATA |

- **新增**：号码可以带常见分隔符和全角数字，会被规范化；含其他字符、或超过 20 位数字的号码被拒绝；超过 255 片的文本被拒绝，不再回绕。
- **新增**：`backend.PreparedSMSSender` 接口与 `SendPreparedSMS`，三种后端都能直接发送准备好的 `Submission`。
- **隐私**：QMI/MBIM 发送日志里的号码改为指纹。

#### 2.2.2 收到的短信先入库、再从模组删除（`9af669c`）

文件：`internal/device/incoming_sms_pipeline.go`（新）、`internal/modem/sms_inbox.go`（新）、`internal/db/sms_incoming.go`、`internal/backend/at_backend.go`、`internal/modem/manager.go`，以及 `internal/device` 下的 `pool_sms.go`、`pool_sms_mbim.go`、`vowifi_incoming_sms.go`、`pool.go`、`pool_bootstrap.go`、`pool_health_ip.go`、`vowifi_start_orchestrator.go`、`vowifi_teardown.go`

- **重构**：IMS 与蜂窝两条接收路径共用 `storeIncomingDeliver`：分片先写入数据库里的接收日志，拼齐后写历史，并且只通知一次。消息 ID 的前缀区分来源：`ims-in-` 与 `cell-in-`。
- **修复**：写入成功之后才从模组删除。暂时写不进去（读不到 SIM 身份，或数据库拒绝）时保留在模组里，下次读取时再试，最长三分钟；三分钟后仍写不进去，就交给原来的内存路径照旧推送并释放模组存储，避免一条反复失败的短信把模组占满。
- **新增**：AT、QMI、MBIM 三种后端都在设备启动 15 秒后读取一次模组里已存的短信，此后每分钟一次（AT 模式以前从不读取）。
- **新增**：接收日志里超过 30 天的行会被清理，最多每六小时清理一次。
- **修复**：`ATBackend.ListSMS` 返回真实的存储索引；AT 管理器增加接收出口和按存储索引删除（`sms_inbox.go`）。

#### 2.2.3 发送的单一入口（`4188d27`）

文件：`internal/device/sms_send.go`（新）、`internal/api/server.go`、`internal/api/openapi.vohive.yaml`、`internal/notify/commands.go`、`internal/device/pool_sms.go`、`internal/device/vowifi_state_api.go`

- **重构**：`Pool.SendSMS` 是唯一入口，Web API 与机器人 `/send` 都走它。请求只有设备、号码、文本和可选的编码；走 IMS 还是走模组只在这里决定一次。
- **修复**：无效请求返回 `ErrSMSRequestInvalid`，不写历史，Web API 回 400（以前是 500 并留下一条失败记录）。凡是到达了某个通道的消息，都留下且只留下一条历史（已发送或失败）。结果里带真实分片数、送达状态和 IMS 消息 ID。
- **修复**：模组发送有 35 秒时限；机器人给 IMS 发送保留 30 秒。
- **清理**：删除没有路由的处理函数及包装（`Pool.SendVoWiFiSMS`、`Pool.SendVoWiFiSMSWithResult`、`Pool.FirstVoWiFiDeviceID`、`Worker.SendSMS`、`Worker.SendSMSWithOptions`）；OpenAPI 的 `/sms/send` 同步更新。

#### 2.2.4 删除危险的死代码（`1664fa8`）

- **清理**：删除 `internal/sms/poller.go`（见 1.5 的 A5）；隐私检查脚本里的文件清单相应更新（`scripts/check-repository-privacy.py` 及其测试）。

### 2.3 配置管理（`51b1fae`）

文件：`internal/config/` 下的 `filestore.go`（新）、`validate.go`（新）、`config.go`、`manager.go`、`persist.go`、`persist_devices.go`、`persist_proxy.go`、`network_migration.go`、`path_field_migration.go`；`internal/api/server.go`、`internal/api/device_mgmt.go`；`internal/backend/factory.go`；`config/config.example.yaml`

- **修复**：所有写配置文件的路径共用一把锁，写入是原子的：唯一临时文件、权限 0600、fsync、rename、再 fsync 目录。
- **修复**：保存通知设置和 Web 登录凭据后，内存中的配置同步刷新。
- **修复**：`proxy:` 段为空（null）时，新增的代理实例不再被吞掉。
- **修复**：1.5 的 A2 三项（`email.use_ssl`、三个 `operator_selection_*` 字段、控制台编辑设备抹掉串口参数和选网设置）。
- **新增**：`config.Validate` 逐字段检查，给出带路径的结论。只有 `server.port` 不可用会阻止启动，其余是警告，并说明实际会按什么值运行。结果在启动时记录一次，并通过 `GET /api/system/info` 的 `config_issues` 字段给出；提示信息里不含任何密钥。
- **修复**：`device_backend` 的校验原来先做规范化（未知值已被折叠成 `at`），所以从不报错。现在通过 API 保存时会拒绝写错的值；加载已有配置时给出警告并仍按 `at` 运行，以兼容已部署的配置。
- **重构**：`Load` 使用私有的解析器实例；`DeviceConfig.SerialSettings()` 给出生效的串口参数。

### 2.4 串口与 AT 层（`5197422`、`2b10aa5`）

文件：`internal/modem/` 下的 `manager.go`、`serial_open.go`（新）、`serial_at.go`、`imei_probe.go`、`at_parse.go`、`commands.go`；`internal/backend/info.go`；`internal/api/device_mgmt.go`；删除 `internal/modem/urc_listener.go`

- **修复**：设备配置里的 `baud_rate`、`data_bits`、`stop_bits`、`parity` 现在对 AT 管理器和手动 AT 会话生效（IMEI 探测仍用 115200 8N1）。没有设置或取值不支持时用 115200 8N1。
- **修复**：读线程放弃时，管理器立即停止并报告断开，不再依赖匹配 4 种错误文本。
- **修复**：`Stop` 立刻结束主循环；交互式命令第二段写失败时立即失败；端口被占用时的重试判断修正。
- **修复**：手动 AT 会话把 `+CME ERROR` / `+CMS ERROR` 应答原样返回，端口出错时停止；初始化失败会写日志；分片清理的定时器在停止时关闭。
- **重构**：串口只通过一个函数打开，并带一个虚拟端口注册表（`modem.RegisterVirtualSerialPort`），测试用它接入模拟模组。产品代码里没有任何地方注册虚拟端口。
- **修复**（`2b10aa5`）：查询命令和测试命令（`AT+X?`、`AT+X=?`）的应答不再被当成主动上报分发。每分钟一次的 `AT+CPIN?` 不再产生两条 info 日志，也不再每分钟唤醒一次 VoWiFi 恢复。SIM 就绪状态如果在两次应答之间变了，只报告一次。
- **清理**：`QuerySIMInserted` 不再发送 `AT+QSIMSTAT?`。它的应答一直被剔除，真正起作用的始终是 `AT+CPIN?`，所以判定结果不变。删除 `parseQSIMSTATInserted` 和没人使用的 `URCListener`。

### 2.5 通知渠道（`2afd7b0`）

文件：`internal/notify/`，15 个文件，清单见附录 A

- **修复（凭据不外泄）**：Bark、Webhook 的日志和错误只显示协议和主机（`FailedURLs` 仍保留完整地址供调用方使用）。Telegram 的 token 和代理账号不再出现在错误、日志和库的报告里；库的报告仍然输出到标准错误。
- **修复**：PushPlus 改用 HTTPS。
- **修复（时限）**：邮件只保留一条投递路径，连接 10 秒、整体 30 秒；PushPlus 15 秒；飞书每个 API 请求 15 秒；QQ 与 Webhook 原有的时限不变。
- **修复（邮件）**：只有配置了用户名且服务器提供认证时才认证；服务器只提供 LOGIN 不提供 PLAIN 时用 LOGIN（密码只在加密连接上、只交给配置的那台服务器）；发件人可以写成 `名称 <地址>`；主题按 RFC 2047 编码，正文用 base64；事件名和设备名不能再注入邮件头。
- **修复（PushPlus 结果判定）**：按响应正文里的 `code` 判定成败，不再只看 HTTP 状态。**注意**：把 200 当作成功码，是凭对该服务文档的记忆写的，没有用真实账号验证过（见 5.2）。
- **清理**：邮件与 PushPlus 不再自己记录失败日志，由管理器统一记录每个渠道的失败，避免重复。

### 2.6 仿真层与新增测试

| 提交 | 内容 | 位置 |
|---|---|---|
| `3f627c5` | SOCKS5 代理模拟器与可编排的 UDP 对端 | `vowifi-go/runtimehost/transport/socks5sim/` |
| `9af669c` | 短信 PDU 生成器 | `internal/simulation/smssim/` |
| `fd86ce3` | 软件蜂窝模组 | `internal/simulation/atsim/` |
| `2b10aa5` | 管理器级测试 18 个、设备池级端到端测试 11 个 | `internal/modem/simulated_modem_test.go`、`internal/device/simulated_modem_e2e_test.go` |
| `2afd7b0` | 可编排的 SMTP 服务器，Telegram、PushPlus、飞书等服务的本地替身 | `internal/notify/` 的测试文件 |
| `d7b30d8` | 端到端测试夹具等设备池的协程全部退出后才关闭数据库 | `internal/device/simulated_modem_e2e_test.go` |

细节在第 4 节。

### 2.7 工程脚本（收尾提交）

- **新增** `scripts/verify-local.sh`：一条命令跑完 CI 的全部检查，另加对仿真器和代理相关包的竞态测试。没有改 `.github/workflows/ci.yml`。这个脚本不会进入发布包（打包脚本按固定清单拷贝）。
- **新增** `HANDOVER_REPORT.md`：本报告。

### 2.8 行为变化一览（合并或升级前请看）

| # | 变化 | 需要注意什么 |
|---|---|---|
| 1 | 串口参数现在生效 | 如果某个设备条目写了与模组实际不符的 `baud_rate` 等参数，以前因为被忽略而能用，现在会按配置打开而连不上。升级前检查各设备条目；拿不准就删掉这几个字段（默认 115200 8N1） |
| 2 | 模组里已存的短信会被读入 | AT 模式以前不读取。升级后第一次启动，模组或 SIM 里积存的旧短信会被写入历史、触发通知，然后从模组删除，可能一次收到一批通知 |
| 3 | 每分钟的 `AT+CPIN?` 不再唤醒 VoWiFi 恢复 | 这是修掉了一个副作用。需要在实物上确认：会话掉线后，正常的恢复机制仍能把它拉起来，没有哪条恢复路径实际上靠的是这个副作用（见 5.1） |
| 4 | `POST /sms/send` 对无效请求回 400 | 以前是 500。依赖 500 的调用方需要调整 |
| 5 | 号码校验变严 | 含字母等字符或超过 20 位数字的号码现在会被拒绝 |
| 6 | 接收短信的消息 ID 前缀按来源区分 | 模组为 `cell-in-`，IMS 为 `ims-in-` |
| 7 | 默认开启 ePDG DNS 救援 | 会话走代理且本机解析失败时，会经代理向公共解析器查询运营商域名。可用 `VOHIVE_EPDG_DNS_RESCUE=off` 关闭 |
| 8 | 国家代理规则离线也生效 | 以前下载不到表时等于直连，现在会按内置表命中规则并走代理。共用 MCC 的取舍见 2.1.4 |
| 9 | 配置校验 | 启动日志多一段检查结果；不可用的 `server.port` 在启动时就被拒绝；`GET /api/system/info` 多了 `config_issues` 字段；通过 API 保存写错的 `device_backend` 会被拒绝 |
| 10 | 通知日志不再有完整地址 | Bark、Webhook 的日志只有协议和主机 |
| 11 | PushPlus 走 HTTPS 并按 `code` 判定 | 部署网络要能访问它的 HTTPS 地址；成功码未经真实验证，若实际不是 200，已送达的消息会被记成失败 |
| 12 | 邮件认证按服务器能力决定 | 不提供认证的服务器不再报错，改为不认证直接投递；没配用户名时不认证 |
| 13 | `vohive-relay` 的退出码 | 关联建不起来时以非零码退出，外部的守护脚本可能据此重启它 |

---

## 3. 自主决策说明

按要求，整个过程没有停下来提问。下面是需要取舍的地方、我的选择和理由。每一条都可以推翻；“代价/风险”一列说明推翻时要动什么。

### 3.1 范围与工作方式

| 决策 | 选择 | 理由 | 代价/风险 |
|---|---|---|---|
| 协议行为 | 不改任何线上行为，遵守仓库的兼容契约 | 没有实物网络可以验证，改协议行为的风险无法用仿真排除 | 一些改进（如 MOBIKE）没有做 |
| 改动重心 | 优先你指定的两条链路，其次是会丢数据、泄露凭据、无限等待的缺陷 | 这几类问题后果最重，而且能用仿真验证 | 1.5 的 G 组没有改 |
| 前端 | 不改 | 体检发现的问题都在后端；前端有自己的 lint、类型检查和 66 个测试，都通过 | 新增的 `config_issues` 字段和探测结果的新字段，控制台还没有展示 |
| 上游代码格式 | 不对未经 gofmt 的既有文件做批量格式化 | 会产生大量与功能无关的差异，妨碍审阅 | 这些文件仍然没有格式化 |
| 工具链放在哪 | Go 1.26.3 与 Node 22 都装在项目内的 `.sandbox/`（已被 git 忽略），在本机已有的 Linux 子系统里运行 | 项目只支持 Linux，而红线要求不动工作目录以外的任何东西。你回来后说可以随意安装，我仍然沿用这个做法，因为它已经能用，而且删掉目录就能完全还原 | `.sandbox/` 占用磁盘，不需要时可整个删除 |
| 版本留存 | 按模块本地提交，不推送 | 按你的要求 | 无 |
| 提交的可构建性 | 每个提交前跑相关包的测试，关键节点和最后跑全量 | 完整检查一次约 25 分钟，只跑 Go 部分也要将近 10 分钟，逐个提交都跑不现实 | 没有逐个提交验证“单独检出该提交时全量通过”，用 `git bisect` 时中间提交可能有不过的测试 |
| 并行协作 | 没有使用，全程串行 | 没有可用的方式启动辅助进程 | 耗时更长 |

### 3.2 代理与 VoWiFi

| 决策 | 选择 | 理由 | 代价/风险 |
|---|---|---|---|
| 认证协商 | 配了账号就先只提供账号认证，被拒后无认证重试一次 | 如果同时提供“无认证”，代理可以选它，账号就悄悄没用上；先只提供账号认证，支持它的代理就一定会认证。不支持账号认证的代理再退回无认证，否则连不上 | 遇到这类代理多一次连接；账号被忽略会在探测结果里标出 |
| 中继地址 | 按 2.1.1 的表改写；内网地址只标记不改写 | 前几种情况下宣告的地址肯定发不到；内网地址在部分组网里是正确的，不能替用户做主 | 内网地址确实发不到时，只能靠日志和探测警告发现 |
| 关联重建 | 有界：5 次，退避 500 ms 至 8 s，存活不足 2 s 算失败 | 无限重试会掩盖故障并拖住上层的恢复 | 代理长时间不可用时会话会结束，由上层恢复重新发起 |
| 中继放弃 | 报告 `EventNetworkDown` | 让会话走已有的断网处理，而不是等 DPD 超时 | 依赖上层对该事件的已有处理 |
| 路径变化 | 新增 `EventPathChanged`，立即发普通 DPD | 不引入新的协议行为，只是把已有的 DPD 提前 | 真实 ePDG 是否据此更新回程地址未验证 |
| 探测重试 | 只对瞬时失败重试，12 秒内最多 3 次 | 认证失败之类的明确答复，重试也不会变 | 启动最坏多等 12 秒 |
| 内置国家表 | 作为兜底，由主程序显式启用；在线表可用时以在线表为准 | 库的其他使用者和既有测试的行为不变 | 内置表只到 MCC，共用 MCC 有 2.1.4 所说的取舍；表会过时 |
| ePDG DNS 救援 | 默认开启，有环境变量开关；本机结果始终优先 | 不开启的话，异地网络下代理根本用不上，这正是你要解决的场景 | 域名会发给公共解析器；公共解析器解析到的 ePDG 地址可能与运营商内部视图不同 |
| 仿真器监听地址 | 只绑定 127.0.0.1 | 测试不应该在局域网上开端口 | 无 |

### 3.3 短信

| 决策 | 选择 | 理由 | 代价/风险 |
|---|---|---|---|
| 号码规范化 | 去掉分隔符、转换全角数字，保留 `+`；不自动补国际区号 | 国内号码、短号码和没写 `+` 的国际号码无法区分，应由短信中心按自己的拨号方案解释 | 用户仍需自己写对区号 |
| 超长文本 | 超过 255 片直接拒绝 | 分片计数只有一个字节，回绕会发出拼不回来的消息 | 无实际影响，这个长度远超正常使用 |
| 接收的可靠性 | 先入库再删除；写不进去就留在模组里重试，三分钟为限 | 宁可重复处理，不能丢；但模组存储很小，不能让一条写不进去的短信一直占着 | 数据库持续写不进去超过三分钟时，退回原来的内存路径：照旧推送，但这条短信不再有入库保证 |
| 读取已存短信 | 三种后端都读，启动 15 秒后一次、此后每分钟 | 主动上报会丢，程序也会有没在运行的时候；定期读取是兜底 | 每分钟多一组查询；升级后首次启动会读入旧短信（2.8 第 2 条） |
| 接收日志的保留 | 30 天 | 足够覆盖长短信分片间隔和排查需要，又不会无限增长 | 期限目前是常量，没有做成配置项 |
| 发送入口 | 只留 `Pool.SendSMS`，删掉其他入口 | 三个入口的行为已经漂移，留着会继续漂移 | 仓库外若有代码调用被删的方法，需要改为调用 `SendSMS` |
| 无效请求 | 回 400，不写历史 | 这是调用方的错误，不是一次发送失败 | 见 2.8 第 4 条 |
| 无人调用的轮询器 | 删除，而不是修 | 它会删光模组里的短信，而且功能已被新的接收流水线覆盖 | 无 |

### 3.4 配置、串口、通知与测试

| 决策 | 选择 | 理由 | 代价/风险 |
|---|---|---|---|
| 配置校验的严厉程度 | 只有端口不可用才阻止启动，其余只警告 | 已部署的配置里很可能有不规范的值，升级后起不来比带警告运行更糟 | 错误配置仍会运行，需要有人看日志或 `config_issues` |
| 串口参数 | 让配置生效 | 配置项存在却不生效是缺陷 | 见 2.8 第 1 条 |
| 查询应答与主动上报 | 按“当前有没有在等这条查询的应答”区分 | 同一行文本既可能是应答也可能是上报，只看文本分不出来 | 见 2.8 第 3 条 |
| 模拟模组的方言 | 按 Quectel 风格实现 | 代码里的专有命令（`+QCCID`、`+QENG` 等）都是这一家的 | 其他厂商的模组没有覆盖 |
| 模拟模组的独立性 | 不依赖产品的短信编解码 | 如果模拟器和被测代码用同一套编解码，编解码的错误会两边抵消而测不出来 | 模拟器里有少量重复实现 |
| 端到端测试的偶发竞态 | 只改测试夹具：等设备池的协程退出后再关数据库 | 根因是设备池关闭不等待后台协程（1.5 的 G1）。产品从不关闭数据库，所以产品里不出问题；改生产关闭流程要动 AT 查询的取消机制，范围大而且无法实物验证 | G1 仍然存在；每个端到端测试多约 1 秒 |
| 通知的时限 | 给每条投递路径固定上限 | 无限等待会拖住设置页 | 慢网络下可能误报超时；上限是常量 |
| PushPlus 成功码 | 按 200 判定 | 没有账号可以实测，只能按记忆中的文档 | 见 2.8 第 11 条；这是本次改动里把握最小的一处 |
| 通知模块的注释语言 | 产品代码的注释用中文 | 与该模块原有注释一致 | 其他模块里我新写的注释多为英文，风格不完全统一 |
| 一键验证脚本 | 新增脚本，不改 CI 配置 | 仓库里有测试盯着 CI 配置的内容 | 脚本与 CI 配置需要人工保持同步 |

### 3.5 为什么 G 组没有改

| 问题 | 没改的原因 |
|---|---|
| G1 设备池关闭不等待后台协程 | 要改就得给 AT 查询加取消机制，涉及面大，而且关闭流程的改动只有在实物上才能验证。产品从不关闭数据库，所以这个问题目前只在测试里显现；这一点是读 `cmd/vohive/main.go` 得出的 |
| G2 任务池没有 `recover`、G3 设置接口没有加锁 | 不难改。我把它们排在两条主线、全量验证和本报告之后，最终没有做。G3 是否真的会出问题也还没有验证 |
| G4 拔卡后停止 VoWiFi 没有接线、G5 处理函数没有路由 | 需要你判断是有意为之还是遗漏。接上 G4 会改变真实设备上的运行行为，没有实物我不敢替你决定 |
| G6 IPv6 范围转 CIDR | 只在运营商下发 IPv6 范围时才有影响，没有网络无法验证改得对不对 |
| G7 日志分类 | 只影响调试日志 |
| G8 sipgo fork 的测试 | 收尾核对统计数字时才发现它的测试不在 CI 里。这是第三方代码的 fork，SIP 传输又在兼容契约的范围内，所以只运行并记录了现状，没有分析这两个失败对产品有没有影响，也没有改它 |

---

## 4. 无实物仿真测试报告

### 4.1 结论与边界

现场没有模组、SIM、代理、运营商网络和通知服务，全部验证都在软件替身上完成。最终的完整运行结果见 4.5。

仿真能证明的是：在我对设备和协议的理解之下，代码按设计工作。它不能证明这个理解与真实设备一致，这部分列在第 5 节。另有两条边界需要先说清：

- **没有 ePDG / IMS 核心网的模拟器。** IKEv2、ESP、IMS 注册这些协议层本次没有改动，它们依赖三个模块里原有的测试（本次全部通过）；SIP 底层用的 sipgo fork 自带的测试不在其中（见 1.5 的 G8）。新写的仿真覆盖到“数据报经代理到达对端并返回”“中继断开后重建并通知会话”这一层，没有覆盖“经代理与一个 ePDG 完成完整握手”。
- **模拟模组不模拟卡应用。** `+CSIM`、`+CGLA`、`+CCHO`、`+CCHC` 一律回 `ERROR`，所以 SIM 鉴权（EAP-AKA、IMS-AKA）没有经过模拟模组验证。

### 4.2 仿真层是怎么构造的

| 被替代的实物或外部服务 | 替身 | 位置 | 能模拟什么 |
|---|---|---|---|
| 蜂窝模组（AT 串口） | 软件模组 `atsim` | `internal/simulation/atsim/` | 身份与 SIM（`+CGSN`、`+CIMI`、`+QCCID`、`+CPIN`、`+CRSM`）、网络（`+CREG`、`+COPS`、`+CSQ`、`+CGDCONT`、`+QENG`、`+QNWINFO`、`+QIMS`）、PDU 模式短信（`+CSCA`、`+CPMS`、`+CNMI`、`+CMGL`、`+CMGR`、`+CMGD`、带提示符的 `+CMGS`）、USSD（`+CUSD`）、通话（`ATD` / `ATA` / `ATH`）。测试可以驱动它：投递或存入短信、改注册状态和信号、拔插 SIM、来电、发主动上报、拔出和插回设备、重启、让某条命令变慢、不回答或回指定内容 |
| 串口 | 虚拟端口注册表 | `internal/modem/serial_open.go` | 产品代码按端口名打开串口时，测试注册过的名字会接到 `atsim` 上。AT 管理器和设备池走的是与真实串口相同的代码路径 |
| 短信网络（下行） | PDU 生成器 `smssim` | `internal/simulation/smssim/` | 生成 SMS-DELIVER PDU，包括拆成多片的长短信。独立实现，不使用产品的编解码，避免两边的错误互相抵消 |
| 上游 SOCKS5 代理 | `socks5sim` 服务器 | `vowifi-go/runtimehost/transport/socks5sim/server.go` | 回环上的 SOCKS5，支持 CONNECT 和 UDP ASSOCIATE，认证方式可选无认证、账号认证或两者皆可。故障注入：握手停住或直接关闭、丢弃接下来的 N 个连接、错误的协议版本、应答延迟或逐字节发送、拒绝请求、各种中继地址宣告方式（真实地址、未指定地址、域名、端口 0）、关联过期、报文丢失、延迟、乱序、重复 |
| 代理后面的对端 | 可编排的 UDP 对端 | `vowifi-go/runtimehost/transport/socks5sim/peer.go` | 按脚本应答数据报。ePDG DNS 测试用它扮演公共解析器 |
| MCC/MNC 表的下载源 | 本地 HTTP 服务器 | `internal/upstreamproxy/country_table_fallback_test.go` | 下载成功、下载失败、超大的表 |
| QMI / MBIM 后端、IMS 短信服务 | 测试内的替身类型 | `internal/device/sms_send_test.go`、`internal/device/incoming_sms_pipeline_test.go`、`internal/backend/prepared_sms_test.go`、`internal/api/sms_send_test.go`、`internal/notify/commands_sms_test.go` | 记录收到的 PDU，按脚本成功或失败 |
| SMTP 服务器 | 可编排的 SMTP 服务器 | `internal/notify/smtp_sim_test.go` | 隐式 TLS 或 STARTTLS；可设定它宣告的认证机制（PLAIN、LOGIN 或没有）、是否只在加密后提供认证、是否强制认证、拒收某个收件人；接了连接不说话；收下邮件后不确认 |
| Telegram、PushPlus、飞书、Bark、Webhook | 本地 HTTP 替身 | `internal/notify/notify_sim_test.go` 及各渠道的测试文件 | 接受、拒绝、不应答 |
| SWu 会话的底层传输 | 测试内的传输替身 | `vowifi-go/runtimehost/swu_transport_test.go`、`third_party/swu-go/pkg/swu/net_event_path_changed_test.go` | 触发中继断开、重建和“路径已变”，观察会话的反应 |

所有仿真器只监听 127.0.0.1，用到的号码、IMSI、IMEI 都是捏造的。

### 4.3 三类流量的覆盖

**正常流**：设备上线、读身份、收发单条和多片短信、USSD、经代理收发数据报、探测通过、各通知渠道投递成功。

**高负载与并发**：

| 测试 | 场景 |
|---|---|
| `TestSimulatedModemBurstOfMessagesIsStoredExactlyOnce`（`internal/device`） | 控制通道被状态查询占满的同时，连续到达 40 条短信和 3 条长短信；要求每条恰好入库一次、通知一次、从模组删除 |
| `TestSocks5UDPTransportHighLoad`（`vowifi-go/runtimehost/transport`） | 6 条流共用一个关联，每条 400 个最大 1400 字节的数据报，全部走同一条控制连接 |
| `TestSocks5UDPTransportConcurrentUse`（同上） | 代理不断丢弃关联的同时，并发使用所有入口；配合竞态检测运行 |
| `TestConcurrentConfigWritersKeepEveryUpdate`、`TestLoadIsSafeForConcurrentUse`（`internal/config`） | 多个写入方并发改配置文件，每一次更新都要保留 |

**异常流**（断连、超时、乱序）：

- 模组：运行中拔出与插回、模组重启、模组挂住不回答、回答很慢、模组拒绝命令（`+CME ERROR` / `+CMS ERROR`）、SIM 从不可用到可用、主动上报夹在命令应答中间。
- 短信接收：长短信各片乱序到达、两片之间程序重启、程序停止期间到达、数据库写不进去、SIM 身份一时读不到。
- 代理：不可达、握手停住、密码错误、不支持 UDP、控制连接闪断、关联反复被丢弃（要求不形成重连风暴并最终放弃）、报文丢失、延迟、乱序、重复、格式错误的中继报文。
- DNS：本机解析失败、本机解析迟迟不回答、某个公共解析器不回答、应答的事务号对不上、救援也失败。
- 短信发送：网络拒绝、网络一直不确认。
- 通知：邮件服务器接了连接不说话、收下邮件不确认、密码错误、拒收收件人、端口无人监听；其他服务拒绝请求。
- 配置：修改失败时保留原文件、并发写入。

### 4.4 测试规模

新增测试文件 38 个，其中有 337 个测试函数；另有 6 个既有测试文件随行为变化做了修改（5 个 Go、1 个 Python）。CI 覆盖的三个模块里，测试函数从 2099 个增至 2435 个，净增 336 个。仓库内 sipgo fork 自带的测试（24 个文件）不在 CI 的范围内，本次没有改动，不计入这些数字（见 1.5 的 G8）。

| 目录 | 基线 | 现在 | 增加 |
|---|---:|---:|---:|
| `internal/modem` | 82 | 131 | +49 |
| `internal/device` | 515 | 561 | +46 |
| `internal/notify` | 30 | 75 | +45 |
| `internal/upstreamproxy` | 16 | 55 | +39 |
| `vowifi-go/runtimehost/transport` | 0 | 39 | +39 |
| `vowifi-go/runtimehost` | 67 | 99 | +32 |
| `internal/config` | 28 | 53 | +25 |
| `internal/simulation/atsim` | 0 | 24 | +24 |
| `internal/api` | 162 | 173 | +11 |
| `pkg/smscodec` | 41 | 52 | +11 |
| `internal/db` | 80 | 86 | +6 |
| `internal/backend` | 94 | 98 | +4 |
| `internal/simulation/smssim` | 0 | 4 | +4 |
| `third_party/swu-go/pkg/swu` | 47 | 48 | +1 |

按层次分：

- **单元测试**：编解码（`pkg/smscodec`）、配置读写与校验、SOCKS5 握手、国家表、DNS 桩解析器、各通知渠道。
- **集成测试**：AT 管理器对着模拟模组（`internal/modem/simulated_modem_test.go`，18 个）；探测、中继工具、隧道传输对着模拟代理；Web API 的发短信接口对着替身后端。
- **端到端仿真**：设备池对着模拟模组（`internal/device/simulated_modem_e2e_test.go`，11 个），从“按端口名打开串口”一直到“短信写入数据库并发出通知”，中间只有模组是假的。

三个模块里仍然没有任何测试文件的 Go 目录有 23 个（基线 24 个），见 5.3。本次没有测量行覆盖率。

### 4.5 运行结果

完整检查（`scripts/verify-local.sh`，不带任何跳过参数）一共跑了两次，两次都是 23 步全部通过，末行 `verify_local=pass`，退出码 0。

| | 第一次 | 最终一次 |
|---|---|---|
| 被检查的代码 | `2afd7b0`（17 个代码提交），外加当时还没有提交的验证脚本 | `15b6799`（验证脚本已提交） |
| 当时的本报告（未提交，但在隐私扫描的范围内） | 只写了一部分 | 正文已写完；这次运行之后的改动见下面的说明 |
| 结果 | 23 步通过，0 步失败 | 23 步通过，0 步失败 |
| 总耗时 | 1510 秒（约 25 分钟） | 1232 秒（约 21 分钟） |
| 日志 | `.sandbox/logs/verify-local-1.log` | `.sandbox/logs/verify-local-2.log` |

最终一次的分步结果（数字由脚本从运行日志里提取，不是手抄的）：

| # | 步骤 | 结果 | 耗时 | 说明 |
|---:|---|---|---:|---|
| 1 | 前端：安装依赖（`npm ci`） | 通过 | 302 s |  |
| 2 | 前端：lint | 通过 | 40 s |  |
| 3 | 前端：类型检查 | 通过 | 117 s |  |
| 4 | 前端：测试 | 通过 | 8 s | 66 个通过，0 个失败 |
| 5 | 前端：构建 | 通过 | 269 s |  |
| 6 | 前端：构建产物同步到 `internal/web/dist` | 通过 | 1 s |  |
| 7 | `go test ./...`，根模块 | 通过 | 169 s | 33 个包通过；另有 9 个包没有测试文件 |
| 8 | `go vet ./...`，根模块 | 通过 | 81 s |  |
| 9 | `go test ./...`，`vowifi-go` | 通过 | 31 s | 12 个包通过；另有 11 个包没有测试文件 |
| 10 | `go vet ./...`，`vowifi-go` | 通过 | 9 s |  |
| 11 | `go test ./...`，`third_party/swu-go` | 通过 | 8 s | 4 个包通过；另有 4 个包没有测试文件 |
| 12 | `go vet ./...`，`third_party/swu-go` | 通过 | 6 s |  |
| 13 | 竞态检测，根模块 | 通过 | 109 s | 11 个包通过 |
| 14 | 竞态检测，`vowifi-go` | 通过 | 29 s | 6 个包通过；另有 1 个包没有测试文件 |
| 15 | 竞态检测，`third_party/swu-go` | 通过 | 8 s | 4 个包通过 |
| 16 | 隐私扫描 | 通过 | 8 s | `privacy_check_passed=true` |
| 17 | Python 契约测试 | 通过 | 0 s | 17 个测试，结果 `OK` |
| 18 | 脚本测试：`check-runtime-deps` | 通过 | 0 s | `check_runtime_deps_test=pass` |
| 19 | 脚本测试：`build-strongswan-plugins` | 通过 | 1 s | `build_strongswan_plugins_test=pass` |
| 20 | 脚本测试：`install-local` | 通过 | 0 s | `install_local_test=pass` |
| 21 | 脚本测试：`package-release-bundle` | 通过 | 0 s | `package_release_bundle_test=pass` |
| 22 | 脚本测试：`verify-release-bundle` | 通过 | 12 s | `verify_release_bundle_test=pass` |
| 23 | 发布包冒烟构建 | 通过 | 24 s | `release_bundle=pass`、`bundle_smoke=pass`；包名 `shannon-ims_local-15b6799a3df3_linux_amd64.tar.gz` |

合计：三个 Go 模块共 49 个包的测试通过，另有 24 个包没有测试文件（其中 1 个不是项目代码：装了前端依赖之后，`web/node_modules` 里某个依赖自带的 Go 包会被根模块的 `./...` 匹配到）；带竞态检测又跑了其中 21 个包，没有报告数据竞争。Go 测试都带 `-count=1`，不使用缓存的结果。

四点说明：

- **这 23 步是 CI 工作流的全部检查，另加仿真器和代理相关包的竞态测试。** 仓库内 sipgo fork 自带的测试不在 CI 里，也不在这 23 步里（见 1.5 的 G8）。
- **最终一次完整运行之后，只有本报告还在改动，代码和脚本没有再动。** 报告的改动是：填入本节的数字、把统计改为按三个模块计、补记 G8。读取本报告的检查只有隐私扫描（它扫描仓库里所有未被忽略的文件），所以改完后只重跑了隐私扫描和 Python 契约测试，都通过；没有再跑完整检查。
- **发布包那一步的含义有限。** 它证明二进制能构建、包能打出来并通过仓库自己的校验脚本；输出里的 `release_bundle_runtime_complete=false` 表示包里不含目标机器的 strongSwan 插件；打包脚本本次没有改（见 5.3 第 30 项）。
- **耗时只供估算等待时间。** 这是这台机器上的数字，不是性能指标。

### 4.6 哪些测试确认过“在旧代码上会失败”

一个只在新代码上跑过的测试，只能说明新代码满足它，不能说明它抓得住原来的缺陷。做过对照运行的只有两批：

1. **查询应答被当成事件**（`2b10aa5`）：`TestAnAnswerToAStatusQueryIsNotAnEvent`、`TestASIMStateThatChangesBetweenAnswersIsReportedOnce`、`TestSimulatedModemStatusPollsAreNotTakenForAModemThatJustBecameReady` 这 3 个测试在修改前的代码上失败。
2. **通知渠道**（`2afd7b0`）：Bark、Webhook、Telegram 的凭据外泄测试，原样放到修改前的代码上会失败；邮件无限等待、重新加载被拖住、库的报告带 token 这三项，用等价的测试在修改前的代码上复现了。其中有一项预期不成立：代理不可达时构造函数返回的错误本来就不含 token，所以那个测试只是回归保护，不代表修了什么。PushPlus 和飞书的旧行为是读代码得出的，没有对照运行。

其余新增测试都没有做对照运行。它们对应的缺陷在 1.5 里标为“读码”。

### 4.7 一键复现

在这台机器上（PowerShell，仓库根目录）：

```powershell
wsl.exe -d Ubuntu-24.04 -- bash ./.sandbox/lx.sh bash scripts/verify-local.sh
```

在任意装有 Go 1.26、Node 22、Python 3 的 Linux 上：

```bash
bash scripts/verify-local.sh
```

脚本按 CI 的顺序执行 23 步，最后列出每一步的结果和耗时，末行是 `verify_local=pass` 或 `verify_local=fail`，退出码只有全部通过时为 0。可选参数：

| 参数 | 作用 |
|---|---|
| `--skip-frontend` | 不重新构建前端，沿用已有的 `internal/web/dist`（前端装依赖最慢，平时可以跳过） |
| `--skip-race` | 不跑竞态测试 |
| `--skip-bundle` | 不做发布包冒烟构建 |

只跑仿真相关的测试：

```powershell
# 模拟模组、短信生成器
wsl.exe -d Ubuntu-24.04 -- bash ./.sandbox/lx.sh go test ./internal/simulation/... -count=1
# AT 管理器和设备池的全部测试，其中包含对着模拟模组的集成测试和端到端测试（约 1.5 分钟）
wsl.exe -d Ubuntu-24.04 -- bash ./.sandbox/lx.sh go test ./internal/modem ./internal/device -count=1
# 代理链路（先进入 vowifi-go 模块目录）
cd vowifi-go
wsl.exe -d Ubuntu-24.04 -- bash ../.sandbox/lx.sh go test ./runtimehost/transport/... -count=1
```

这三条命令都在这台机器上实际执行过。`wsl.exe` 会打印一行关于 localhost 代理的提示，可以忽略。

### 4.8 过程中遇到的失败与处理

| 现象 | 原因 | 处理 |
|---|---|---|
| 设备池端到端测试在全量竞态运行里失败过一次（数据竞争） | 设备池关闭后，它的后台协程还在读模组状态并写数据库，而测试已经关闭了数据库。实测这些协程在关闭返回后约 1 秒内全部退出，没有发现永不退出的 | 夹具改为等这些协程退出后再关数据库（`d7b30d8`）。之后连续 10 次带竞态检测运行这 11 个测试没有再出现。**需要说明**：修复前的失败概率没有测过（只见到一次），所以 10 次干净运行不能证明已根除，只能说修复直接针对了观察到的原因 |
| 模拟模组接上后，3 个测试失败 | 产品缺陷：查询应答被当成主动上报（1.5 的 D3） | 修产品代码（`2b10aa5`）。这是仿真层找到的真实缺陷 |
| 通知模块对照运行里有一项预期不成立 | 我以为旧代码在该路径会泄露 token，实际不会 | 该测试保留为回归保护，提交说明和本报告都不把它算作修复 |
| Linux 子系统里没有 Node，前端检查无法运行 | 环境缺失 | 把 Node 22 装到项目内的 `.sandbox/`（安装包校验了 sha256） |

### 4.9 仿真的局限

- `atsim` 按 Quectel 风格实现，其他厂商的 AT 方言没有覆盖；不模拟卡应用，不模拟串口的电气层（波特率不匹配、乱码）。
- `socks5sim` 实现的是协议规范和我预设的几种异常；真实代理软件各有自己的偏差，只有拿实际要用的代理试过才算数。
- QMI 和 MBIM 设备没有设备级的模拟器，只有接口级的替身。
- 通知服务的替身按我对各服务接口的理解编写，PushPlus 的成功码尤其没有把握。
- 没有 ePDG / IMS 核心网模拟器（见 4.1）。
- 高负载测试的规模是几十条短信、几千个数据报，验证的是正确性，不是性能；没有做吞吐量或长时间稳定性测试。

---

## 5. 待实物验证清单（Next Steps）

### 5.1 P0：合并或上线前要在实物上确认

| # | 验证什么 | 怎么做 | 通过标准 | 对应改动 |
|---|---|---|---|---|
| 1 | 串口参数生效后设备仍能连上 | 用现有配置启动，逐台检查 AT 设备；再故意把一台的 `baud_rate` 写错 | 现有设备全部上线；写错的那台连不上并有清楚的日志 | 2.4 |
| 2 | 拔出与插回模组 | 运行中拔掉 USB，几十秒后插回 | 拔出后日志立即报告断开（不是等命令逐个超时）；插回后设备自动恢复 | 2.4 |
| 3 | 掉线恢复不依赖 CPIN 轮询的副作用 | 让 VoWiFi 会话掉线（断网或停代理）再恢复网络；另外观察一小时日志 | 会话能自动重新拉起；日志里不再有每分钟一次的“Modem RDY” | 2.4、2.8 第 3 条 |
| 4 | 模组收短信 | 给卡发单条、中文、超过一片的长短信；程序停止时发一条再启动；长短信收到一半时重启程序 | 每条在历史里恰好一条、通知一次、模组里已删除；停机期间的短信在启动后一分钟内出现；长短信完整 | 2.2.2 |
| 5 | 升级后第一次启动读入旧短信 | 在存有旧短信的模组上启动 | 读入的数量与模组里原有的一致，没有重复；确认这批通知可以接受 | 2.8 第 2 条 |
| 6 | 模组发短信 | AT、QMI、MBIM 各选一台：英文、中文、长文本、带分隔符的号码 | 对端收到的内容完整；历史里的分片数正确 | 2.2.1、2.2.3 |
| 7 | SMS over IMS 收发 | VoWiFi 在线时收发长短信各一条 | 收发成功；送达状态与历史一致 | 2.2 |
| 8 | 经真实代理拉起 VoWiFi | 用实际要用的 SOCKS5 代理（须支持 UDP ASSOCIATE），先看探测结果再启动会话 | 探测结果里的中继地址与警告合理；隧道建立、IMS 注册成功 | 2.1.1、2.1.3 |
| 9 | 代理闪断后恢复 | 会话在线时重启代理，或切断它的控制连接 | 关联自动重建；恢复后立刻给这张卡打电话或发短信能到达（说明 ePDG 已经改用新地址） | 2.1.2 |
| 10 | ePDG DNS 救援 | 在本机解析不了运营商 ePDG 域名的网络里经代理启动；再设 `VOHIVE_EPDG_DNS_RESCUE=off` 试一次 | 开启时能解析并拉起；关闭时不发救援查询 | 2.1.5 |
| 11 | 国家代理规则离线可用 | 断开到表下载源的网络后启动；用共用 MCC 的卡验证归属 | 规则命中；共用 MCC 的归属符合预期 | 2.1.4 |

### 5.2 P1：建议尽快确认

| # | 验证什么 | 说明 |
|---|---|---|
| 12 | PushPlus 的成功码 | 用真实 token 发一条。如果消息送到了却被记成失败，改 `internal/notify/pushplus.go` 里的 `pushplusAccepted`。这是本次改动里把握最小的一处 |
| 13 | 邮件 | 对实际使用的邮箱服务商，SSL 端口和 STARTTLS 端口各发一封；检查中文主题和正文、`名称 <地址>` 形式的发件人 |
| 14 | 其余通知渠道 | Telegram（含经代理）、飞书、Bark、Webhook、QQ 各发一条；故意配错一次，确认日志里没有 token 或密钥 |
| 15 | QMI / MBIM 设备每分钟读一次已存短信 | 确认对设备没有副作用（数据连接、功耗、日志量） |
| 16 | 设置的持久化 | 在控制台编辑设备、改邮件 SSL 开关、改手动选网，重启后检查是否都在 |
| 17 | 配置校验的警告 | 用生产配置启动，看 `GET /api/system/info` 的 `config_issues` 里的警告是否都合理、有没有误报 |
| 18 | 其他厂商的模组 | 如果有非 Quectel 的 AT 模组，重点看查询应答与主动上报的区分（2.4）是否适用 |

### 5.3 P2：没有改的发现与后续建议

| # | 事项 | 建议 |
|---|---|---|
| 19 | 设备池关闭不等待后台协程、不停止 AT 管理器，AT 查询不可取消（1.5 的 G1） | 让设备池跟踪它启动的协程并在关闭时等待；给 AT 查询加上可取消的上下文。改动面大，需要实物回归 |
| 20 | 任务池没有 `recover`（G2） | 在 `pkg/taskpool` 的任务外层加 `recover` 并记日志；这个包目前也没有测试 |
| 21 | 设置接口访问 `s.fullCfg` 没有加锁（G3） | 给 `internal/api/settings.go` 的读写加锁，或改为每次从配置管理器取快照 |
| 22 | AT 模式下“拔卡后停止 VoWiFi”没有接线（G4） | 确认这是不是有意为之；如果不是，在现行的启动路径里绑定 SIM 状态处理函数，并删除没人调用的 `startAllSynchronousLegacy` |
| 23 | `handleVoWiFiSMSStatus` 没有路由（G5） | 接上路由或删除 |
| 24 | IPv6 地址范围转 CIDR 不完整（G6） | 按范围拆成若干 CIDR；只在运营商下发 IPv6 范围选择器时才有影响 |
| 25 | `+CRSM` 应答被调试日志记成“未分类 URC”（G7） | 只影响日志，顺手可改 |
| 26 | 三个模块里有 23 个 Go 目录没有测试 | 其中与产品逻辑关系较大的：`cmd/vohive-relay`、`internal/sipgw`、`pkg/taskpool`、`vowifi-go/runtimehost/messaging`、`vowifi-go/runtimehost/voicehost`、`vowifi-go/runtimehost/e911` |
| 27 | 控制台没有展示新信息 | `config_issues` 和探测结果的新字段（中继地址、账号被忽略、警告）可以显示在设置页和代理页 |
| 28 | 若干时限和期限是常量 | 通知投递时限、接收日志保留 30 天、读取已存短信的间隔，需要时可做成配置项 |
| 29 | ePDG / IMS 没有模拟器 | 如果要在没有实物的情况下验证完整的 VoWiFi 拉起，需要写一个最小的 IKEv2 响应端和 IMS 注册服务器，工作量不小 |
| 30 | 发布包 | 冒烟构建的输出里有 `release_bundle_runtime_complete=false` 和 `target_plugin_build_required=true`，即包里不含目标机器的 strongSwan 插件。打包脚本本次没有改，这两个值与本次改动无关，发布流程照旧按 `RELEASE_CHECKLIST.md` 走 |
| 31 | sipgo fork 的测试不在 CI 里，其中 2 个失败（G8） | 先弄清 `TestTransportLayerClosing/UDP` 的失败是 fork 的有意改动，还是 UDP 监听没有真正关闭；再决定要不要把这个模块的测试加进 CI。根包的测试需要先运行 `third_party/sipgo/testdata/generate_certs.sh` 生成证书，生成的证书和私钥不要提交（这个脚本我没有运行过） |

---

## 附录 A：每个提交的文件清单

由 `git log main..` 的记录生成，按提交先后排列。收尾的两个提交（`scripts/verify-local.sh`、`HANDOVER_REPORT.md`）不在其中。

**`51b1fae`** fix(config): make config writes atomic and serialized, persist dropped settings, validate on load

- 新增（6）：`internal/api/config_observability_test.go`、`internal/config/filestore.go`、`internal/config/filestore_test.go`、`internal/config/persist_regression_test.go`、`internal/config/validate.go`、`internal/config/validate_test.go`
- 修改（12）：`.gitignore`、`config/config.example.yaml`、`internal/api/device_mgmt.go`、`internal/api/server.go`、`internal/backend/factory.go`、`internal/config/config.go`、`internal/config/manager.go`、`internal/config/network_migration.go`、`internal/config/path_field_migration.go`、`internal/config/persist.go`、`internal/config/persist_devices.go`、`internal/config/persist_proxy.go`

**`3f627c5`** feat(transport): shared SOCKS5 core, resilient UDP association and a proxy simulator

- 新增（6）：`vowifi-go/runtimehost/transport/socks5.go`、`vowifi-go/runtimehost/transport/socks5_test.go`、`vowifi-go/runtimehost/transport/socks5_udp.go`、`vowifi-go/runtimehost/transport/socks5_udp_test.go`、`vowifi-go/runtimehost/transport/socks5sim/peer.go`、`vowifi-go/runtimehost/transport/socks5sim/server.go`
- 修改（1）：`vowifi-go/runtimehost/transport/transport.go`

**`b8a7bfc`** feat(swu): probe the peer at once when the local egress path changes

- 新增（1）：`third_party/swu-go/pkg/swu/net_event_path_changed_test.go`
- 修改（2）：`third_party/swu-go/pkg/ipsec/icmp_err.go`、`third_party/swu-go/pkg/swu/session.go`

**`ef278ad`** fix(vowifi): keep the SWu tunnel alive across proxy relay changes and report relay failures

- 新增（1）：`vowifi-go/runtimehost/swu_transport_test.go`
- 修改（1）：`vowifi-go/runtimehost/swu_transport.go`

**`8ca3952`** refactor(upstreamproxy): run the proxy probe and the relay tool on the shared SOCKS5 core

- 新增（2）：`internal/upstreamproxy/probe_sim_test.go`、`internal/upstreamproxy/udprelay_test.go`
- 修改（4）：`cmd/vohive-relay/main.go`、`internal/upstreamproxy/probe.go`、`internal/upstreamproxy/probe_test.go`、`internal/upstreamproxy/udprelay.go`

**`542baf8`** feat(upstreamproxy): retry the proxy probe on transient failures

- 新增（2）：`internal/upstreamproxy/probe_retry.go`、`internal/upstreamproxy/probe_retry_test.go`

**`5806dfd`** fix(vowifi): make country proxy rules apply reliably when a VoWiFi session starts

- 新增（6）：`cmd/vohive/country_table.go`、`internal/db/upstream_proxy_home_network_test.go`、`internal/device/vowifi_proxy_probe.go`、`internal/device/vowifi_proxy_probe_test.go`、`internal/upstreamproxy/country_builtin.go`、`internal/upstreamproxy/country_table_fallback_test.go`
- 修改（4）：`cmd/vohive/main.go`、`internal/db/upstream_proxy.go`、`internal/device/vowifi_start_orchestrator.go`、`internal/upstreamproxy/country_table.go`

**`dba2287`** feat(vowifi): resolve the ePDG name through the proxy when local DNS fails

- 新增（4）：`vowifi-go/runtimehost/epdg_dns.go`、`vowifi-go/runtimehost/epdg_dns_test.go`、`vowifi-go/runtimehost/epdg_proxy_resolver.go`、`vowifi-go/runtimehost/epdg_proxy_resolver_test.go`
- 修改（1）：`vowifi-go/runtimehost/swu_candidates.go`

**`f3569a8`** feat(sms): prepare outgoing messages once and frame them per channel

- 新增（4）：`internal/backend/prepared_sms_test.go`、`internal/modem/manager_sms_send_test.go`、`pkg/smscodec/submission.go`、`pkg/smscodec/submission_test.go`
- 修改（7）：`internal/backend/at_backend.go`、`internal/backend/mbim_backend_sms.go`、`internal/backend/qmi_backend.go`、`internal/backend/sms.go`、`internal/device/vowifi_state_api.go`、`internal/modem/manager.go`、`pkg/smscodec/pdu.go`

**`9af669c`** feat(sms): store received messages before deleting them from the modem

- 新增（7）：`internal/db/sms_incoming_purge_test.go`、`internal/device/incoming_sms_pipeline.go`、`internal/device/incoming_sms_pipeline_test.go`、`internal/modem/sms_inbox.go`、`internal/modem/sms_inbox_test.go`、`internal/simulation/smssim/smssim.go`、`internal/simulation/smssim/smssim_test.go`
- 修改（12）：`internal/backend/at_backend.go`、`internal/db/sms_incoming.go`、`internal/device/pool.go`、`internal/device/pool_bootstrap.go`、`internal/device/pool_health_ip.go`、`internal/device/pool_sms.go`、`internal/device/pool_sms_mbim.go`、`internal/device/pool_sms_mbim_test.go`、`internal/device/vowifi_incoming_sms.go`、`internal/device/vowifi_start_orchestrator.go`、`internal/device/vowifi_teardown.go`、`internal/modem/manager.go`

**`4188d27`** feat(sms): send every message through one entry point

- 新增（4）：`internal/api/sms_send_test.go`、`internal/device/sms_send.go`、`internal/device/sms_send_test.go`、`internal/notify/commands_sms_test.go`
- 修改（6）：`internal/api/openapi.vohive.yaml`、`internal/api/server.go`、`internal/api/sms_submission_response_test.go`、`internal/device/pool_sms.go`、`internal/device/vowifi_state_api.go`、`internal/notify/commands.go`

**`1664fa8`** refactor(sms): remove the unused stand-alone SMS poller

- 修改（2）：`scripts/check-repository-privacy.py`、`scripts/tests/test_check_repository_privacy.py`
- 删除（1）：`internal/sms/poller.go`

**`5197422`** fix(modem): honour the serial settings and recover at once from a dead port

- 新增（2）：`internal/modem/serial_lifecycle_test.go`、`internal/modem/serial_open.go`
- 修改（6）：`internal/api/device_mgmt.go`、`internal/api/device_mgmt_at_test.go`、`internal/modem/imei_probe.go`、`internal/modem/manager.go`、`internal/modem/manager_force_release_test.go`、`internal/modem/serial_at.go`
- 删除（1）：`internal/modem/urc_listener.go`

**`fd86ce3`** test(simulation): add a software cellular modem

- 新增（4）：`internal/simulation/atsim/atsim_test.go`、`internal/simulation/atsim/commands.go`、`internal/simulation/atsim/modem.go`、`internal/simulation/atsim/port.go`

**`2b10aa5`** fix(modem): do not take the answer to a query for an event

- 新增（2）：`internal/device/simulated_modem_e2e_test.go`、`internal/modem/simulated_modem_test.go`
- 修改（4）：`internal/backend/info.go`、`internal/modem/at_parse.go`、`internal/modem/commands.go`、`internal/modem/manager.go`

**`d7b30d8`** test(device): wait for the pool's goroutines before the E2E fixture closes its database

- 修改（1）：`internal/device/simulated_modem_e2e_test.go`

**`2afd7b0`** fix(notify): keep credentials out of logs and errors, put a time limit on every delivery

- 新增（9）：`internal/notify/bark_test.go`、`internal/notify/channel_secrets_test.go`、`internal/notify/email_test.go`、`internal/notify/feishu_test.go`、`internal/notify/notify_sim_test.go`、`internal/notify/pushplus_test.go`、`internal/notify/redact.go`、`internal/notify/redact_test.go`、`internal/notify/smtp_sim_test.go`
- 修改（6）：`internal/notify/bark.go`、`internal/notify/email.go`、`internal/notify/feishu.go`、`internal/notify/pushplus.go`、`internal/notify/telegram.go`、`internal/notify/webhook.go`

---

## 附录 B：这台机器上留下了什么

所有东西都在 `E:\11.10归档文档\shannonims` 之内。

| 位置 | 内容 | 是否进入 git |
|---|---|---|
| `.sandbox/` | 项目内的工具链（Go 1.26.3、Node 22）、模块与构建缓存、包装脚本 `lx.sh`、辅助脚本 `tasks/`、各次运行的日志 `logs/` | 否（已在 `.gitignore`）。不需要时整个删除即可 |
| `web/node_modules` | 前端依赖，**在 Linux 下安装的**。要在 Windows 上跑前端，先执行 `npm ci --prefix web` | 否 |
| `web/dist`、`internal/web/dist` | 验证时生成的前端构建产物 | 否 |
| `dist/verify-local/` | 验证时生成的二进制和发布包 | 否 |
| `.git/config` | 仅对本仓库设置了 `core.autocrlf=false`、`core.eol=lf`，保证检出的文件是 LF 换行（脚本测试和 Linux 构建需要） | 不适用 |

其他说明：

- Go 模块通过国内镜像下载，镜像地址只写在 `.sandbox/lx.sh` 里，没有改任何全局配置；npm 用的是默认源。
- git 的用户身份用的是这台机器上已有的设置，没有修改。
- 没有执行过 `git push`。要审阅改动：`git log --stat main..feat/auto-optimization`，或逐个提交 `git show <提交号>`。
