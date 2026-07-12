<div align="center">

<h1>Shannon IMS</h1>

<p>
  <strong>Cellular module management with a deeply optimized Wi‑Fi Calling / IMS stack</strong><br>
  <strong>面向蜂窝模组的管理平台，内置深度优化的 Wi‑Fi Calling / IMS 能力</strong>
</p>

<p>
  <a href="#中文介绍">中文介绍</a> ·
  <a href="#english">English</a> ·
  <a href="#快速开始">快速开始</a> ·
  <a href="#quick-start">Quick Start</a>
</p>

<p>
  <a href="LICENSE"><img alt="License: PolyForm Noncommercial" src="https://img.shields.io/badge/License-PolyForm--Noncommercial-blue.svg"></a>
  <a href="go.mod"><img alt="Go 1.26+" src="https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go"></a>
  <a href="web/package.json"><img alt="Vue 3" src="https://img.shields.io/badge/Vue-3-42b883?logo=vue.js"></a>
  <a href="#运行环境"><img alt="Linux and WSL2" src="https://img.shields.io/badge/Platform-Linux%20%7C%20WSL2-555555?logo=linux"></a>
</p>

</div>

---

<a id="中文介绍"></a>

## 中文介绍

Shannon IMS 不只是一个“能管理 4G/5G 模组”的后台，也不只是一个独立的 SIP 库。

它把 **模组控制、UICC 鉴权、SWu 隧道、IMS-AKA、3GPP IPsec、IMS 注册、IMS 短信和 Web 管理界面** 放进同一套运行时，目标是在 Linux 或 WSL2 上完成一条可以观察、诊断和恢复的 Wi‑Fi Calling 链路。

项目尤其适合以下场景：

- 使用 QMI、MBIM 或 AT 接口接入蜂窝模组；
- 研究或验证 Wi‑Fi Calling、IMS 和 SMS over IMS；
- 在弱蜂窝覆盖环境中通过宽带网络建立 IMS 服务；
- 调试真实网络中的 AKA 重同步、IPsec 协商和 SIP 路由问题；
- 需要 Web UI、API、短信、USSD、eSIM 与多模组管理的一体化平台。

### 为什么 Shannon IMS 不一样

| 能力 | 常见实现 | Shannon IMS |
| --- | --- | --- |
| IMS 鉴权 | 只处理一次 AKA challenge | 支持 AUTS/SQN 重同步、fresh challenge 和有界 challenge 状态机 |
| IMS 安全 | 只生成 SIP Authorization | 完整处理 Security-Client、Security-Server、Security-Verify 与 3GPP IPsec |
| 数据面 | 依赖普通 TCP/UDP socket | 支持 SWu raw IP、ESP、UDP protected flow 和 IPv4 分片 |
| IMS 注册 | 发送一次 REGISTER 后等待结果 | 区分未保护重同步、密钥生成、IPsec 安装与受保护 REGISTER |
| IMS 短信 | 直接向目标号码发 SIP MESSAGE | 使用短信中心 PSI、Service-Route、P-Preferred-Identity 和安全 MESSAGE |
| 故障诊断 | 打印完整 SIP 或认证字段 | 记录状态、长度、布尔值和不可逆指纹，避免泄露 AKA 材料 |
| 设备管理 | 单一模组脚本 | 集成 QMI、MBIM、AT、短信、USSD、eSIM、代理和 Web 控制台 |

### 已覆盖的端到端链路

~~~text
蜂窝模组
  └─ QMI / MBIM / AT
      └─ USIM / ISIM
          └─ SWu tunnel
              └─ IMS-AKA
                  ├─ 正常 AKA
                  └─ AUTS / SQN 重同步
                      └─ 3GPP IPsec
                          └─ protected REGISTER
                              ├─ IMS Ready
                              ├─ SMS over IMS
                              └─ Voice service
~~~

真实设备验证过的核心状态链：

~~~text
Access ready
→ SWu tunnel ready
→ initial REGISTER
→ AKA challenge
→ optional AUTS resync
→ fresh AKA challenge
→ RES / CK / IK available
→ IPsec installed
→ protected REGISTER
→ 200 OK
→ IMSReady
→ SMSReady
~~~

> 运营商、账户、SIM 资料和区域策略会影响最终结果。项目能够实现完整协议链路，但不能替运营商开启未授权的 IMS 服务。

### 核心特性

#### Wi‑Fi Calling / IMS

- SWu 隧道生命周期管理；
- IMS-AKA 与 AUTS/SQN 重同步；
- 重复 nonce、重复同步状态与 challenge 轮次保护；
- 3GPP IPsec SA、FlowC/FlowS 和重放保护；
- UDP protected signaling 与 IPv4 MTU 分片；
- 初始、重同步、鉴权和受保护 REGISTER 的独立状态；
- carrier profile、P-CSCF 解析与 IMS 路由；
- 可观察的 IMSReady、SMSReady 和 tunnel 状态。

#### SMS over IMS

- 3GPP SMS over IP 封装；
- 短信中心 PSI Request-URI；
- REGISTER 返回的 Service-Route 复用；
- Security-Verify 与 sec-agree；
- 多分片提交与 delivery 状态记录；
- 接收 RP-ACK / RP-ERROR 报告；
- SQLite 幂等写入和安全迁移。

#### 模组与平台能力

- QMI、MBIM、AT 多后端；
- 多模组发现、热插拔和状态监控；
- 短信、USSD、运营商选择和信号信息；
- eSIM Profile 管理；
- SOCKS5 / HTTP 移动网络代理；
- Vue 3 Web 管理界面；
- HTTP API 与 OpenAPI 文档；
- SQLite 本地状态存储。

### 架构

~~~mermaid
flowchart LR
    UI["Web UI / HTTP API"] --> Service["Shannon IMS Service"]

    Service --> Manager["Modem Manager"]
    Manager --> QMI["QMI"]
    Manager --> MBIM["MBIM"]
    Manager --> AT["AT"]

    Service --> UICC["USIM / ISIM"]
    UICC --> AKA["IMS-AKA + AUTS Recovery"]

    Service --> SWu["SWu Tunnel"]
    SWu --> Raw["Raw IP / ESP"]
    Raw --> PCSCF["IMS P-CSCF"]

    AKA --> PCSCF
    PCSCF --> IPsec["3GPP IPsec"]
    IPsec --> Register["Protected REGISTER"]
    Register --> IMS["IMSReady / SMSReady"]
    IMS --> SMS["SMS over IMS"]
~~~

### 面向使用者的隐私设计

Shannon IMS 的隐私边界体现在运行方式中，而不是要求使用者理解仓库维护流程：

- 示例配置不包含真实凭据，首次部署时由使用者在本机生成配置；
- 运行数据库、日志和设备状态保存在部署机器上，不随源码仓库分发；
- IMS-AKA 的 RAND、AUTN、AUTS、RES、CK 和 IK 不进入常规日志；
- SIP trace 默认只记录报文长度和连接信息，不保存完整认证报文；
- challenge 诊断使用轮次、布尔状态、字段长度和不可逆 nonce 指纹；
- Web 密码、通知 Token 和第三方凭据由本地配置管理。

### 运行环境

| 项目 | 建议 |
| --- | --- |
| 操作系统 | Linux 或 WSL2 |
| Go | 1.26.3 或更高版本 |
| Node.js | 20 或更高版本 |
| 模组 | 支持 QMI、MBIM 或 AT 的 LTE / 5G 模组 |
| 网络权限 | raw socket、TUN、ESP、路由和设备访问权限 |
| SWu 组件 | StrongSwan / VICI 及对应插件 |
| SIM | 有效 SIM，且账户允许使用相应 IMS 服务 |

<a id="快速开始"></a>

## 快速开始

### 1. 获取源码

~~~bash
git clone git@github.com:deeeeeeeeap/shannon-ims.git
cd shannon-ims
~~~

### 2. 准备配置

~~~bash
cp config/config.example.yaml config/config.yaml
chmod 600 config/config.yaml
~~~

编辑 <code>config/config.yaml</code>，至少修改 Web 登录密码，并按实际模组填写设备配置。

### 3. 构建 Linux amd64

~~~bash
bash scripts/build-linux-amd64.sh
~~~

构建产物：

~~~text
dist/shannon-ims_linux_amd64
~~~

### 4. 安装

~~~bash
sudo bash scripts/install-local.sh \
  dist/shannon-ims_linux_amd64 \
  /opt/shannon-ims
~~~

启动：

~~~bash
sudo /opt/shannon-ims/bin/shannon-ims \
  -c /opt/shannon-ims/config/config.yaml
~~~

健康检查：

~~~bash
curl http://127.0.0.1:7575/api/health
~~~

### 从 Release 部署

版本标签会触发 GitHub Actions，生成 Linux amd64、arm64 和 armv7 二进制。希望快速部署时，可直接从 Releases 下载对应架构的产物，而无需在目标机器安装前端工具链。

### 项目结构

| 路径 | 内容 |
| --- | --- |
| <code>cmd/vohive</code> | 主服务入口 |
| <code>internal/device</code> | 模组管理与 Wi‑Fi Calling 编排 |
| <code>internal/sim</code> | UICC APDU 与 AKA 适配 |
| <code>internal/db</code> | SQLite 模型、投递状态与迁移 |
| <code>vowifi-go</code> | SWu、IMS、IPsec、SIP 与 SMS 核心 |
| <code>third_party/sipgo</code> | 项目使用的 SIP transport 扩展 |
| <code>web</code> | Vue 3 管理界面 |
| <code>scripts</code> | 构建、安装与仓库检查工具 |

### 当前边界

Shannon IMS 是面向研究、实验室和个人部署的工程项目，不是运营商认证终端固件。

目前不承诺：

- 所有运营商和所有账户都能开通 Wi‑Fi Calling；
- 所有模组固件都暴露相同的 UICC、QMI 或 MBIM 能力；
- 紧急呼叫、商业语音质量或生产级高可用；
- 在没有合法授权的情况下绕过运营商策略。

---

<a id="english"></a>

## English

Shannon IMS is an integrated cellular-module platform with a deeply optimized Wi‑Fi Calling and IMS stack.

Instead of treating IMS as a single SIP request, it models the complete path from modem control and UICC authentication to SWu transport, AKA synchronization recovery, 3GPP IPsec, protected registration, and SMS over IMS.

### What makes it useful

- QMI, MBIM, and AT modem backends;
- multi-modem discovery and lifecycle management;
- SWu tunnel orchestration with raw IP and ESP support;
- IMS-AKA authentication with AUTS/SQN resynchronization;
- bounded challenge handling and repeated-state protection;
- 3GPP IPsec security agreement and protected UDP signaling;
- protected REGISTER with explicit state transitions;
- SMS over IMS using service-centre PSI and Service-Route;
- local SQLite delivery tracking;
- privacy-safe diagnostics that do not expose AKA key material;
- Vue 3 management UI, HTTP API, and OpenAPI documentation.

### End-to-end model

~~~text
Modem access
→ USIM / ISIM
→ SWu tunnel
→ IMS-AKA
→ optional AUTS resynchronization
→ fresh AKA challenge
→ 3GPP IPsec
→ protected REGISTER
→ IMS ready
→ SMS ready
~~~

### Privacy by design

- Runtime configuration and state remain on the deployment machine.
- Sample configuration ships without real credentials.
- AKA authentication material is excluded from normal logs.
- SIP diagnostics record metadata and lengths rather than full authenticated messages.
- Challenge troubleshooting uses state, round counters, booleans, lengths, and irreversible fingerprints.

<a id="quick-start"></a>

## Quick Start

~~~bash
git clone git@github.com:deeeeeeeeap/shannon-ims.git
cd shannon-ims

cp config/config.example.yaml config/config.yaml
chmod 600 config/config.yaml

bash scripts/build-linux-amd64.sh
~~~

Install the generated binary:

~~~bash
sudo bash scripts/install-local.sh \
  dist/shannon-ims_linux_amd64 \
  /opt/shannon-ims

sudo /opt/shannon-ims/bin/shannon-ims \
  -c /opt/shannon-ims/config/config.yaml
~~~

Health check:

~~~bash
curl http://127.0.0.1:7575/api/health
~~~

### Compatibility notes

A valid IMS protocol implementation does not guarantee service activation for every subscription. Carrier policy, account provisioning, regional access, SIM capabilities, modem firmware, and network topology all affect the result.

Use Shannon IMS only with hardware, subscriptions, networks, and destination numbers you are authorized to test.

## Build verification

Focused regression suites:

~~~bash
go test ./internal/sim ./internal/vowifihost
go test ./internal/db -run '^TestEnsureSMSDeliveryPartUniqueIndex'

cd vowifi-go
go test ./internal/vowifi/imscore \
  ./runtimehost/simauth \
  ./internal/vowifi/ipsec3gpp \
  ./runtimehost/voiceclient \
  -run Test -skip '^TestFormatGSMAIMEIURN$'
~~~

## Releases

Push a semantic version tag to build Linux artifacts for amd64, arm64, and armv7:

~~~bash
git tag v0.1.0
git push origin v0.1.0
~~~

## Credits and license

Shannon IMS combines and extends the VoHive service, an embedded Wi‑Fi Calling core, and a locally maintained SIP transport layer. Attribution and required notices are available in [NOTICE.md](NOTICE.md).

The repository is distributed under the [PolyForm Noncommercial License 1.0.0](LICENSE). Commercial use requires separate authorization.

This is an independent research project and is not affiliated with any modem vendor, mobile network operator, or standards organization.
