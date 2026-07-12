# Shannon IMS

[English](#english) · [中文](#中文)

[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm--Noncommercial--1.0.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go)](go.mod)
[![Vue](https://img.shields.io/badge/Vue-3-42b883?logo=vue.js)](web/package.json)

Shannon IMS is a research-oriented cellular module management stack with special focus on reliable Wi-Fi Calling, IMS registration, IMS-AKA recovery, 3GPP IPsec, and SMS over IMS.

Shannon IMS 是一个面向蜂窝模组的研究型管理栈，重点优化 Wi-Fi Calling、IMS 注册、IMS-AKA 重同步、3GPP IPsec 与 IMS 短信链路。

> Privacy first: this repository contains no runtime database, device identity, subscriber identity, phone number, credential, token, packet capture, or real deployment configuration.
>
> 隐私优先：本仓库不包含运行数据库、设备身份、用户身份、电话号码、凭据、Token、抓包或真实部署配置。

<a id="english"></a>

## English

### Why this project exists

Cellular modules often expose enough QMI, MBIM, AT, UICC, and raw IP functionality to build a complete Wi-Fi Calling client, but real IMS networks are strict about registration state, AKA synchronization, IPsec direction, transport reuse, and SMS routing.

Shannon IMS packages the device manager and the Wi-Fi Calling core into one reproducible repository. The implementation is optimized around observable state transitions, bounded retries, privacy-safe diagnostics, and safe radio fallback after failures.

### Highlights

- Multi-modem discovery and lifecycle management for QMI, MBIM, AT, SMS, USSD, and eSIM workflows.
- SWu tunnel orchestration with raw IP and ESP data-plane support.
- IMS-AKA authentication with AUTS/SQN synchronization recovery.
- Bounded challenge rounds and repeated challenge protection.
- 3GPP IPsec security agreement, directional FlowC/FlowS handling, UDP protected transport, replay protection, and IPv4 fragmentation.
- Protected REGISTER flow with security-agreement verification.
- SMS over IMS with secure MESSAGE requests, service-centre PSI routing, Service-Route preservation, and delivery tracking.
- Privacy-safe IMS diagnostics: challenge fingerprints, lengths, booleans, and state transitions instead of secret material.
- Vue-based management UI and HTTP API.
- Linux amd64, arm64, and armv7 release workflow.

### Architecture

~~~mermaid
flowchart LR
    UI["Web UI / API"] --> Core["Shannon IMS service"]
    Core --> Device["QMI / MBIM / AT modem control"]
    Core --> UICC["USIM / ISIM authentication"]
    Core --> SWu["SWu tunnel and raw IP stack"]
    SWu --> IMS["IMS P-CSCF"]
    UICC --> AKA["IMS-AKA and AUTS recovery"]
    AKA --> IMS
    IMS --> IPsec["3GPP IPsec protected signaling"]
    IPsec --> Services["REGISTER / SMS / Voice services"]
~~~

### Repository layout

| Path | Purpose |
| --- | --- |
| cmd/vohive | Main service entry point |
| internal/device | Modem lifecycle and Wi-Fi Calling orchestration |
| internal/sim | UICC APDU and AKA adapter |
| internal/db | SQLite models and safe migrations |
| internal/web | Embedded web assets |
| web | Vue 3 management interface |
| vowifi-go | Embedded Wi-Fi Calling and IMS core |
| third_party/sipgo | Local SIP transport changes used by both modules |
| scripts | Build, install, and repository privacy checks |

### Requirements

- Linux or WSL2 with direct access to the cellular module.
- Go 1.26.3 or newer.
- Node.js 20 or newer and npm.
- A compatible QMI or MBIM modem and the required USB serial/control interfaces.
- StrongSwan/VICI components required by the SWu environment.
- Root or equivalent capabilities for raw networking, TUN, ESP, device access, and route management.
- A valid SIM and carrier support for Wi-Fi Calling.

Carrier behavior differs. A successful build does not guarantee that a specific subscription or network enables IMS services.

### Quick start

~~~bash
git clone git@github.com:deeeeeeeeap/shannon-ims.git
cd shannon-ims

cp config/config.example.yaml config/config.yaml
chmod 600 config/config.yaml

# Edit config/config.yaml and replace every placeholder.
bash scripts/build-linux-amd64.sh
~~~

The generated binary is:

~~~text
dist/shannon-ims_linux_amd64
~~~

Install it into a local prefix:

~~~bash
sudo bash scripts/install-local.sh dist/shannon-ims_linux_amd64 /opt/shannon-ims
sudo /opt/shannon-ims/bin/shannon-ims -c /opt/shannon-ims/config/config.yaml
~~~

Check service health:

~~~bash
curl http://127.0.0.1:7575/api/health
~~~

### Manual build

~~~bash
npm ci --prefix web
npm run build --prefix web

rm -rf internal/web/dist
cp -R web/dist internal/web/dist

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -buildvcs=false \
  -tags "with_utls nomsgpack" \
  -o dist/shannon-ims_linux_amd64 ./cmd/vohive
~~~

### Validation

Run the repository privacy check before committing or releasing:

~~~bash
python3 scripts/check-repository-privacy.py
~~~

Run the focused Wi-Fi Calling regression suites:

~~~bash
go test ./internal/sim ./internal/vowifihost
go test ./internal/db -run '^TestEnsureSMSDeliveryPartUniqueIndex'

cd vowifi-go
go test ./internal/vowifi/imscore ./runtimehost/simauth \
  ./internal/vowifi/ipsec3gpp ./runtimehost/voiceclient \
  -run Test -skip '^TestFormatGSMAIMEIURN$'
~~~

### Configuration and privacy

- Never commit config/config.yaml. Only config/config.example.yaml belongs in Git.
- Keep database, logs, packet captures, crash dumps, modem identities, subscriber identities, phone numbers, passwords, and tokens outside the repository.
- Use a unique web password before the first run.
- IMS authentication material must never be printed, copied into issues, or stored in diagnostic artifacts.
- Review staged files with git status and run the privacy checker before every push.

### Wi-Fi Calling state model

A healthy registration normally progresses through these classes of state:

~~~text
access ready
SWu tunnel ready
initial REGISTER
AKA challenge
optional AUTS synchronization recovery
fresh AKA challenge
IPsec installed
protected REGISTER
IMS ready
SMS ready
~~~

An HTTP or SIP challenge is not automatically a failure. Diagnose the current state transition and preserve already-proven transport and identity settings.

### Releases

Pushing a version tag such as v0.1.0 runs the GitHub Actions release workflow and builds Linux binaries for amd64, arm64, and armv7.

~~~bash
git tag v0.1.0
git push origin v0.1.0
~~~

### Safety and legal notice

This is an independent research project. It is not affiliated with any modem vendor, network operator, or standards organization. Use it only with hardware, subscriptions, networks, and destination numbers you are authorized to test. Follow local law and carrier terms.

The software is provided as-is without warranty. Radio, SIM, eSIM, routing, and IMS operations can interrupt connectivity. Keep backups and maintain a known-safe fallback procedure.

<a id="中文"></a>

## 中文

### 项目定位

蜂窝模组通常已经提供 QMI、MBIM、AT、UICC 和原始 IP 能力，但真实 IMS 网络会严格校验注册状态、AKA 同步、IPsec 方向、连接复用以及短信路由。Shannon IMS 将模组管理服务与 Wi-Fi Calling 核心整合为一个可复现仓库，便于在其他 Linux 或 WSL2 机器上构建和部署。

项目重点不是“堆叠重试”，而是清晰记录状态迁移、限制 challenge 轮次、保护认证材料，并在失败后恢复到安全的短信与射频状态。

### 核心能力

- 支持 QMI、MBIM、AT、短信、USSD 和 eSIM 的多模组发现与生命周期管理。
- 支持 SWu 隧道、原始 IP 与 ESP 数据面。
- 支持 IMS-AKA 鉴权和 AUTS/SQN 重同步。
- 限制 challenge 轮次，并阻止重复 challenge 在本地形成死循环。
- 支持 3GPP IPsec security agreement、FlowC/FlowS 方向、UDP 保护传输、重放保护与 IPv4 分片。
- 支持受保护 REGISTER 和 security-agreement 验证。
- 支持 IMS 短信安全 MESSAGE、短信中心 PSI 路由、Service-Route 保留和投递状态记录。
- 日志只记录状态、长度、布尔值与不可逆指纹，不记录 AKA 密钥材料。
- 提供 Vue 3 管理后台与 HTTP API。
- 提供 Linux amd64、arm64、armv7 的 GitHub Release 构建流程。

### 环境要求

- Linux 或可直通蜂窝模组的 WSL2。
- Go 1.26.3 或更高版本。
- Node.js 20 或更高版本及 npm。
- 兼容的 QMI 或 MBIM 模组，以及对应 USB 串口和控制接口。
- SWu 环境所需的 StrongSwan/VICI 组件。
- 原始网络、TUN、ESP、设备访问和路由管理所需的 root 权限或等效 capabilities。
- 有效 SIM，并且运营商侧允许 Wi-Fi Calling。

不同网络的 IMS 策略存在差异。编译成功并不代表任意账户都一定开放 IMS 服务。

### 快速开始

~~~bash
git clone git@github.com:deeeeeeeeap/shannon-ims.git
cd shannon-ims

cp config/config.example.yaml config/config.yaml
chmod 600 config/config.yaml

# 编辑 config/config.yaml，并替换所有占位值。
bash scripts/build-linux-amd64.sh
~~~

构建产物：

~~~text
dist/shannon-ims_linux_amd64
~~~

安装到本机目录：

~~~bash
sudo bash scripts/install-local.sh dist/shannon-ims_linux_amd64 /opt/shannon-ims
sudo /opt/shannon-ims/bin/shannon-ims -c /opt/shannon-ims/config/config.yaml
~~~

检查服务健康状态：

~~~bash
curl http://127.0.0.1:7575/api/health
~~~

### 手动构建

~~~bash
npm ci --prefix web
npm run build --prefix web

rm -rf internal/web/dist
cp -R web/dist internal/web/dist

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -buildvcs=false \
  -tags "with_utls nomsgpack" \
  -o dist/shannon-ims_linux_amd64 ./cmd/vohive
~~~

### 测试与隐私检查

提交或发布前先运行：

~~~bash
python3 scripts/check-repository-privacy.py
~~~

运行关键 Wi-Fi Calling 回归测试：

~~~bash
go test ./internal/sim ./internal/vowifihost
go test ./internal/db -run '^TestEnsureSMSDeliveryPartUniqueIndex'

cd vowifi-go
go test ./internal/vowifi/imscore ./runtimehost/simauth \
  ./internal/vowifi/ipsec3gpp ./runtimehost/voiceclient \
  -run Test -skip '^TestFormatGSMAIMEIURN$'
~~~

### 配置与隐私边界

- 禁止提交 config/config.yaml，Git 中只能保留 config/config.example.yaml。
- 数据库、日志、抓包、崩溃转储、设备身份、用户身份、电话号码、密码和 Token 必须放在仓库外。
- 第一次启动前必须更换 Web 密码。
- IMS 鉴权材料不得打印、粘贴到 Issue 或写入诊断文件。
- 每次推送前检查 git status，并运行仓库隐私检查器。

### Wi-Fi Calling 状态链

健康的注册链路通常依次经过：

~~~text
接入就绪
SWu 隧道就绪
初始 REGISTER
AKA challenge
必要时发送 AUTS 重同步
新的 AKA challenge
安装 IPsec
受保护 REGISTER
IMSReady
SMSReady
~~~

收到 HTTP 或 SIP challenge 不等于最终失败。应沿当前状态迁移诊断，并保留已经证明有效的传输和身份画像。

### 发布版本

推送 v0.1.0 之类的版本标签后，GitHub Actions 会构建 amd64、arm64 和 armv7 Linux 二进制并创建 Release。

~~~bash
git tag v0.1.0
git push origin v0.1.0
~~~

### 安全与合规

本项目为独立研究项目，与任何模组厂商、网络运营商或标准组织均无官方关联。只能对自己有权使用的硬件、账户、网络和目的号码进行测试，并遵守当地法律和运营商条款。

软件按现状提供，不附带任何担保。射频、SIM、eSIM、路由和 IMS 操作可能中断连接，请保留备份和已验证的安全回落流程。

## License / 许可证

This repository is distributed under the [PolyForm Noncommercial License 1.0.0](LICENSE). Commercial use is not permitted without separate authorization.

本仓库采用 [PolyForm Noncommercial License 1.0.0](LICENSE)，仅限非商业用途；商业使用需要另行授权。

<details>
<summary>Upstream project background / 上游项目背景</summary>

# VoHive

[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm--Noncommercial--1.0.0-blue.svg)](https://polyformproject.org/licenses/noncommercial/1.0.0)
[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go)](go.mod)
[![Vue 3](https://img.shields.io/badge/Vue-3-42b883?logo=vue.js)](web/package.json)

> 面向高通 4G/LTE/5G 模组（Quectel EC20/EC25/EC21/EG25/EM20 等）的综合管理与代理服务平台。

VoHive 把模组热插拔管理、SOCKS5/HTTP 代理编排、短信收发、VoWiFi/IMS 通话、eSIM 全生命周期管理整合到一个服务里,并提供一套现代化的响应式 Web 管理后台。

## 核心特性

| 模块 | 说明 |
| --- | --- |
| 多模组并发管理 | USB 热插拔自动发现(ttyUSB 等)、多设备实时状态监控 |
| 轻量级代理引擎 | 内建 SOCKS5 / HTTP 代理内核,支持多实例并发;基于 `SO_BINDTODEVICE` 按设备网卡严格绑定出站流量 |
| 通信与短信中心 | 统一界面/API 处理 AT 短信收发、会话与联系人管理、USSD 交互,短信落库可查 |
| eSIM 管理 | 通过 AT 指令通道直接管理 eSIM 芯片,支持 Profile 下载、启用/停用、重命名、删除 |
| 全渠道通知 | 重要短信及系统告警可推送至 Telegram、Email、PushPlus、Bark、飞书(Lark/Feishu)、QQ 等 |
| 多架构构建 | 原生支持 amd64 / arm64 / arm7 跨平台编译,路由器到边缘节点均可部署 |

## 典型应用场景

- **私有 IP 代理池**:单主机挂载多张物理 SIM 卡或多张 eSIM,每张网卡对应独立的 SOCKS5/HTTP 实例,组建自己的移动网络代理。
- **统一接码/验证码中心**:Web 界面或 API 并行收发多卡短信,并通过 Webhook/Bot 实时推送到个人终端。
- **VoWiFi 零信号通信**:地下室、弱覆盖场景下,借助宽带网络隧道建立 IMS 连接,保证业务不掉线。

## 架构与技术栈

- **Backend**:Go 1.26+(Gin、GORM、Viper、sipgo、euicc-go)
- **Frontend**:Vue 3 + Vite + TailwindCSS + Element Plus
- **Database**:SQLite(`vohive.db`)
- **CI/CD**:GitHub Actions 自动化多架构 Docker 镜像构建与发布


## 免责声明

- **用途定位**:本项目主要面向个人学习、技术研究与功能测试场景,不建议直接用于生产环境或关键业务系统;由此产生的部署及使用风险由使用者自行承担。
- **非官方项目**:VoHive 为第三方独立开发的开源软件,与 Quectel(高通模组厂商)、高通公司及其他任何模组/芯片厂商均无官方关联、授权或合作关系,亦不对模组硬件本身的功能、质量或安全性负责。
- **合规使用**:使用本项目搭建的服务时,请自行确保符合所在地区的法律法规及电信运营商的服务条款,不得用于任何违法违规用途。因违规使用造成的一切法律责任由使用者自行承担,与本项目作者及贡献者无关。
- **无担保**:本软件按"现状"提供,不附带任何明示或暗示的担保,包括但不限于适销性、特定用途适用性及不侵权担保。因使用或无法使用本软件(含数据丢失、设备异常、业务中断等)造成的任何直接或间接损失,作者及贡献者不承担任何责任。

## License

本项目基于 [PolyForm Noncommercial License 1.0.0](LICENSE) 开源,**仅限非商业用途**:可自由查看、使用、修改、分发源码用于个人学习、研究、测试等非商业场景;**禁止任何形式的商业使用**(包括但不限于销售、提供付费服务、用于盈利性产品或业务)。如需商业授权,请联系作者另行协商。

</details>
