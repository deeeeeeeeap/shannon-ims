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
  <a href="https://github.com/deeeeeeeeap/shannon-ims/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/deeeeeeeeap/shannon-ims/actions/workflows/ci.yml/badge.svg"></a>
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
- 默认、空白、`admin` 或示例 placeholder Web 密码会使服务拒绝启动；
- Session token 使用独立随机密钥签名，不复用 Web 密码。标准部署首次启动会在 `data/session-secret` 创建权限为 `0600` 的密钥文件，重启后稳定复用；
- 控制台、文件、SSE 和 IMS 子模块共用集中脱敏边界，电话号码、设备/SIM 身份、Token、短信正文和鉴权材料只保留状态、长度或不可逆指纹；
- Web 密码、通知 Token 和第三方凭据由本地配置管理。

### 运行环境

| 项目 | 建议 |
| --- | --- |
| 操作系统 | Linux 或 WSL2 |
| Go | 1.26.3 或更高版本 |
| Node.js | 22 或更高版本 |
| 模组 | 支持 QMI、MBIM 或 AT 的 LTE / 5G 模组 |
| 运行权限 | 当前受支持的部署方式使用 root；需要 raw socket、TUN、ESP、路由、设备访问，以及写入 `/etc/strongswan.d` 和 `/run` 的权限 |
| SWu 组件 | 与目标机版本匹配的 strongSwan/charon、VICI、标准 EAP-AKA/EAP-Identity、kernel-netlink、默认 userspace 数据面所需的 kernel-libipsec，以及项目的 EAP-AKA/P-CSCF 插件 |
| SIM | 有效 SIM，且账户允许使用相应 IMS 服务 |

> Go 二进制不是完整的 Wi‑Fi Calling 运行时。两个自定义 strongSwan 插件必须针对目标机实际安装版本的 configured source tree 构建。部署前请运行 `scripts/check-runtime-deps.sh`；只有输出 `runtime_preflight=pass` 才表示运行时依赖闭环。

### 发布候选稳定性基线

`v0.1.0-rc.1` 将当前协议实现收口为可持续验证的 RC 基线：根模块和 `vowifi-go` 全量测试/vet、关键并发模块 race、前端 lint/typecheck/build、隐私扫描、运行时脚本测试以及 Linux amd64 归档 smoke 都进入 push/PR CI。发布包同时包含 `release-manifest.env`、运行时 manifest、归档内 `SHA256SUMS` 和独立 `.sha256` 文件。

本轮只收紧 SA 所有权、测试夹具、持续验证和发布归档，不改变已验证的 IMS-AKA、AUTS、3GPP IPsec、短信或 eSIM 协议行为。详见 [RELEASE_NOTES.md](RELEASE_NOTES.md) 和 [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)。

<a id="快速开始"></a>

## 快速开始

### 1. 获取源码

~~~bash
git clone git@github.com:deeeeeeeeap/shannon-ims.git
cd shannon-ims
~~~

### 2. 构建 Linux amd64

~~~bash
bash scripts/build-linux-amd64.sh
~~~

构建产物：

~~~text
dist/shannon-ims_linux_amd64
~~~

### 3. 准备 strongSwan 运行时

先安装与目标系统匹配的 strongSwan/charon、VICI、标准 EAP-AKA/EAP-Identity、kernel-netlink 和 kernel-libipsec，并停止发行版自动启动的 charon/strongSwan 服务；Shannon IMS 会独占 `/run/charon.vici` 并自行监管 charon。然后使用**与已安装运行时版本及编译选项一致**、已经生成 `config.h` 的 strongSwan source tree 构建两个自定义插件：

~~~bash
bash scripts/build-strongswan-plugins.sh \
  --strongswan-src /path/to/configured/strongswan \
  --ipsec-lib-dir /usr/lib/ipsec \
  --output dist/strongswan-plugins
~~~

校验并安装插件。以下目录是 Debian/Ubuntu 常见路径，其他系统请使用该 strongSwan 实际的 plugin directory：

~~~bash
(cd dist/strongswan-plugins && sha256sum -c SHA256SUMS)
sudo install -m 0755 \
  dist/strongswan-plugins/libstrongswan-eap-aka-vohive.so \
  dist/strongswan-plugins/libstrongswan-p-cscf-vohive.so \
  /usr/lib/ipsec/plugins/
sudo bash scripts/check-runtime-deps.sh
~~~

预检会只输出检查项和状态，不打印主机路径、用户身份、设备身份、凭据或 IMS-AKA 材料。非标准布局可通过 `SHANNON_CHARON_BIN`、`SHANNON_PLUGIN_DIR`、`SHANNON_STRONGSWAN_CONF` 和 `SHANNON_STRONGSWAN_CONF_DIR` 指定实际位置。

### 4. 安装并准备首次启动

~~~bash
sudo bash scripts/install-local.sh \
  dist/shannon-ims_linux_amd64 \
  /opt/shannon-ims
~~~

安装器会再次执行运行时预检；预检失败时不会写入安装目录。首次安装会从 `config/config.example.yaml` 创建权限为 `0600` 的本地配置，并把 `data/` 设为 `0700`；已有配置不会被覆盖。

首次启动前编辑配置，替换所有 placeholder，至少设置新的 Web 登录密码，并按实际模组填写设备配置：

~~~bash
sudoedit /opt/shannon-ims/config/config.yaml
~~~

如果 Web 密码仍为空、为旧默认值 `admin`，或仍是 `CHANGE_ME_BEFORE_FIRST_RUN` 等 placeholder，Shannon IMS 会 fail-closed 并在启动网络服务前退出。不要把本地配置中的密码复制回源码仓库。

首次通过安全检查的启动会自动生成 `/opt/shannon-ims/data/session-secret`，文件权限为 `0600`。它不需要写入 YAML，也不会进入 Release 包。原地升级时应保留该文件以维持现有登录会话；如需主动使全部会话失效，可在服务停止后删除它，下一次启动会生成新密钥。不同部署实例不应共享此文件。

启动：

~~~bash
sudo /opt/shannon-ims/bin/shannon-ims \
  -c /opt/shannon-ims/config/config.yaml
~~~

健康检查：

~~~bash
curl -fsS http://127.0.0.1:7575/ping
~~~

`/ping` 是无需登录的进程存活检查；`/api/*` 管理接口需要登录后携带 Bearer token。

### 从 Release 部署

版本标签会触发 GitHub Actions，为 Linux amd64、arm64 和 armv7 生成 `.tar.gz` 运行时归档及独立 SHA-256 文件。归档包含主程序、示例配置、预检/安装/校验脚本、自定义插件源码、发布 manifest 和运行时 manifest，因此目标机无需前端工具链；但仍必须针对目标机 strongSwan 构建并安装插件。

~~~bash
sha256sum -c shannon-ims_v0.1.0-rc.1_linux_amd64.tar.gz.sha256
bash scripts/verify-release-bundle.sh \
  --archive shannon-ims_v0.1.0-rc.1_linux_amd64.tar.gz \
  --arch amd64
~~~

完整顺序见 [packaging/runtime/README.md](packaging/runtime/README.md) 和 [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md)。

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
- Empty, legacy-default, and placeholder Web passwords fail closed before the network service starts.
- Session tokens are signed with an independent random secret. Standard installs create `data/session-secret` with mode `0600` and reuse it across restarts.
- Console, file, SSE, and embedded IMS logs share one redaction boundary for phone numbers, device/SIM identities, tokens, message bodies, and authentication material.

### Release candidate stability baseline

`v0.1.0-rc.1` is the continuously verifiable RC baseline. Push and pull-request CI now runs full tests and vet for both Go modules, race tests for critical concurrency packages, frontend lint/typecheck/build, privacy and runtime contract checks, plus a Linux amd64 release-bundle smoke test. Every archive carries `release-manifest.env`, the runtime manifest, in-bundle `SHA256SUMS`, and a detached `.sha256` file.

This hardening round changes SA ownership, stale test fixtures, continuous verification, and release packaging only. It does not change the validated IMS-AKA, AUTS, 3GPP IPsec, SMS, or eSIM protocol behavior. See [RELEASE_NOTES.md](RELEASE_NOTES.md) and [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).

<a id="quick-start"></a>

## Quick Start

~~~bash
git clone git@github.com:deeeeeeeeap/shannon-ims.git
cd shannon-ims
bash scripts/build-linux-amd64.sh
~~~

Install a matching strongSwan/charon runtime with VICI, the standard EAP-AKA
and EAP-Identity plugins, kernel-netlink, and kernel-libipsec, then stop any
distribution-managed charon/strongSwan service.
Shannon IMS owns `/run/charon.vici` and supervises charon itself. Build the two
custom plugins against the configured source tree that exactly matches that
runtime:

~~~bash
bash scripts/build-strongswan-plugins.sh \
  --strongswan-src /path/to/configured/strongswan \
  --ipsec-lib-dir /usr/lib/ipsec \
  --output dist/strongswan-plugins

(cd dist/strongswan-plugins && sha256sum -c SHA256SUMS)
sudo install -m 0755 \
  dist/strongswan-plugins/libstrongswan-eap-aka-vohive.so \
  dist/strongswan-plugins/libstrongswan-p-cscf-vohive.so \
  /usr/lib/ipsec/plugins/
sudo bash scripts/check-runtime-deps.sh
~~~

The plugin directory above is common on Debian/Ubuntu; use the directory from
the target strongSwan installation on other systems. A Go binary alone is not
a complete Wi-Fi Calling runtime. For non-standard layouts, pass the actual
locations through `SHANNON_CHARON_BIN`, `SHANNON_PLUGIN_DIR`,
`SHANNON_STRONGSWAN_CONF`, and `SHANNON_STRONGSWAN_CONF_DIR` when running the
preflight and installer.

Install the application only after the preflight reports
`runtime_preflight=pass`:

~~~bash
sudo bash scripts/install-local.sh \
  dist/shannon-ims_linux_amd64 \
  /opt/shannon-ims

sudoedit /opt/shannon-ims/config/config.yaml

sudo /opt/shannon-ims/bin/shannon-ims \
  -c /opt/shannon-ims/config/config.yaml
~~~

Replace every placeholder and set a new Web password before the first start.
The installer preserves an existing configuration and creates `data/` with
mode `0700`. Startup is refused while the Web password is empty, still set to
the legacy default, or still a placeholder.

On the first valid start, Shannon IMS creates
`/opt/shannon-ims/data/session-secret` with mode `0600`. The secret is separate
from the Web password and is reused after restart. Preserve it during in-place
upgrades; deleting it while the service is stopped intentionally invalidates
all existing sessions and causes a new secret to be generated. Do not commit,
publish, or share this file between deployments.

Health check:

~~~bash
curl -fsS http://127.0.0.1:7575/ping
~~~

`/ping` is public process liveness. Management routes under `/api/*` require an
authenticated Bearer token.

### Compatibility notes

A valid IMS protocol implementation does not guarantee service activation for every subscription. Carrier policy, account provisioning, regional access, SIM capabilities, modem firmware, and network topology all affect the result.

Use Shannon IMS only with hardware, subscriptions, networks, and destination numbers you are authorized to test.

## Build verification / 构建验证

The same matrix is enforced by `.github/workflows/ci.yml` on pushes and pull requests. 本地等价验证命令如下：

~~~bash
go test ./... -count=1
go vet ./...

(cd vowifi-go && go test ./... -count=1)
(cd vowifi-go && go vet ./...)

go test -race \
  ./internal/apduarbiter \
  ./internal/device \
  ./internal/vowifihost \
  ./pkg/logger \
  -count=1

(cd vowifi-go && go test -race \
  ./internal/vowifi/ipsec3gpp \
  ./internal/vowifi/imscore \
  ./runtimehost/simauth \
  ./runtimehost/voiceclient \
  -count=1)

npm ci --prefix web
npm run lint --prefix web
npm run typecheck --prefix web
npm run build --prefix web

python3 scripts/check-repository-privacy.py
python3 -m unittest discover -s scripts/tests -p 'test_*.py'
bash scripts/tests/check-runtime-deps_test.sh
bash scripts/tests/build-strongswan-plugins_test.sh
bash scripts/tests/install-local_test.sh
bash scripts/tests/package-release-bundle_test.sh
bash scripts/tests/verify-release-bundle_test.sh
~~~

## Releases

Push a semantic version tag to build runtime-aware Linux archives for amd64,
arm64, and armv7:

~~~bash
git tag v0.1.0
git push origin v0.1.0
~~~

Each release archive includes the application, example configuration,
deployment and verification scripts, custom-plugin source, release/runtime
manifests, internal checksums, and a detached archive checksum. It intentionally
does not ship target-independent custom plugin binaries: build those against
the target's matching strongSwan source, then require the preflight to pass.
See [packaging/runtime/README.md](packaging/runtime/README.md) and
[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).

## Credits and license

Shannon IMS combines and extends the VoHive service, an embedded Wi‑Fi Calling core, and a locally maintained SIP transport layer. Attribution and required notices are available in [NOTICE.md](NOTICE.md).

The repository is distributed under the [PolyForm Noncommercial License 1.0.0](LICENSE). Commercial use requires separate authorization.

This is an independent research project and is not affiliated with any modem vendor, mobile network operator, or standards organization.
