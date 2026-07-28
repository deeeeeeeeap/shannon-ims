# swu-go

纯 Go 实现的 SWu 客户端库，适用于 VoWiFi 建立到 ePDG (Evolved Packet Data Gateway) 的 IPSec 隧道。

## 功能特性

### 核心协议
- **IKEv2** — 完整实现 IKE_SA_INIT、IKE_AUTH、CREATE_CHILD_SA、INFORMATIONAL
- **EAP-AKA 认证** — 支持 SIM/USIM 卡认证，含同步失败 (AUTS) 处理
- **COOKIE 处理** — RFC 7296 §2.6 防 DoS 机制
- **IKE Fragmentation** — RFC 7383 大消息分片传输，防止被防火墙丢弃

### SA 生命周期管理
- **Child SA Rekey** — 主动 + 被动，含碰撞检测 (TryLock)
- **IKE SA Rekey** — 主动 + 被动，DH 密钥交换刷新
- **IKE Reauthentication** — RFC 7296 §2.8.3 完全重认证
- **EAP-AKA Fast Re-auth** — RFC 4187 0-RTT 极速伪装重认证，免 SIM 强验
- **Session Resumption** — RFC 5723 跨会话凭证漂流保护与快速恢复
- **AUTH Lifetime** — RFC 4478 动态适配 ePDG 通告的 SA 生命周期
- **Soft/Hard Expire** — XFRM 内核事件驱动的 SA 过期处理
- **DPD** — RFC 3706 Dead Peer Detection

### 网络适应性
- **Smart DPD** — 基于 XFRM 底层流量感知的智能死穴检测 (Dead Peer Detection)
- **NAT-T** — ESP-in-UDP 封装 + Keepalive
- **MOBIKE** — RFC 4555 网络切换（WiFi ↔ 4G）无感迁移
- **IKE Redirect** — RFC 5685 ePDG 负载均衡重定向
- **Message ID 同步** — RFC 6311 长连接 ID 同步

### 数据平面
- **XFRMI 模式** — 内核态 XFRM Interface（推荐，性能最优）
- **TUN 模式** — 用户态 ESP 加解密
- **可配置 Replay Window** — 支持 32/128/256 窗口大小
- **ESN** — RFC 4303 64 位扩展序列号（可选）
- **SA Direction** — `XFRMA_SA_DIR` 内核精细管理（Linux 6.x+）

### 网络配置
- **自动接口配置** — 策略路由、冲突路由清理、sysctl 管理
- **IPv4/IPv6 双栈** — 完整双栈支持
- **网络命名空间** — 可选的隔离网络环境

## 安装

```bash
go get github.com/iniwex5/swu-go
```

## 依赖

- Go 1.24+
- Linux（需要 XFRM / TUN/TAP / Netlink 支持）
- Root 权限（网络配置需要）
- [github.com/iniwex5/netlink](https://github.com/iniwex5/netlink) — vishvananda/netlink 的 fork，增加了 `XFRM_STATE_AF_UNSPEC`、`XFRMA_SA_DIR`、`ESN` 支持

## 配置项

```go
type Config struct {
    EpDGAddr      string          // ePDG 地址
    EpDGPort      uint16          // ePDG 端口 (默认 500)
    APN           string          // 接入点名称
    SIM           sim.SIMProvider // SIM 卡提供者
    DataplaneMode string          // "xfrmi" (推荐) 或 "tun"
    TUNName       string          // 接口设备名 (默认 "ipsec0")

    // 流量与生存期管理
    ReauthInterval int  // IKE SA 重认证间隔（秒），0=禁用
    ReplayWindow   int  // XFRM 抗重放窗口 (默认 32, 建议 128/256)
    EnableESN      bool // 启用 64 位扩展序列号 (默认 false)

    // RFC 5723 Ticket 凭证漂流保护
    ResumeTicket   []byte
    ResumeOldSKd   []byte
    OnTicketUpdate func(ticket, skd []byte)

    // 0-RTT 极速重建缓存 (可选，对接外层应用存储)
    FastReauthID       string // ePDG 赋予的下次断线重连假名
    FastReauthMK       []byte // 上次全量认证协商的根密钥
    FastReauthKAut     []byte
    FastReauthKEncr    []byte
    OnFastReauthUpdate func(reauthID string, mk, kAut, kEncr []byte)
}
```

## 使用示例

```go
package main

import (
    "context"
    "github.com/iniwex5/swu-go/pkg/swu"
    "github.com/iniwex5/swu-go/pkg/sim"
)

func main() {
    simProvider := sim.NewATModem("/dev/ttyUSB2")

    cfg := &swu.Config{
        EpDGAddr:      "epdg.example.com",
        APN:           "ims",
        SIM:           simProvider,
        DataplaneMode: "xfrmi",
        TUNName:       "ims0",
        ReplayWindow:  128,
    }

    session := swu.NewSession(cfg, nil)
    defer session.Shutdown()

    if err := session.Connect(context.Background()); err != nil {
        panic(err)
    }

    // 会话建立后，XFRM 接口已配置完成
    // 可以通过 ims0 接口访问 IMS 网络

    session.WaitDone()
}
```

## 项目结构

```
pkg/
├── crypto/     # 加密算法 (AES-CBC, AES-GCM, HMAC, DH, PRF)
├── driver/     # 系统驱动
│   ├── nettools.go    # 网络配置 (netlink API)
│   ├── xfrm.go        # XFRM SA/SP/Interface 管理
│   ├── xfrm_algo.go   # 算法 ID 映射
│   ├── netns.go        # 网络命名空间
│   └── tun.go          # TUN 设备
├── eap/        # EAP-AKA 协议编解码
├── ikev2/      # IKEv2 协议 (载荷编解码、常量、SA 协商)
├── ipsec/      # ESP 数据平面与 Socket 管理
├── logger/     # 日志封装 (zap)
├── sim/        # SIM 卡接口 (AT 命令)
└── swu/        # SWu 会话管理
    ├── session.go          # 核心会话逻辑 + 数据平面配置
    ├── config.go           # 配置结构体
    ├── state_init.go       # IKE_SA_INIT + COOKIE + REDIRECT
    ├── state_auth.go       # IKE_AUTH + EAP-AKA + AUTH_LIFETIME
    ├── state_rekey.go      # Child SA Rekey (主动)
    ├── state_rekey_ike.go  # IKE SA Rekey (主动 + 被动)
    ├── ike_control.go      # ePDG 发起的请求分发 (Rekey/Delete/MID Sync)
    ├── informational.go    # 智能流量感知 DPD、Delete 通知
    ├── mobike.go           # MOBIKE 地址更新 (RFC 4555)
    ├── fragment.go         # IKE Fragmentation (RFC 7383)
    ├── cookie.go           # COOKIE 处理
    ├── msg_handler.go      # 消息加解密与收发
    └── retry.go            # 重传机制
```

## 许可证

MIT License
