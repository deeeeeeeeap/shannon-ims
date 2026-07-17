# Shannon IMS Web Console

Shannon IMS 的 Web 管理界面，基于 Vue 3、TypeScript、Vite、Pinia、Element Plus 和 ECharts。它负责展示模组、网络、Wi‑Fi Calling/IMS、短信、代理、日志和系统设置等运行状态，并通过后端 `/api` 接口执行经过鉴权的管理操作。

The Shannon IMS management console is built with Vue 3, TypeScript, Vite, Pinia, Element Plus, and ECharts. It presents modem, network, Wi‑Fi Calling/IMS, SMS, proxy, log, and system state, and uses authenticated backend routes under `/api` for management actions.

## 本地开发 / Local development

后端默认监听 `http://127.0.0.1:7575`，Vite 开发服务器默认监听 `http://127.0.0.1:5173`。开发代理只转发 `/api`；可通过 `VITE_API_PROXY_TARGET` 指向其他本地后端。

```bash
npm ci
npm run dev
```

PowerShell 示例：

```powershell
$env:VITE_API_PROXY_TARGET='http://127.0.0.1:7575'
npm run dev
```

后端公开的进程存活检查是：

```bash
curl -fsS http://127.0.0.1:7575/ping
```

`/api/*` 路由需要先登录并携带 Bearer token。

## 质量检查 / Quality checks

```bash
npm run lint
npm run typecheck
npm run build
```

`npm run build` 会先执行 TypeScript/Vue 类型检查，再把静态资源输出到 `web/dist`。仓库的主构建脚本随后将该目录同步到 `internal/web/dist`，由 Go 服务嵌入并托管。

## 项目文档 / Project documentation

完整的架构、构建、strongSwan 运行时和部署说明见 [../README.md](../README.md)。Release 运行时包说明见 [../packaging/runtime/README.md](../packaging/runtime/README.md)。
