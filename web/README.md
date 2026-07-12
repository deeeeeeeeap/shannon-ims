# Web 管理界面（Vue 3 + Vite）

该目录是 EC20 4G Proxy Manager 的前端工程，提供设备状态、短信、代理实例（sing-box）等管理功能。

## 依赖与约定

- 后端默认监听 `:7575`，API 前缀为 `/api`。
- 前端开发服务器默认监听 `:5173`，并通过 Vite 代理把 `/api` 转发到 `http://127.0.0.1:7575`（见 [vite.config.ts](file:///root/ec20/go-4gproxy/web/vite.config.ts)）。

## 开发运行

```bash
npm i
npm run dev
```

默认访问 `http://127.0.0.1:5173/`。

如需在远程/容器里对外暴露，可使用：

```bash
npm run dev -- --host 0.0.0.0 --port 5174
```

## 构建

```bash
npm run build
```

构建产物输出到 `web/dist`。后端会读取该目录并把它作为 SPA 静态资源托管（未命中路由时回落到 `index.html`）。

## 相关文档

- 后端与整体项目说明见 [../README.md](file:///root/ec20/go-4gproxy/README.md)
