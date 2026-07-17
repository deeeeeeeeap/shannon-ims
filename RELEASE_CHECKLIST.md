# Release and deployment checklist / 发布与部署验证清单

## 发布前 / Before release

- [ ] `config/config.yaml`、运行数据库、日志、抓包和 session secret 不在仓库或归档中。 / Runtime config, databases, logs, captures, and session secrets are absent from the repository and archive.
- [ ] 根模块与 `vowifi-go` 的 `go test ./...`、`go vet ./...` 全部通过。 / Full test and vet pass for both Go modules.
- [ ] `.github/workflows/ci.yml` 中列出的关键模块 `-race` 零告警。 / Critical race suites in CI report no warnings.
- [ ] 前端在 `package-lock.json` 下完成 `npm ci`、lint、typecheck 和 build。 / Frontend install, lint, typecheck, and build pass from the lockfile.
- [ ] 隐私扫描、Python 合约测试和全部 `scripts/tests/*` 发布/运行时测试通过。 / Privacy, Python contracts, and release/runtime script tests pass.
- [ ] runtime root/卸载越界、ESP 坏 ICV replay、登录代理头绕过与限流容量回归测试通过。 / Runtime-root deletion bounds, ESP bad-ICV replay, proxy-header bypass, and limiter-capacity regressions pass.
- [ ] Linux amd64 二进制以目标版本构建，归档由 `package-release-bundle.sh` 生成。 / The Linux amd64 binary is built with the target version and packaged by the release script.
- [ ] `verify-release-bundle.sh` 输出 `bundle_smoke=pass`，并记录归档与二进制 SHA-256。 / Bundle verification passes and both hashes are recorded.

## 目标机部署前 / Before target deployment

- [ ] 使用独立 `.sha256` 验证下载归档，再验证归档内 `SHA256SUMS` 和 `release-manifest.env`。 / Verify the detached archive checksum, in-bundle checksums, and release manifest.
- [ ] strongSwan/charon 版本、configured source、插件目录和编译选项相互匹配。 / strongSwan runtime, configured source, plugin directory, and build options match.
- [ ] 两个自定义插件已构建、校验并安装，且没有其他 charon 占用 VICI socket。 / Both custom plugins are built, verified, installed, and no other charon owns the VICI socket.
- [ ] `scripts/check-runtime-deps.sh` 输出 `runtime_preflight=pass`。 / Runtime preflight passes.
- [ ] 从 `config.example.yaml` 创建本地 `config.yaml`，替换全部 placeholder 并设置新的 Web 密码。 / Create local config from the example, replace placeholders, and set a new Web password.
- [ ] `data/` 权限为 `0700`；首次有效启动后 `data/session-secret` 为 `0600`。 / Data directory and session-secret permissions are correct.
- [ ] 从安装根目录启动，并确认数据库、日志和运营商覆盖位于该绝对 runtime root。 / Start from the installation root and confirm mutable runtime files remain under it.

## 启动后 / After startup

- [ ] `/ping` 返回成功，管理 API 仍要求 Bearer token。 / Liveness succeeds and management APIs remain authenticated.
- [ ] 日志只包含状态、长度、布尔值和不可逆指纹，不包含身份、号码、Token 或 AKA 材料。 / Logs contain safe diagnostics only.
- [ ] 如需真实网络验收，按授权范围单独验证模组、SIM、SWu、IMS 和短信；RC 构建验证本身不触发这些操作。 / Run live modem/network acceptance separately and only when authorized.
