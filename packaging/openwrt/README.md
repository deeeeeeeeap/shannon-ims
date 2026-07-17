# OpenWrt packaging status / OpenWrt 包装状态

## Not supported

This release does not ship or support an OpenWrt package. The former init/config
fragments used a split layout across `/usr`, `/etc`, and `/var/lib`; that layout
is incompatible with the application's single absolute runtime-root and
fail-closed uninstall guarantees. Those deployable fragments were therefore
removed instead of being left as an apparently working package.

The supported release path is the verified Linux runtime bundle documented in
the repository root; CI performs the full bundle smoke test on amd64. Restoring
OpenWrt support requires a complete package recipe, a documented data migration,
package-manager-owned uninstall behavior, and CI coverage on the target layout.

Existing manual OpenWrt installations should back up their configuration and
runtime data before migration. Do not reuse the removed init script without
first defining and testing those ownership and migration rules.

## 当前不受支持

本版本不提供、也不支持 OpenWrt 安装包。旧 init/config 片段把文件分散在
`/usr`、`/etc` 和 `/var/lib`，与当前“单一绝对 runtime root”以及卸载
fail-closed 的安全约束不一致，因此已移除这些可部署片段，避免它们继续以
“似乎可用”的形式误导部署。

当前受支持的发布方式是仓库根目录文档中经过验证的 Linux runtime bundle，CI
会对 amd64 执行完整 bundle smoke。若未来恢复 OpenWrt 支持，必须同时提供完整
包配方、明确的数据迁移、由包管理器负责的卸载语义，以及针对目标布局的 CI 验证。

已有手工 OpenWrt 部署在迁移前应备份配置和运行数据。在上述所有权与迁移规则
完成并经过测试前，请勿复用已移除的 init 脚本。
