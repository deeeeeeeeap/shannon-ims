# Shannon IMS runtime bundle / 运行时包

This archive contains the Shannon IMS application, an example configuration,
deployment checks, and the source for two custom strongSwan plugins. It is not
a self-contained strongSwan distribution: the plugins must be compiled against
the configured source tree that matches the target machine's installed
strongSwan build.

此归档包含 Shannon IMS 主程序、示例配置、部署预检脚本，以及两个自定义
strongSwan 插件的源码。它不是独立的 strongSwan 发行包：自定义插件必须在
目标机器上，针对与已安装 strongSwan 版本和编译选项一致的 configured source
tree 构建。

## Deployment order / 部署顺序

Before extracting a downloaded archive, verify its detached checksum from the
same directory:

```bash
sha256sum -c shannon-ims_v0.1.0_linux_amd64.tar.gz.sha256
```

When the repository verification script is available, it validates the
detached checksum, archive layout, `release-manifest.env`, runtime manifest,
in-bundle `SHA256SUMS`, binary SHA-256, and Linux Go architecture metadata:

```bash
bash scripts/verify-release-bundle.sh \
  --archive shannon-ims_v0.1.0_linux_amd64.tar.gz \
  --arch amd64
```

如可使用仓库中的校验脚本，上述命令会同时验证独立校验文件、归档结构、
`release-manifest.env`、运行时 manifest、归档内 `SHA256SUMS`、二进制
SHA-256 和 Linux 二进制架构，全程不会启动网络或设备访问。

1. Install a matching strongSwan/charon runtime with VICI, the standard
   EAP-AKA and EAP-Identity plugins, and kernel-netlink. The default userspace
   dataplane also requires kernel-libipsec and a usable `/dev/net/tun`.
2. Obtain the exact matching strongSwan source and run its normal `./configure`
   step with options compatible with the installed runtime. `config.h` must
   exist before the custom plugins are built.
3. Build, but do not yet install, the custom plugins:

   ```bash
   bash scripts/build-strongswan-plugins.sh \
     --strongswan-src /path/to/configured/strongswan \
     --ipsec-lib-dir /usr/lib/ipsec \
     --output dist/strongswan-plugins
   ```

4. Verify `dist/strongswan-plugins/SHA256SUMS`, then install both `.so` files
   into the plugin directory belonging to that strongSwan runtime. A common
   Debian/Ubuntu path is `/usr/lib/ipsec/plugins`; use the actual path reported
   by the target installation.

   ```bash
   (cd dist/strongswan-plugins && sha256sum -c SHA256SUMS)
   sudo install -m 0755 \
     dist/strongswan-plugins/libstrongswan-eap-aka-vohive.so \
     dist/strongswan-plugins/libstrongswan-p-cscf-vohive.so \
     /usr/lib/ipsec/plugins/
   ```
5. Run the read-only preflight as the same privileged user that will run the
   service:

   ```bash
   sudo bash scripts/check-runtime-deps.sh
   ```

   For non-standard layouts, set `SHANNON_CHARON_BIN`, `SHANNON_PLUGIN_DIR`,
   `SHANNON_STRONGSWAN_CONF`, and `SHANNON_STRONGSWAN_CONF_DIR` to the target
   runtime's actual paths. Pass the same environment when invoking
   `install-local.sh`, because the installer repeats the preflight before it
   writes any files.

6. Only after `runtime_preflight=pass`, install the application:

   ```bash
   sudo bash scripts/install-local.sh bin/shannon-ims /opt/shannon-ims
   ```

7. Edit `/opt/shannon-ims/config/config.yaml`, replace every placeholder, and
   set a new Web password before the first start. Empty passwords, the legacy
   default, and placeholder values are rejected before the network service
   starts.

   编辑 `/opt/shannon-ims/config/config.yaml`，替换全部 placeholder，并在首次
   启动前设置新的 Web 密码。空密码、旧默认密码和 placeholder 都会触发
   fail-closed，网络服务不会启动。

8. On the first valid start, the application creates
   `/opt/shannon-ims/data/session-secret` with mode `0600`; the installer keeps
   `data/` at mode `0700`. This independent signing secret is reused across
   restarts and is not stored in YAML or included in the archive. Preserve it
   during in-place upgrades. Deleting it while the service is stopped
   intentionally invalidates all sessions and generates a new secret on the
   next start. Do not commit or share it between deployments.

   首次通过安全检查的启动会创建权限为 `0600` 的
   `/opt/shannon-ims/data/session-secret`，安装器将 `data/` 保持为 `0700`。
   此独立签名密钥不会写入 YAML 或归档，并会在重启后复用。原地升级时应保留；
   若在服务停止后删除它，现有会话会全部失效，下次启动会生成新密钥。不要提交
   或在不同部署之间共享该文件。

The application supervises charon itself. It writes
`/etc/strongswan.d/91-vohive-swu.conf`, uses `/run/charon.vici`, and creates the
AKA/P-CSCF bridge sockets under `/run`. Do not run another charon instance that
owns the same VICI socket.

应用会自行监管 charon，写入 `/etc/strongswan.d/91-vohive-swu.conf`，使用
`/run/charon.vici`，并在 `/run` 下创建 AKA/P-CSCF bridge socket。不要同时启动
另一个占用相同 VICI socket 的 charon 实例。
