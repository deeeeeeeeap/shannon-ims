package api

import (
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/1239t/vohive/internal/config"
	"github.com/1239t/vohive/internal/updater"
	"github.com/1239t/vohive/pkg/logger"
	"github.com/gin-gonic/gin"
)

var errNotFound = errors.New("not found")

const uninstallConfirmation = "UNINSTALL"

// resolveUninstallTargets 计算自毁流程需要清理的数据目录和配置文件路径。
// 配置文件路径必须来自运行时实际加载的路径（config.GetConfigPath()），
// 不能假定其固定位于进程工作目录下的 "config" 子目录——
// OpenWrt 部署通过 -c 显式传入 /etc/vohive/config.yaml，与工作目录无关，
// 用硬编码相对路径删除会删错地方（实际等于什么都没删）。
// configPath 为空（配置管理器未初始化）时不返回任何配置文件路径，避免误删。
func resolveUninstallTargets(configPath string) (dataDir string, configFile string) {
	return "data", configPath
}

// detectServiceStopCommands 根据当前部署形态返回应执行的"停止 + 禁用自启"命令。
// systemd 的 Restart=always 和 OpenWrt procd 的 respawn 都只在进程
// "非主动" 退出时才会重新拉起；只要在自毁前显式请求服务管理器停止/禁用，
// 即使后续删除可执行文件失败（例如只读 squashfs），也不会被重新拉起。
// 仅靠"删掉自己导致 exec 失败"这种副作用来阻止重启是不可靠的。
func detectServiceStopCommands(lookPath func(string) (string, error), statFile func(string) bool) [][]string {
	var cmds [][]string
	if statFile("/etc/init.d/vohive") {
		cmds = append(cmds, []string{"/etc/init.d/vohive", "disable"})
		cmds = append(cmds, []string{"/etc/init.d/vohive", "stop"})
		return cmds
	}
	if _, err := lookPath("systemctl"); err == nil {
		cmds = append(cmds, []string{"systemctl", "disable", "--now", "vohive"})
	}
	return cmds
}

// handleCheckUpdate 检查系统更新
func (s *Server) handleCheckUpdate(c *gin.Context) {
	info, err := updater.CheckUpdate()
	if err != nil {
		logger.Error("检查系统更新失败", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, info)
}

// handleApplyUpdate 应用系统更新
func (s *Server) handleApplyUpdate(c *gin.Context) {
	if err := updater.ApplyUpdate(); err != nil {
		if errors.Is(err, updater.ErrAutomaticUpdateDisabled) {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status":  "error",
				"code":    "automatic_update_disabled",
				"message": err.Error(),
			})
			return
		}
		logger.Error("应用更新失败", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"status":  "error",
			"code":    "update_failed",
			"message": "应用更新失败",
		})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"message": "正在后台下载更新，系统稍后将自动重启..."})
}

// handleUninstall is a local-only, authenticated uninstall boundary.
func (s *Server) handleUninstall(c *gin.Context) {
	if !isLoopbackRequest(c.Request) {
		c.JSON(http.StatusForbidden, gin.H{
			"status":     "error",
			"code":       "uninstall_local_only",
			"message":    "卸载操作仅允许从本机发起",
			"request_id": requestID(c),
		})
		return
	}

	var req struct {
		Confirm string `json:"confirm"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Confirm) != uninstallConfirmation {
		c.JSON(http.StatusBadRequest, gin.H{
			"status":  "error",
			"code":    "uninstall_confirmation_required",
			"message": "卸载操作需要明确确认",
		})
		return
	}

	logger.Warn("本机管理员已确认卸载，正在执行卸载逻辑")
	c.JSON(http.StatusAccepted, gin.H{"message": "正在卸载软件..."})
	s.startUninstall()
}

func isLoopbackRequest(req *http.Request) bool {
	if req == nil {
		return false
	}
	host := strings.TrimSpace(req.RemoteAddr)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) startUninstall() {
	runner := runDefaultUninstall
	if s != nil && s.uninstallRunner != nil {
		runner = s.uninstallRunner
	}
	go runner()
}

func runDefaultUninstall() {
	time.Sleep(1 * time.Second)

	// 先主动通知服务管理器停止 + 禁用自启，确保即使后面的文件删除
	// 失败（只读文件系统等），systemd Restart=always / procd respawn
	// 也不会把进程重新拉起来。命令异步触发(Start 不 Wait)，
	// 避免对"停止自己"这条命令的等待造成死锁。
	for _, args := range detectServiceStopCommands(exec.LookPath, fileExists) {
		cmd := exec.Command(args[0], args[1:]...)
		if err := cmd.Start(); err != nil {
			logger.Warn("通知服务管理器停止失败", "cmd", args, "err", err)
			continue
		}
		go cmd.Wait()
	}

	dataDir, configFile := resolveUninstallTargets(config.GetConfigPath())

	if err := os.RemoveAll(dataDir); err != nil {
		logger.Warn("清理数据目录失败", "dir", dataDir, "err", err)
	}
	if configFile != "" {
		if err := os.Remove(configFile); err != nil && !os.IsNotExist(err) {
			logger.Warn("清理配置文件失败", "file", configFile, "err", err)
		}
	}
	if executable, err := os.Executable(); err == nil {
		if err := os.Remove(executable); err != nil {
			logger.Warn("删除可执行文件失败", "file", executable, "err", err)
		}
	}

	logger.Warn("自毁流程结束，退出进程")
	os.Exit(0)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
