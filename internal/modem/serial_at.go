package modem

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/1239t/vohive/internal/config"

	"go.bug.st/serial"
)

// serialATDrainLimit 限制发送命令前清空输入缓冲区所花的时间：端口上有持续上报时，
// 缓冲区永远读不空。
const serialATDrainLimit = 500 * time.Millisecond

// SerialAT 是一个轻量级的串口包装器，用于在不实例化整个 Manager 的情况下执行简单的 AT 命令
type SerialAT struct {
	port serial.Port
}

// OpenSerialAT 按给定的串口参数打开串口并返回 SerialAT 实例
func OpenSerialAT(portName string, settings config.SerialSettings) (*SerialAT, error) {
	port, err := openSerialPort(portName, serialMode(settings))
	if err != nil {
		return nil, err
	}

	// 设置默认超时
	if err := port.SetReadTimeout(time.Second); err != nil {
		port.Close()
		return nil, err
	}

	return &SerialAT{port: port}, nil
}

// Close 关闭串口
func (s *SerialAT) Close() error {
	return s.port.Close()
}

// Execute 发送 AT 命令并等待响应。返回的文本是模组的原始输出，模组用 ERROR、
// +CME ERROR 或 +CMS ERROR 拒绝命令时同样算作已收到响应；只有在超时或串口读写失败时才返回错误，
// 此时已经收到的内容仍然一并返回。
func (s *SerialAT) Execute(cmd string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	// 临时调整超时
	if err := s.port.SetReadTimeout(100 * time.Millisecond); err != nil {
		return "", err
	}

	// 清空缓冲区
	buf := make([]byte, 1024)
	drainDeadline := time.Now().Add(serialATDrainLimit)
	for time.Now().Before(drainDeadline) {
		n, _ := s.port.Read(buf)
		if n == 0 {
			break
		}
	}

	if err := s.port.SetReadTimeout(200 * time.Millisecond); err != nil {
		return "", err
	}

	if !strings.HasSuffix(cmd, "\r\n") {
		cmd += "\r\n"
	}

	if _, err := s.port.Write([]byte(cmd)); err != nil {
		return "", err
	}

	deadline := time.Now().Add(timeout)
	var response strings.Builder

	for time.Now().Before(deadline) {
		n, err := s.port.Read(buf)
		if n > 0 {
			response.Write(buf[:n])
			if atResponseComplete(response.String()) {
				return response.String(), nil
			}
		}
		if err != nil {
			if isSerialReadTimeout(err) {
				continue
			}
			// 串口库用 (0, nil) 表示读超时，这里的错误是串口已经不可用（设备拔出、句柄失效）：
			// 继续读只会立刻再次失败，空转到超时为止。
			return response.String(), fmt.Errorf("读取 AT 端口失败: %w", err)
		}
	}

	return response.String(), errors.New("timeout")
}

// isSerialReadTimeout 识别以错误形式上报的读超时。
func isSerialReadTimeout(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "timeout")
}

// atResponseComplete 判断响应中是否已经出现最终结果码（独占一行）。
func atResponseComplete(resp string) bool {
	lines := strings.Split(resp, "\n")
	// 最后一段没有换行符结尾，可能还没收全。
	lines = lines[:len(lines)-1]
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch line {
		case "OK", "ERROR", "NO CARRIER", "BUSY", "NO ANSWER", "NO DIALTONE":
			return true
		}
		if strings.HasPrefix(line, "+CME ERROR:") || strings.HasPrefix(line, "+CMS ERROR:") {
			return true
		}
	}
	return false
}
