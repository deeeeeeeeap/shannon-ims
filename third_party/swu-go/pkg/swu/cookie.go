package swu

import (
	"errors"

	"github.com/1239t/swu-go/pkg/logger"
)

var ErrCookieRequired = errors.New("需要重新发送带 COOKIE 的 IKE_SA_INIT")

// handleCookie 处理来自 ePDG 的 COOKIE 通知
// 当收到 COOKIE 时，需要在下次 IKE_SA_INIT 中包含该 COOKIE
func (s *Session) handleCookie(cookieData []byte) error {
	logger.Debug("收到 COOKIE，重新发送 IKE_SA_INIT", logger.Int("len", len(cookieData)))

	// 保存 cookie
	s.cookie = make([]byte, len(cookieData))
	copy(s.cookie, cookieData)
	s.sendCookie = true

	return nil
}
