package device

import (
	"fmt"
	"strconv"
	"strings"
)

func formatVoWiFiPLMN3(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 || n > 999 {
		return value
	}
	return fmt.Sprintf("%03d", n)
}
