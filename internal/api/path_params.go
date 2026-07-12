package api

import (
	"strings"

	"github.com/gin-gonic/gin"
)

func firstPathParam(c *gin.Context, names ...string) string {
	if c == nil {
		return ""
	}
	for _, name := range names {
		if v := strings.TrimSpace(c.Param(name)); v != "" {
			return v
		}
	}
	return ""
}

func deviceIDParam(c *gin.Context) string {
	return firstPathParam(c, "device_id", "id")
}

func upstreamProxyIDParam(c *gin.Context) string {
	return firstPathParam(c, "proxy_id", "id")
}

func countryCodeParam(c *gin.Context) string {
	return firstPathParam(c, "country_code", "country")
}

func proxyInstanceIDParam(c *gin.Context) string {
	return firstPathParam(c, "instance_id", "id")
}
