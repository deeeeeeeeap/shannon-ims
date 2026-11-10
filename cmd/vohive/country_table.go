package main

import (
	"context"
	"time"

	"github.com/1239t/vohive/internal/upstreamproxy"
	"github.com/1239t/vohive/pkg/logger"
)

// countryTableStartupBudget bounds how long startup waits for the MCC/MNC
// table when it has to be downloaded. Past it the built-in table is used
// and the download is left to the background.
const countryTableStartupBudget = 8 * time.Second

// loadCountryTable installs the country table the VoWiFi proxy rules are
// matched with. It reports whether the full table is still to be
// downloaded.
func loadCountryTable(ctx context.Context, opts upstreamproxy.CountryTableOptions) bool {
	loadCtx, cancel := context.WithTimeout(ctx, countryTableStartupBudget)
	defer cancel()
	result := upstreamproxy.InitCountryTable(loadCtx, opts)
	logCountryTableResult(result)
	switch result.Source {
	case upstreamproxy.CountryTableSourceBuiltin, upstreamproxy.CountryTableSourceEmpty:
		return true
	}
	return false
}

// refreshCountryTableInBackground downloads the full table as soon as the
// network allows and returns once it has, or when ctx ends.
func refreshCountryTableInBackground(ctx context.Context, opts upstreamproxy.CountryTableOptions) {
	upstreamproxy.KeepRefreshingCountryTable(ctx, opts, nil, func(result upstreamproxy.CountryTableInitResult) {
		if result.Downloaded {
			logCountryTableResult(result)
			return
		}
		logger.Debug("MCC/MNC 国家表后台下载未成功，稍后重试",
			"source", result.Source,
			"err", result.Err)
	})
}

func logCountryTableResult(result upstreamproxy.CountryTableInitResult) {
	switch result.Source {
	case upstreamproxy.CountryTableSourceBuiltin:
		logger.Warn("MCC/MNC 国家表下载失败，已启用内置国家表；VoWiFi 国家代理规则照常生效，后台将继续尝试下载完整表",
			"path", result.CachePath,
			"source_url", result.SourceURL,
			"source", result.Source,
			"countries", result.Countries,
			"err", result.Err)
	case upstreamproxy.CountryTableSourceEmpty:
		logger.Warn("MCC/MNC 国家表不可用，VoWiFi 国家代理规则将按未知国家直连",
			"path", result.CachePath,
			"source_url", result.SourceURL,
			"source", result.Source,
			"err", result.Err)
	default:
		logger.Info("MCC/MNC 国家表已加载",
			"path", result.CachePath,
			"source", result.Source,
			"rows", result.RowCount,
			"countries", result.Countries)
		if result.Err != nil {
			// The table is in use; only the cache could not be written.
			logger.Warn("MCC/MNC 国家表写入本地缓存失败，下次启动需要重新下载",
				"path", result.CachePath,
				"err", result.Err)
		}
	}
}
