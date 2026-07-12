package db

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"
)

type TrafficBucket struct {
	Bucket     string `json:"bucket"`
	RxBytes    int64  `json:"rx_bytes"`
	TxBytes    int64  `json:"tx_bytes"`
	TotalBytes int64  `json:"total_bytes"`
}

func GetTrafficAnalysis(rangeName string, deviceID string, now time.Time) ([]TrafficBucket, error) {
	buckets, _, err := GetTrafficAnalysisWithChart(rangeName, deviceID, now)
	if err != nil {
		return nil, err
	}
	return buckets, nil
}

type TrafficChartData struct {
	Timestamps []string           `json:"timestamps"`
	Devices    []string           `json:"devices"`
	Series     map[string][]int64 `json:"series"` // device_id -> [bytes, bytes, ...]
}

func GetTrafficChartData(rangeName string, deviceID string, now time.Time) (*TrafficChartData, error) {
	_, chart, err := GetTrafficAnalysisWithChart(rangeName, deviceID, now)
	if err != nil {
		return nil, err
	}
	return chart, nil
}

func GetTrafficAnalysisWithChart(rangeName string, deviceID string, now time.Time) ([]TrafficBucket, *TrafficChartData, error) {
	if DB == nil {
		return nil, nil, fmt.Errorf("db not initialized")
	}

	spec, err := newTrafficRangeSpec(rangeName, now)
	if err != nil {
		return nil, nil, err
	}

	timestamps := make([]string, 0)
	tsMap := make(map[string]int)
	bucketAgg := map[string]*TrafficBucket{}
	bucketOrder := make([]string, 0)
	cursor := spec.since
	for !cursor.After(now) {
		bucketKey := spec.bucketKey(cursor)
		bucketAgg[bucketKey] = &TrafficBucket{Bucket: bucketKey}
		bucketOrder = append(bucketOrder, bucketKey)
		chartKey := spec.chartKey(cursor)
		tsMap[chartKey] = len(timestamps)
		timestamps = append(timestamps, chartKey)
		cursor = cursor.Add(spec.step)
	}

	rows, err := queryTrafficRollupRows(rangeName, deviceID, spec.since, now)
	if err != nil {
		return nil, nil, err
	}
	currentRows, err := queryTrafficCurrentRows(rangeName, deviceID, spec.currentStart, now)
	if err != nil {
		return nil, nil, err
	}

	deviceSet := map[string]struct{}{}
	tempSeries := map[string]map[int]int64{}
	applyRow := func(r trafficRollupRow) {
		ps := r.PeriodStart.In(now.Location())
		if b, ok := bucketAgg[spec.bucketKey(ps)]; ok {
			if r.Direction {
				b.TxBytes += r.TrafficBytes
			} else {
				b.RxBytes += r.TrafficBytes
			}
			b.TotalBytes = b.RxBytes + b.TxBytes
		}

		chartKey := spec.chartKey(ps)
		tIdx, ok := tsMap[chartKey]
		if !ok {
			return
		}
		dev := trafficDeviceFromTag(r.Tag)
		deviceSet[dev] = struct{}{}
		if _, exists := tempSeries[dev]; !exists {
			tempSeries[dev] = make(map[int]int64)
		}
		tempSeries[dev][tIdx] += r.TrafficBytes
	}

	for _, r := range rows {
		applyRow(r)
	}
	for _, r := range currentRows {
		applyRow(r)
	}

	buckets := make([]TrafficBucket, 0, len(bucketOrder))
	for _, k := range bucketOrder {
		buckets = append(buckets, *bucketAgg[k])
	}

	devices := make([]string, 0, len(deviceSet))
	for d := range deviceSet {
		devices = append(devices, d)
	}
	sort.Strings(devices)

	series := make(map[string][]int64)
	for _, dev := range devices {
		data := make([]int64, len(timestamps))
		if points, ok := tempSeries[dev]; ok {
			for tIdx, val := range points {
				data[tIdx] = val
			}
		}
		series[dev] = data
	}

	return buckets, &TrafficChartData{
		Timestamps: timestamps,
		Devices:    devices,
		Series:     series,
	}, nil
}

type trafficRangeSpec struct {
	since        time.Time
	step         time.Duration
	currentStart time.Time
	bucketKey    func(time.Time) string
	chartKey     func(time.Time) string
}

func newTrafficRangeSpec(rangeName string, now time.Time) (trafficRangeSpec, error) {
	switch rangeName {
	case "day":
		return trafficRangeSpec{
			since:        now.Add(-24 * time.Hour).Truncate(time.Hour),
			step:         time.Hour,
			currentStart: now.Truncate(time.Hour),
			bucketKey: func(t time.Time) string {
				return t.Truncate(time.Hour).Format("2006-01-02 15:00")
			},
			chartKey: func(t time.Time) string {
				return t.Truncate(time.Hour).Format("15:00")
			},
		}, nil
	case "week":
		since := startOfTrafficDay(now.Add(-7 * 24 * time.Hour))
		return trafficRangeSpec{
			since:        since,
			step:         24 * time.Hour,
			currentStart: startOfTrafficDay(now),
			bucketKey: func(t time.Time) string {
				return startOfTrafficDay(t).Format("2006-01-02")
			},
			chartKey: func(t time.Time) string {
				return startOfTrafficDay(t).Format("01-02")
			},
		}, nil
	case "month":
		since := startOfTrafficDay(now.Add(-30 * 24 * time.Hour))
		return trafficRangeSpec{
			since:        since,
			step:         24 * time.Hour,
			currentStart: startOfTrafficDay(now),
			bucketKey: func(t time.Time) string {
				return startOfTrafficDay(t).Format("2006-01-02")
			},
			chartKey: func(t time.Time) string {
				return startOfTrafficDay(t).Format("01-02")
			},
		}, nil
	default:
		return trafficRangeSpec{}, fmt.Errorf("invalid range")
	}
}

func startOfTrafficDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

type trafficRollupRow struct {
	PeriodStart  time.Time
	Tag          string
	Direction    bool
	TrafficBytes int64
}

func queryTrafficRollupRows(rangeName string, deviceID string, since time.Time, now time.Time) ([]trafficRollupRow, error) {
	var rows []trafficRollupRow
	var q *gorm.DB
	if rangeName == "day" {
		q = DB.Model(&TrafficHour{})
	} else {
		q = DB.Model(&TrafficDay{})
	}
	q = q.Select("period_start, tag, direction, traffic_bytes").
		Where("resource = ? AND period_start >= ? AND period_start <= ?", "iface", since, now)
	q = applyTrafficDeviceFilter(q, deviceID)
	if err := q.Order("period_start asc").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

func queryTrafficCurrentRows(rangeName string, deviceID string, currentStart time.Time, now time.Time) ([]trafficRollupRow, error) {
	type currentRow struct {
		Tag          string
		Direction    bool
		TrafficBytes int64
	}
	var rows []currentRow
	var q *gorm.DB
	if rangeName == "day" {
		q = DB.Model(&TrafficMinute{})
	} else {
		q = DB.Model(&TrafficHour{})
	}
	q = q.Select("tag, direction, sum(traffic_bytes) as traffic_bytes").
		Where("resource = ? AND period_start >= ? AND period_start <= ?", "iface", currentStart, now).
		Group("tag, direction")
	q = applyTrafficDeviceFilter(q, deviceID)
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}

	out := make([]trafficRollupRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, trafficRollupRow{
			PeriodStart:  currentStart,
			Tag:          r.Tag,
			Direction:    r.Direction,
			TrafficBytes: r.TrafficBytes,
		})
	}
	return out, nil
}

func trafficDeviceFromTag(tag string) string {
	if idx := indexByte(tag, '@'); idx >= 0 {
		return tag[:idx]
	}
	return tag
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func applyTrafficDeviceFilter(tx *gorm.DB, deviceID string) *gorm.DB {
	pattern := trafficTagPrefixPattern(deviceID)
	if pattern == "" {
		return tx
	}
	return tx.Where("tag LIKE ? ESCAPE '\\'", pattern)
}

func trafficTagPrefixPattern(deviceID string) string {
	trimmed := strings.TrimSpace(deviceID)
	if trimmed == "" {
		return ""
	}
	return escapeLikePattern(trimmed) + "@%"
}

func escapeLikePattern(v string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"%", "\\%",
		"_", "\\_",
	)
	return replacer.Replace(v)
}
