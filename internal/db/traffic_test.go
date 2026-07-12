package db

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/gorm/logger"
)

func TestGetTrafficAnalysisDayWithDeviceFilter(t *testing.T) {
	now := initTrafficTestDB(t)

	mustInsertTrafficHour(t, now, now.Truncate(time.Hour).Add(-2*time.Hour), "dev-a@wwan0", false, 100)
	mustInsertTrafficHour(t, now, now.Truncate(time.Hour).Add(-2*time.Hour), "dev-a@wwan0", true, 40)
	mustInsertTrafficHour(t, now, now.Truncate(time.Hour).Add(-2*time.Hour), "dev-a@wwan1", false, 60)
	mustInsertTrafficHour(t, now, now.Truncate(time.Hour).Add(-2*time.Hour), "dev-a@wwan1", true, 20)
	mustInsertTrafficHour(t, now, now.Truncate(time.Hour).Add(-2*time.Hour), "dev-b@wwan0", false, 70)
	mustInsertTrafficHour(t, now, now.Truncate(time.Hour).Add(-2*time.Hour), "dev-b@wwan0", true, 30)

	mustInsertTrafficMinute(t, now, now.Truncate(time.Hour).Add(5*time.Minute), "dev-a@wwan0", false, 11)
	mustInsertTrafficMinute(t, now, now.Truncate(time.Hour).Add(5*time.Minute), "dev-a@wwan0", true, 5)
	mustInsertTrafficMinute(t, now, now.Truncate(time.Hour).Add(20*time.Minute), "dev-a@wwan1", false, 9)
	mustInsertTrafficMinute(t, now, now.Truncate(time.Hour).Add(20*time.Minute), "dev-a@wwan1", true, 7)
	mustInsertTrafficMinute(t, now, now.Truncate(time.Hour).Add(12*time.Minute), "dev-b@wwan0", false, 13)
	mustInsertTrafficMinute(t, now, now.Truncate(time.Hour).Add(12*time.Minute), "dev-b@wwan0", true, 17)

	globalBuckets, err := GetTrafficAnalysis("day", "", now)
	if err != nil {
		t.Fatalf("GetTrafficAnalysis(global) error = %v", err)
	}
	globalByBucket := bucketMap(globalBuckets)
	historicBucket := now.Truncate(time.Hour).Add(-2 * time.Hour).Format("2006-01-02 15:00")
	currentBucket := now.Truncate(time.Hour).Format("2006-01-02 15:00")
	assertBucketTotals(t, globalByBucket, historicBucket, 230, 90, 320)
	assertBucketTotals(t, globalByBucket, currentBucket, 33, 29, 62)

	filteredBuckets, err := GetTrafficAnalysis("day", "dev-a", now)
	if err != nil {
		t.Fatalf("GetTrafficAnalysis(filtered) error = %v", err)
	}
	filteredByBucket := bucketMap(filteredBuckets)
	assertBucketTotals(t, filteredByBucket, historicBucket, 160, 60, 220)
	assertBucketTotals(t, filteredByBucket, currentBucket, 20, 12, 32)

	chart, err := GetTrafficChartData("day", "dev-a", now)
	if err != nil {
		t.Fatalf("GetTrafficChartData(filtered) error = %v", err)
	}
	if len(chart.Devices) != 1 || chart.Devices[0] != "dev-a" {
		t.Fatalf("chart devices mismatch: got=%v want=[dev-a]", chart.Devices)
	}
	historicIdx := timestampIndex(chart.Timestamps, "13:00")
	currentIdx := lastTimestampIndex(chart.Timestamps, "15:00")
	if historicIdx < 0 || currentIdx < 0 {
		t.Fatalf("expected timestamps not found: timestamps=%v", chart.Timestamps)
	}
	if got := chart.Series["dev-a"][historicIdx]; got != 220 {
		t.Fatalf("historic series mismatch: got=%d want=220", got)
	}
	if got := chart.Series["dev-a"][currentIdx]; got != 32 {
		t.Fatalf("current-hour series mismatch: got=%d want=32", got)
	}
}

func TestGetTrafficAnalysisWeekWithDeviceFilterAndEmptyResult(t *testing.T) {
	now := initTrafficTestDB(t)

	previousDay := time.Date(now.Add(-24*time.Hour).Year(), now.Add(-24*time.Hour).Month(), now.Add(-24*time.Hour).Day(), 0, 0, 0, 0, now.Location())
	currentDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	mustInsertTrafficDay(t, now, previousDay, "dev-a@wwan0", false, 500)
	mustInsertTrafficDay(t, now, previousDay, "dev-a@wwan0", true, 50)
	mustInsertTrafficDay(t, now, previousDay, "dev-b@wwan0", false, 300)
	mustInsertTrafficDay(t, now, previousDay, "dev-b@wwan0", true, 30)

	mustInsertTrafficHour(t, now, currentDay.Add(10*time.Hour), "dev-a@wwan0", false, 21)
	mustInsertTrafficHour(t, now, currentDay.Add(10*time.Hour), "dev-a@wwan0", true, 9)
	mustInsertTrafficHour(t, now, currentDay.Add(12*time.Hour), "dev-a@wwan1", false, 7)
	mustInsertTrafficHour(t, now, currentDay.Add(12*time.Hour), "dev-a@wwan1", true, 3)
	mustInsertTrafficHour(t, now, currentDay.Add(11*time.Hour), "dev-b@wwan0", false, 5)
	mustInsertTrafficHour(t, now, currentDay.Add(11*time.Hour), "dev-b@wwan0", true, 5)

	filteredBuckets, err := GetTrafficAnalysis("week", "dev-a", now)
	if err != nil {
		t.Fatalf("GetTrafficAnalysis(week filtered) error = %v", err)
	}
	filteredByBucket := bucketMap(filteredBuckets)
	assertBucketTotals(t, filteredByBucket, previousDay.Format("2006-01-02"), 500, 50, 550)
	assertBucketTotals(t, filteredByBucket, currentDay.Format("2006-01-02"), 28, 12, 40)

	chart, err := GetTrafficChartData("week", "dev-a", now)
	if err != nil {
		t.Fatalf("GetTrafficChartData(week filtered) error = %v", err)
	}
	if len(chart.Devices) != 1 || chart.Devices[0] != "dev-a" {
		t.Fatalf("chart devices mismatch: got=%v want=[dev-a]", chart.Devices)
	}
	prevIdx := timestampIndex(chart.Timestamps, previousDay.Format("01-02"))
	curIdx := timestampIndex(chart.Timestamps, currentDay.Format("01-02"))
	if prevIdx < 0 || curIdx < 0 {
		t.Fatalf("expected timestamps not found: timestamps=%v", chart.Timestamps)
	}
	if got := chart.Series["dev-a"][prevIdx]; got != 550 {
		t.Fatalf("previous-day series mismatch: got=%d want=550", got)
	}
	if got := chart.Series["dev-a"][curIdx]; got != 40 {
		t.Fatalf("current-day series mismatch: got=%d want=40", got)
	}

	emptyBuckets, err := GetTrafficAnalysis("day", "missing-device", now)
	if err != nil {
		t.Fatalf("GetTrafficAnalysis(empty) error = %v", err)
	}
	if len(emptyBuckets) == 0 {
		t.Fatalf("expected prefilled buckets for empty result")
	}
	for _, bucket := range emptyBuckets {
		if bucket.RxBytes != 0 || bucket.TxBytes != 0 || bucket.TotalBytes != 0 {
			t.Fatalf("expected zero bucket for empty result, got=%+v", bucket)
		}
	}

	emptyChart, err := GetTrafficChartData("day", "missing-device", now)
	if err != nil {
		t.Fatalf("GetTrafficChartData(empty) error = %v", err)
	}
	if len(emptyChart.Devices) != 0 {
		t.Fatalf("expected no devices for empty chart, got=%v", emptyChart.Devices)
	}
	if len(emptyChart.Series) != 0 {
		t.Fatalf("expected empty series map, got=%v", emptyChart.Series)
	}
	if len(emptyChart.Timestamps) == 0 {
		t.Fatalf("expected timestamps for empty chart")
	}
}

func TestGetTrafficAnalysisEscapesLikePatternMetaChars(t *testing.T) {
	now := initTrafficTestDB(t)
	hourStart := now.Truncate(time.Hour).Add(-2 * time.Hour)

	mustInsertTrafficHour(t, now, hourStart, "dev_a@wwan0", false, 15)
	mustInsertTrafficHour(t, now, hourStart, "devXa@wwan0", false, 80)
	mustInsertTrafficHour(t, now, hourStart, "dev%p@wwan0", false, 21)
	mustInsertTrafficHour(t, now, hourStart, "devZp@wwan0", false, 77)

	underscoreBuckets, err := GetTrafficAnalysis("day", "dev_a", now)
	if err != nil {
		t.Fatalf("GetTrafficAnalysis(underscore) error = %v", err)
	}
	assertBucketTotals(t, bucketMap(underscoreBuckets), hourStart.Format("2006-01-02 15:00"), 15, 0, 15)

	percentBuckets, err := GetTrafficAnalysis("day", "dev%p", now)
	if err != nil {
		t.Fatalf("GetTrafficAnalysis(percent) error = %v", err)
	}
	assertBucketTotals(t, bucketMap(percentBuckets), hourStart.Format("2006-01-02 15:00"), 21, 0, 21)
}

func TestGetTrafficAnalysisWithChartUsesSingleDataScanPerRollup(t *testing.T) {
	now := initTrafficTestDB(t)

	historicHour := now.Truncate(time.Hour).Add(-2 * time.Hour)
	currentHour := now.Truncate(time.Hour)
	mustInsertTrafficHour(t, now, historicHour, "dev-a@wwan0", false, 100)
	mustInsertTrafficHour(t, now, historicHour, "dev-a@wwan0", true, 40)
	mustInsertTrafficHour(t, now, historicHour, "dev-b@wwan0", false, 70)
	mustInsertTrafficMinute(t, now, currentHour.Add(5*time.Minute), "dev-a@wwan0", false, 11)
	mustInsertTrafficMinute(t, now, currentHour.Add(5*time.Minute), "dev-a@wwan0", true, 5)
	mustInsertTrafficMinute(t, now, currentHour.Add(10*time.Minute), "dev-b@wwan0", false, 13)

	counter := &trafficSelectCounter{}
	oldLogger := DB.Logger
	DB.Logger = counter
	t.Cleanup(func() {
		DB.Logger = oldLogger
	})

	buckets, chart, err := GetTrafficAnalysisWithChart("day", "", now)
	if err != nil {
		t.Fatalf("GetTrafficAnalysisWithChart() error = %v", err)
	}

	if got := counter.Count(); got > 2 {
		t.Fatalf("expected at most 2 traffic SELECT queries, got %d", got)
	}
	byBucket := bucketMap(buckets)
	assertBucketTotals(t, byBucket, historicHour.Format("2006-01-02 15:00"), 170, 40, 210)
	assertBucketTotals(t, byBucket, currentHour.Format("2006-01-02 15:00"), 24, 5, 29)
	if chart == nil {
		t.Fatalf("expected chart data")
	}
	if got, want := chart.Devices, []string{"dev-a", "dev-b"}; len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("chart devices mismatch: got=%v want=%v", got, want)
	}
	historicIdx := timestampIndex(chart.Timestamps, "13:00")
	currentIdx := lastTimestampIndex(chart.Timestamps, "15:00")
	if historicIdx < 0 || currentIdx < 0 {
		t.Fatalf("expected timestamps not found: timestamps=%v", chart.Timestamps)
	}
	if got := chart.Series["dev-a"][historicIdx]; got != 140 {
		t.Fatalf("dev-a historic series mismatch: got=%d want=140", got)
	}
	if got := chart.Series["dev-a"][currentIdx]; got != 16 {
		t.Fatalf("dev-a current series mismatch: got=%d want=16", got)
	}
	if got := chart.Series["dev-b"][historicIdx]; got != 70 {
		t.Fatalf("dev-b historic series mismatch: got=%d want=70", got)
	}
	if got := chart.Series["dev-b"][currentIdx]; got != 13 {
		t.Fatalf("dev-b current series mismatch: got=%d want=13", got)
	}
}

type trafficSelectCounter struct {
	count atomic.Int64
}

func (l *trafficSelectCounter) LogMode(logger.LogLevel) logger.Interface      { return l }
func (l *trafficSelectCounter) Info(context.Context, string, ...interface{})  {}
func (l *trafficSelectCounter) Warn(context.Context, string, ...interface{})  {}
func (l *trafficSelectCounter) Error(context.Context, string, ...interface{}) {}
func (l *trafficSelectCounter) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	sql, _ := fc()
	normalized := strings.ToLower(strings.TrimSpace(sql))
	if strings.HasPrefix(normalized, "select") && strings.Contains(normalized, "traffic_") {
		l.count.Add(1)
	}
}
func (l *trafficSelectCounter) Count() int64 { return l.count.Load() }

func initTrafficTestDB(t *testing.T) time.Time {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "traffic.db")
	if err := Init(dbPath); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	t.Cleanup(func() {
		DB = nil
	})
	return time.Date(2026, time.March, 30, 15, 37, 0, 0, time.UTC)
}

func mustInsertTrafficMinute(t *testing.T, now time.Time, periodStart time.Time, tag string, direction bool, bytes int64) {
	t.Helper()
	if err := DB.Create(&TrafficMinute{
		PeriodStart:  periodStart,
		Resource:     "iface",
		Tag:          tag,
		Direction:    direction,
		TrafficBytes: bytes,
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("insert traffic_minute failed: %v", err)
	}
}

func mustInsertTrafficHour(t *testing.T, now time.Time, periodStart time.Time, tag string, direction bool, bytes int64) {
	t.Helper()
	if err := DB.Create(&TrafficHour{
		PeriodStart:  periodStart,
		Resource:     "iface",
		Tag:          tag,
		Direction:    direction,
		TrafficBytes: bytes,
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("insert traffic_hour failed: %v", err)
	}
}

func mustInsertTrafficDay(t *testing.T, now time.Time, periodStart time.Time, tag string, direction bool, bytes int64) {
	t.Helper()
	if err := DB.Create(&TrafficDay{
		PeriodStart:  periodStart,
		Resource:     "iface",
		Tag:          tag,
		Direction:    direction,
		TrafficBytes: bytes,
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("insert traffic_day failed: %v", err)
	}
}

func bucketMap(buckets []TrafficBucket) map[string]TrafficBucket {
	out := make(map[string]TrafficBucket, len(buckets))
	for _, bucket := range buckets {
		out[bucket.Bucket] = bucket
	}
	return out
}

func assertBucketTotals(t *testing.T, buckets map[string]TrafficBucket, key string, rx int64, tx int64, total int64) {
	t.Helper()
	bucket, ok := buckets[key]
	if !ok {
		t.Fatalf("bucket %q not found", key)
	}
	if bucket.RxBytes != rx || bucket.TxBytes != tx || bucket.TotalBytes != total {
		t.Fatalf("bucket %q mismatch: got=(rx=%d tx=%d total=%d) want=(rx=%d tx=%d total=%d)", key, bucket.RxBytes, bucket.TxBytes, bucket.TotalBytes, rx, tx, total)
	}
}

func timestampIndex(timestamps []string, target string) int {
	for idx, ts := range timestamps {
		if ts == target {
			return idx
		}
	}
	return -1
}

func lastTimestampIndex(timestamps []string, target string) int {
	for idx := len(timestamps) - 1; idx >= 0; idx-- {
		if timestamps[idx] == target {
			return idx
		}
	}
	return -1
}
