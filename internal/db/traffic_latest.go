package db

import (
	"fmt"
	"time"
)

func GetLatestMinuteDeltas(resource string, tag string) (time.Time, int64, int64, error) {
	if DB == nil {
		return time.Time{}, 0, 0, fmt.Errorf("db not initialized")
	}
	var last TrafficMinute
	if err := DB.Where("resource = ? AND tag = ?", resource, tag).
		Order("period_start desc").
		First(&last).Error; err != nil {
		return time.Time{}, 0, 0, nil
	}
	ps := last.PeriodStart
	type row struct {
		Direction    bool
		TrafficBytes int64
	}
	var rows []row
	if err := DB.Model(&TrafficMinute{}).
		Select("direction, traffic_bytes").
		Where("resource = ? AND tag = ? AND period_start = ?", resource, tag, ps).
		Find(&rows).Error; err != nil {
		return time.Time{}, 0, 0, err
	}
	var rx, tx int64
	for _, r := range rows {
		if r.Direction {
			tx += r.TrafficBytes
		} else {
			rx += r.TrafficBytes
		}
	}
	return ps, rx, tx, nil
}

type LatestMinuteDeltas struct {
	PeriodStart time.Time
	RxBytes     int64
	TxBytes     int64
}

func GetLatestMinuteDeltasBatch(resource string, tags []string) (map[string]LatestMinuteDeltas, error) {
	out := map[string]LatestMinuteDeltas{}
	if DB == nil {
		return out, fmt.Errorf("db not initialized")
	}
	if len(tags) == 0 {
		return out, nil
	}

	type row struct {
		Tag          string    `gorm:"column:tag"`
		PeriodStart  time.Time `gorm:"column:period_start"`
		Direction    bool      `gorm:"column:direction"`
		TrafficBytes int64     `gorm:"column:traffic_bytes"`
	}
	var rows []row
	q := `
WITH latest AS (
  SELECT tag, MAX(period_start) AS period_start
  FROM traffic_minute
  WHERE resource = ? AND tag IN ?
  GROUP BY tag
)
SELECT t.tag, t.period_start, t.direction, t.traffic_bytes
FROM traffic_minute t
JOIN latest l
  ON t.tag = l.tag AND t.period_start = l.period_start
WHERE t.resource = ? AND t.tag IN ?;
`
	if err := DB.Raw(q, resource, tags, resource, tags).Scan(&rows).Error; err != nil {
		return out, err
	}

	for _, r := range rows {
		cur := out[r.Tag]
		if cur.PeriodStart.IsZero() {
			cur.PeriodStart = r.PeriodStart
		}
		if r.Direction {
			cur.TxBytes += r.TrafficBytes
		} else {
			cur.RxBytes += r.TrafficBytes
		}
		out[r.Tag] = cur
	}
	return out, nil
}
