package db

import (
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type TrafficMinute struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	PeriodStart  time.Time `gorm:"not null;uniqueIndex:uk_traffic_minute,priority:1;index:idx_traffic_minute_ps" json:"period_start"`
	Resource     string    `gorm:"not null;size:32;uniqueIndex:uk_traffic_minute,priority:2;index:idx_traffic_minute_res_tag_dir_ps,priority:1" json:"resource"`
	Tag          string    `gorm:"not null;size:128;uniqueIndex:uk_traffic_minute,priority:3;index:idx_traffic_minute_res_tag_dir_ps,priority:2" json:"tag"`
	Direction    bool      `gorm:"not null;uniqueIndex:uk_traffic_minute,priority:4;index:idx_traffic_minute_res_tag_dir_ps,priority:3" json:"direction"`
	TrafficBytes int64     `gorm:"not null" json:"traffic_bytes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (TrafficMinute) TableName() string { return "traffic_minute" }

type TrafficHour struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	PeriodStart  time.Time `gorm:"not null;uniqueIndex:uk_traffic_hour,priority:1;index:idx_traffic_hour_ps" json:"period_start"`
	Resource     string    `gorm:"not null;size:32;uniqueIndex:uk_traffic_hour,priority:2;index:idx_traffic_hour_res_tag_dir_ps,priority:1" json:"resource"`
	Tag          string    `gorm:"not null;size:128;uniqueIndex:uk_traffic_hour,priority:3;index:idx_traffic_hour_res_tag_dir_ps,priority:2" json:"tag"`
	Direction    bool      `gorm:"not null;uniqueIndex:uk_traffic_hour,priority:4;index:idx_traffic_hour_res_tag_dir_ps,priority:3" json:"direction"`
	TrafficBytes int64     `gorm:"not null" json:"traffic_bytes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (TrafficHour) TableName() string { return "traffic_hour" }

type TrafficDay struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	PeriodStart  time.Time `gorm:"not null;uniqueIndex:uk_traffic_day,priority:1;index:idx_traffic_day_ps" json:"period_start"`
	Resource     string    `gorm:"not null;size:32;uniqueIndex:uk_traffic_day,priority:2;index:idx_traffic_day_res_tag_dir_ps,priority:1" json:"resource"`
	Tag          string    `gorm:"not null;size:128;uniqueIndex:uk_traffic_day,priority:3;index:idx_traffic_day_res_tag_dir_ps,priority:2" json:"tag"`
	Direction    bool      `gorm:"not null;uniqueIndex:uk_traffic_day,priority:4;index:idx_traffic_day_res_tag_dir_ps,priority:3" json:"direction"`
	TrafficBytes int64     `gorm:"not null" json:"traffic_bytes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (TrafficDay) TableName() string { return "traffic_day" }

type TrafficWeek struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	PeriodStart  time.Time `gorm:"not null;uniqueIndex:uk_traffic_week,priority:1;index:idx_traffic_week_ps" json:"period_start"`
	Resource     string    `gorm:"not null;size:32;uniqueIndex:uk_traffic_week,priority:2;index:idx_traffic_week_res_tag_dir_ps,priority:1" json:"resource"`
	Tag          string    `gorm:"not null;size:128;uniqueIndex:uk_traffic_week,priority:3;index:idx_traffic_week_res_tag_dir_ps,priority:2" json:"tag"`
	Direction    bool      `gorm:"not null;uniqueIndex:uk_traffic_week,priority:4;index:idx_traffic_week_res_tag_dir_ps,priority:3" json:"direction"`
	TrafficBytes int64     `gorm:"not null" json:"traffic_bytes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (TrafficWeek) TableName() string { return "traffic_week" }

type TrafficMonth struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	PeriodStart  time.Time `gorm:"not null;uniqueIndex:uk_traffic_month,priority:1;index:idx_traffic_month_ps" json:"period_start"`
	Resource     string    `gorm:"not null;size:32;uniqueIndex:uk_traffic_month,priority:2;index:idx_traffic_month_res_tag_dir_ps,priority:1" json:"resource"`
	Tag          string    `gorm:"not null;size:128;uniqueIndex:uk_traffic_month,priority:3;index:idx_traffic_month_res_tag_dir_ps,priority:2" json:"tag"`
	Direction    bool      `gorm:"not null;uniqueIndex:uk_traffic_month,priority:4;index:idx_traffic_month_res_tag_dir_ps,priority:3" json:"direction"`
	TrafficBytes int64     `gorm:"not null" json:"traffic_bytes"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (TrafficMonth) TableName() string { return "traffic_month" }

type TrafficPoint struct {
	PeriodStart  time.Time
	Resource     string
	Tag          string
	Direction    bool
	TrafficBytes int64
}

func UpsertTrafficMinute(points []TrafficPoint) error {
	if DB == nil {
		return fmt.Errorf("db not initialized")
	}
	if len(points) == 0 {
		return nil
	}
	rows := make([]TrafficMinute, 0, len(points))
	now := time.Now()
	for _, p := range points {
		rows = append(rows, TrafficMinute{
			PeriodStart:  p.PeriodStart,
			Resource:     p.Resource,
			Tag:          p.Tag,
			Direction:    p.Direction,
			TrafficBytes: p.TrafficBytes,
			CreatedAt:    now,
			UpdatedAt:    now,
		})
	}
	onConflict := clause.OnConflict{
		Columns: []clause.Column{{Name: "period_start"}, {Name: "resource"}, {Name: "tag"}, {Name: "direction"}},
		DoUpdates: clause.Assignments(map[string]any{
			"traffic_bytes": gorm.Expr("traffic_bytes + excluded.traffic_bytes"),
			"updated_at":    now,
		}),
	}
	return DB.Clauses(onConflict).Create(&rows).Error
}

func RollupToHour(hourStart time.Time) error {
	return rollup("traffic_minute", "traffic_hour", hourStart, hourStart.Add(time.Hour))
}

func RollupToDay(dayStart time.Time) error {
	return rollup("traffic_hour", "traffic_day", dayStart, dayStart.Add(24*time.Hour))
}

func RollupToWeek(weekStart time.Time) error {
	return rollup("traffic_day", "traffic_week", weekStart, weekStart.Add(7*24*time.Hour))
}

func RollupToMonth(monthStart time.Time) error {
	next := monthStart.AddDate(0, 1, 0)
	return rollup("traffic_day", "traffic_month", monthStart, next)
}

func CleanupBefore(now time.Time, keepMinute time.Duration, keepHour time.Duration, keepDay time.Duration, keepWeek time.Duration, keepMonth time.Duration) error {
	if DB == nil {
		return fmt.Errorf("db not initialized")
	}
	if keepMinute > 0 {
		_ = DB.Where("period_start < ?", now.Add(-keepMinute)).Delete(&TrafficMinute{}).Error
	}
	if keepHour > 0 {
		_ = DB.Where("period_start < ?", now.Add(-keepHour)).Delete(&TrafficHour{}).Error
	}
	if keepDay > 0 {
		_ = DB.Where("period_start < ?", now.Add(-keepDay)).Delete(&TrafficDay{}).Error
	}
	if keepWeek > 0 {
		_ = DB.Where("period_start < ?", now.Add(-keepWeek)).Delete(&TrafficWeek{}).Error
	}
	if keepMonth > 0 {
		_ = DB.Where("period_start < ?", now.Add(-keepMonth)).Delete(&TrafficMonth{}).Error
	}
	return nil
}

func rollup(fromTable string, toTable string, start time.Time, end time.Time) error {
	if DB == nil {
		return fmt.Errorf("db not initialized")
	}
	now := time.Now()
	sql := fmt.Sprintf(
		`INSERT INTO %s (period_start, resource, tag, direction, traffic_bytes, created_at, updated_at)
		 SELECT ?, resource, tag, direction, SUM(traffic_bytes) AS traffic_bytes, ?, ?
		 FROM %s
		 WHERE period_start >= ? AND period_start < ?
		 GROUP BY resource, tag, direction
		 ON CONFLICT(period_start, resource, tag, direction) DO UPDATE SET
		   traffic_bytes=excluded.traffic_bytes,
		   updated_at=excluded.updated_at`,
		toTable,
		fromTable,
	)
	return DB.Exec(sql, start, now, now, start, end).Error
}
