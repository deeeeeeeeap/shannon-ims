package db

import (
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	SMSDeliveryStatePending             = "pending"
	SMSDeliveryStatePartialAck          = "partial_ack"
	SMSDeliveryStateAcked               = "acked"
	SMSDeliveryStateDeliveryPending     = "delivery_pending"
	SMSDeliveryStateDeliveryUnconfirmed = "delivery_unconfirmed"
	SMSDeliveryStateDelivered           = "delivered"
	SMSDeliveryStateFailed              = "failed"
)

const (
	SMSDeliveryPartStatePending             = "pending"
	SMSDeliveryPartStateAcked               = "acked"
	SMSDeliveryPartStateDeliveryPending     = "delivery_pending"
	SMSDeliveryPartStateDeliveryUnconfirmed = "delivery_unconfirmed"
	SMSDeliveryPartStateDelivered           = "delivered"
	SMSDeliveryPartStateDeliveryFailed      = "delivery_failed"
	SMSDeliveryPartStateFailed              = "failed"
	SMSDeliveryPartStateTimeout             = "timeout"
)

var ErrSMSDeliveryReportAmbiguous = errors.New("SMS delivery report correlation is ambiguous")

// SMSDelivery 记录一条上行短信(message 级别)的发送追踪状态。
type SMSDelivery struct {
	MessageID  string    `gorm:"column:message_id;primaryKey" json:"message_id"`
	IMSI       string    `gorm:"column:imsi;index" json:"imsi"`
	ICCID      string    `gorm:"column:iccid;index" json:"iccid"`
	DeviceID   string    `gorm:"column:device_id;index" json:"device_id"`
	Peer       string    `gorm:"column:peer;index" json:"peer"`
	Content    string    `gorm:"column:content" json:"content"`
	PartsTotal int       `gorm:"column:parts_total" json:"parts_total"`
	Acks       int       `gorm:"column:acks" json:"acks"`
	State      string    `gorm:"column:state;index" json:"state"`
	LastError  string    `gorm:"column:last_error" json:"last_error"`
	CreatedAt  time.Time `gorm:"column:created_at" json:"created_at"`
	UpdatedAt  time.Time `gorm:"column:updated_at" json:"updated_at"`
}

func (SMSDelivery) TableName() string { return "sms_delivery" }

// SMSDeliveryPart 记录一条上行短信分片(part 级别)的发送与回执状态。
type SMSDeliveryPart struct {
	ID                uint       `gorm:"primaryKey" json:"id"`
	MessageID         string     `gorm:"column:message_id;uniqueIndex:idx_sms_delivery_part_mid_no,priority:1;index" json:"message_id"`
	PartNo            int        `gorm:"column:part_no;uniqueIndex:idx_sms_delivery_part_mid_no,priority:2" json:"part_no"`
	CallID            string     `gorm:"column:call_id;index" json:"call_id"`
	InReplyTo         string     `gorm:"column:in_reply_to;index" json:"in_reply_to"`
	RPMR              int        `gorm:"column:rp_mr;index" json:"rp_mr"`
	State             string     `gorm:"column:state;index" json:"state"`
	SIPCode           int        `gorm:"column:sip_code" json:"sip_code"`
	RPCause           int        `gorm:"column:rp_cause" json:"rp_cause"`
	ErrorText         string     `gorm:"column:error_text" json:"error_text"`
	SentAt            time.Time  `gorm:"column:sent_at;index" json:"sent_at"`
	ReportAt          *time.Time `gorm:"column:report_at;index" json:"report_at,omitempty"`
	CreatedAt         time.Time  `gorm:"column:created_at" json:"created_at"`
	UpdatedAt         time.Time  `gorm:"column:updated_at" json:"updated_at"`
	CorrelationMethod string     `gorm:"-" json:"-"`
}

func (SMSDeliveryPart) TableName() string { return "sms_delivery_part" }

// SMSDeliveryStatus 用于 API 返回 message 及其分片状态。
type SMSDeliveryStatus struct {
	MessageID  string            `json:"message_id"`
	IMSI       string            `json:"imsi"`
	ICCID      string            `json:"iccid"`
	DeviceID   string            `json:"device_id"`
	Peer       string            `json:"peer"`
	Content    string            `json:"content"`
	PartsTotal int               `json:"parts_total"`
	Acks       int               `json:"acks"`
	State      string            `json:"state"`
	LastError  string            `json:"last_error"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	Parts      []SMSDeliveryPart `json:"parts"`
}

func CreateSMSDelivery(messageID, imsi, deviceID, peer, content string, partsTotal int, at time.Time) error {
	if DB == nil {
		return nil
	}
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return errors.New("message_id 不能为空")
	}
	if at.IsZero() {
		at = time.Now()
	}
	imsi = strings.TrimSpace(imsi)
	row := SMSDelivery{
		MessageID:  messageID,
		IMSI:       imsi,
		ICCID:      GetICCIDForIMSI(imsi),
		DeviceID:   strings.TrimSpace(deviceID),
		Peer:       strings.TrimSpace(peer),
		Content:    content,
		PartsTotal: partsTotal,
		Acks:       0,
		State:      SMSDeliveryStatePending,
		LastError:  "",
		CreatedAt:  at,
		UpdatedAt:  at,
	}
	return DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "message_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"imsi", "iccid", "device_id", "peer", "content", "parts_total", "state", "last_error", "updated_at"}),
	}).Create(&row).Error
}

func UpsertSMSDeliveryPart(messageID string, partNo int, callID string, rpMR int, state string, sentAt time.Time) error {
	if DB == nil {
		return nil
	}
	messageID = strings.TrimSpace(messageID)
	if messageID == "" || partNo <= 0 {
		return errors.New("message_id/part_no 非法")
	}
	if sentAt.IsZero() {
		sentAt = time.Now()
	}
	if strings.TrimSpace(state) == "" {
		state = SMSDeliveryPartStatePending
	}
	part := SMSDeliveryPart{
		MessageID: messageID,
		PartNo:    partNo,
		CallID:    strings.TrimSpace(callID),
		RPMR:      rpMR,
		State:     strings.TrimSpace(state),
		SentAt:    sentAt,
		CreatedAt: sentAt,
		UpdatedAt: sentAt,
	}
	return DB.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "message_id"}, {Name: "part_no"}},
		DoUpdates: clause.Assignments(map[string]any{
			"call_id": part.CallID,
			"rp_mr":   part.RPMR,
			"state": clause.Expr{
				SQL: `CASE
					WHEN sms_delivery_part.state IN (?, ?, ?, ?)
					THEN sms_delivery_part.state
					WHEN sms_delivery_part.state = ? AND excluded.state <> ?
					THEN sms_delivery_part.state
					WHEN excluded.state = ? AND sms_delivery_part.state IN (?, ?, ?)
					THEN sms_delivery_part.state
					ELSE excluded.state
				END`,
				Vars: []any{
					SMSDeliveryPartStateDeliveryPending,
					SMSDeliveryPartStateDeliveryUnconfirmed,
					SMSDeliveryPartStateDelivered,
					SMSDeliveryPartStateDeliveryFailed,
					SMSDeliveryPartStateAcked,
					SMSDeliveryPartStateAcked,
					SMSDeliveryPartStatePending,
					SMSDeliveryPartStateAcked,
					SMSDeliveryPartStateFailed,
					SMSDeliveryPartStateTimeout,
				},
			},
			"sent_at":    part.SentAt,
			"updated_at": sentAt,
		}),
	}).Create(&part).Error
}

// MarkSMSDeliveryPartStatusReport applies the recipient-delivery axis of an
// SMS-STATUS-REPORT. New VoWiFi submissions deliberately encode TP-MR equal
// to their persisted RP-MR, so this bounded lookup can use the existing
// column without a production schema migration. The inner TP-MR is still the
// semantic correlation key; the report's outer RP-MR is never passed here.
func MarkSMSDeliveryPartStatusReport(imsi, deviceID, recipient string, tpMR int, state string, _ int, at time.Time) (SMSDeliveryPart, error) {
	if DB == nil {
		return SMSDeliveryPart{}, gorm.ErrRecordNotFound
	}
	if at.IsZero() {
		at = time.Now()
	}
	imsi = strings.TrimSpace(imsi)
	deviceID = strings.TrimSpace(deviceID)
	recipient = canonicalSMSStatusRecipient(recipient)
	if imsi == "" || deviceID == "" || recipient == "" || tpMR < 0 || tpMR > 255 {
		return SMSDeliveryPart{}, gorm.ErrRecordNotFound
	}
	state = boundedSMSStatusPartState(state)

	type statusCandidate struct {
		SMSDeliveryPart
		DeliveryPeer string `gorm:"column:delivery_peer"`
	}
	var part SMSDeliveryPart
	err := DB.Transaction(func(tx *gorm.DB) error {
		var rows []statusCandidate
		query := tx.Table("sms_delivery_part").
			Select("sms_delivery_part.*, sms_delivery.peer AS delivery_peer").
			Joins("JOIN sms_delivery ON sms_delivery.message_id = sms_delivery_part.message_id").
			Where("sms_delivery.imsi = ? AND sms_delivery.device_id = ?", imsi, deviceID).
			Where("sms_delivery_part.rp_mr = ? AND sms_delivery_part.created_at >= ?", tpMR, at.Add(-7*24*time.Hour)).
			Where("sms_delivery_part.state IN ?", []string{
				SMSDeliveryPartStatePending,
				SMSDeliveryPartStateAcked,
				SMSDeliveryPartStateDeliveryPending,
				SMSDeliveryPartStateDeliveryUnconfirmed,
				SMSDeliveryPartStateDelivered,
				SMSDeliveryPartStateDeliveryFailed,
			}).
			Order("sms_delivery_part.created_at desc").
			Limit(16).
			Find(&rows)
		if query.Error != nil {
			return query.Error
		}
		matches := make([]SMSDeliveryPart, 0, 2)
		for _, row := range rows {
			if canonicalSMSStatusRecipient(row.DeliveryPeer) == recipient {
				matches = append(matches, row.SMSDeliveryPart)
			}
		}
		switch len(matches) {
		case 0:
			return gorm.ErrRecordNotFound
		case 1:
			part = matches[0]
		default:
			return ErrSMSDeliveryReportAmbiguous
		}

		if !isFinalSMSDeliveryPartState(part.State) {
			reportAt := at
			if err := tx.Model(&SMSDeliveryPart{}).
				Where("id = ? AND state NOT IN ?", part.ID, []string{
					SMSDeliveryPartStateDelivered,
					SMSDeliveryPartStateDeliveryFailed,
					SMSDeliveryPartStateDeliveryUnconfirmed,
				}).
				Updates(map[string]any{
					"state":      state,
					"report_at":  &reportAt,
					"updated_at": at,
				}).Error; err != nil {
				return err
			}
		}
		if err := tx.First(&part, part.ID).Error; err != nil {
			return err
		}
		if err := recomputeSMSDelivery(tx, part.MessageID, at); err != nil {
			return err
		}
		return syncVoWiFiSMSHistoryStatusFromDelivery(tx, part.MessageID)
	})
	if err != nil {
		return SMSDeliveryPart{}, err
	}
	part.CorrelationMethod = "tp_mr"
	return part, nil
}

func canonicalSMSStatusRecipient(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var out strings.Builder
	for i, r := range value {
		switch {
		case r == '+' && i == 0:
			out.WriteRune(r)
		case r >= '0' && r <= '9':
			out.WriteRune(r)
		case r == ' ' || r == '-' || r == '(' || r == ')':
		default:
			return ""
		}
	}
	if out.String() == "+" {
		return ""
	}
	return out.String()
}

func boundedSMSStatusPartState(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case SMSDeliveryPartStateDelivered:
		return SMSDeliveryPartStateDelivered
	case SMSDeliveryPartStateDeliveryPending:
		return SMSDeliveryPartStateDeliveryPending
	case SMSDeliveryPartStateDeliveryFailed:
		return SMSDeliveryPartStateDeliveryFailed
	default:
		return SMSDeliveryPartStateDeliveryUnconfirmed
	}
}

func isFinalSMSDeliveryPartState(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case SMSDeliveryPartStateDelivered, SMSDeliveryPartStateDeliveryFailed, SMSDeliveryPartStateDeliveryUnconfirmed:
		return true
	default:
		return false
	}
}

func MarkSMSDeliveryPartReport(inReplyTo, callID, deviceID string, rpMR int, state string, sipCode int, rpCause int, errText string, at time.Time) (SMSDeliveryPart, error) {
	if DB == nil {
		return SMSDeliveryPart{}, gorm.ErrRecordNotFound
	}
	if at.IsZero() {
		at = time.Now()
	}
	state = strings.TrimSpace(state)
	if state == "" {
		state = SMSDeliveryPartStateFailed
	}

	deviceID = strings.TrimSpace(deviceID)
	inReplyTo = strings.TrimSpace(inReplyTo)
	callID = strings.TrimSpace(callID)

	var part SMSDeliveryPart
	correlationMethod := ""
	err := DB.Transaction(func(tx *gorm.DB) error {
		baseQuery := func() *gorm.DB {
			q := tx.Model(&SMSDeliveryPart{})
			if deviceID != "" {
				q = q.Joins("JOIN sms_delivery ON sms_delivery.message_id = sms_delivery_part.message_id").
					Where("sms_delivery.device_id = ?", deviceID)
			}
			return q
		}
		findLatest := func(q *gorm.DB) (SMSDeliveryPart, error) {
			var p SMSDeliveryPart
			err := q.Order("sms_delivery_part.created_at desc").First(&p).Error
			return p, err
		}

		var findErr error
		if inReplyTo != "" {
			part, findErr = findLatest(baseQuery().Where("sms_delivery_part.call_id = ?", inReplyTo))
			if part.ID != 0 {
				correlationMethod = "in_reply_to"
			}
		}
		if findErr != nil && !errors.Is(findErr, gorm.ErrRecordNotFound) {
			return findErr
		}
		if part.ID == 0 && callID != "" {
			part, findErr = findLatest(baseQuery().Where("sms_delivery_part.call_id = ?", callID))
			if part.ID != 0 {
				correlationMethod = "call_id"
			}
			if findErr != nil && !errors.Is(findErr, gorm.ErrRecordNotFound) {
				return findErr
			}
		}
		if part.ID == 0 && rpMR >= 0 {
			cutoff := at.Add(-120 * time.Second)
			var candidates []SMSDeliveryPart
			candidateQuery := baseQuery().
				Where("sms_delivery_part.rp_mr = ? AND sms_delivery_part.created_at >= ?", rpMR, cutoff).
				Where("sms_delivery_part.state IN ?", []string{
					SMSDeliveryPartStatePending,
					SMSDeliveryPartStateAcked,
					SMSDeliveryPartStateDeliveryPending,
					SMSDeliveryPartStateDeliveryUnconfirmed,
					SMSDeliveryPartStateDelivered,
					SMSDeliveryPartStateDeliveryFailed,
					SMSDeliveryPartStateFailed,
					SMSDeliveryPartStateTimeout,
				}).
				Order("sms_delivery_part.created_at desc").
				Limit(2).
				Find(&candidates)
			if candidateQuery.Error != nil {
				return candidateQuery.Error
			}
			switch len(candidates) {
			case 0:
				findErr = gorm.ErrRecordNotFound
			case 1:
				part = candidates[0]
				findErr = nil
				correlationMethod = "rp_mr"
			default:
				return ErrSMSDeliveryReportAmbiguous
			}
			if findErr != nil && !errors.Is(findErr, gorm.ErrRecordNotFound) {
				return findErr
			}
		}
		if part.ID == 0 {
			return gorm.ErrRecordNotFound
		}

		// A valid RP transaction has one terminal result. Duplicate or
		// contradictory late reports must not flip an already-terminal part.
		if part.State == SMSDeliveryPartStatePending {
			reportAt := at
			updates := map[string]any{
				"in_reply_to": inReplyTo,
				"state":       state,
				"sip_code":    sipCode,
				"rp_cause":    rpCause,
				"error_text":  strings.TrimSpace(errText),
				"report_at":   &reportAt,
				"updated_at":  at,
			}
			if err := tx.Model(&SMSDeliveryPart{}).
				Where("id = ? AND state = ?", part.ID, SMSDeliveryPartStatePending).
				Updates(updates).Error; err != nil {
				return err
			}
		}
		if err := tx.First(&part, part.ID).Error; err != nil {
			return err
		}
		if err := recomputeSMSDelivery(tx, part.MessageID, at); err != nil {
			return err
		}
		return syncVoWiFiSMSHistoryStatusFromDelivery(tx, part.MessageID)
	})
	if err != nil {
		return SMSDeliveryPart{}, err
	}
	part.CorrelationMethod = correlationMethod
	return part, nil
}

func syncVoWiFiSMSHistoryStatusFromDelivery(database *gorm.DB, messageID string) error {
	if database == nil {
		return nil
	}
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return nil
	}
	var delivery SMSDelivery
	if err := database.Select("state").Where("message_id = ?", messageID).First(&delivery).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	status := voWiFiSMSHistoryStatusForDeliveryState(delivery.State, 4)
	return database.Model(&SMS{}).
		Where("message_id = ? AND type = ?", messageID, 2).
		Update("status", status).Error
}

func RecomputeSMSDelivery(messageID string, at time.Time) error {
	if DB == nil {
		return nil
	}
	return recomputeSMSDelivery(DB, messageID, at)
}

func recomputeSMSDelivery(database *gorm.DB, messageID string, at time.Time) error {
	if database == nil {
		return nil
	}
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return nil
	}
	if at.IsZero() {
		at = time.Now()
	}

	var expectedTotal int
	var delivery SMSDelivery
	if err := database.Select("parts_total", "state", "last_error").Where("message_id = ?", messageID).First(&delivery).Error; err == nil {
		expectedTotal = delivery.PartsTotal
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	var total int64
	if err := database.Model(&SMSDeliveryPart{}).Where("message_id = ?", messageID).Count(&total).Error; err != nil {
		return err
	}
	if total == 0 {
		return nil
	}
	if expectedTotal <= 0 {
		expectedTotal = int(total)
	}
	var acked int64
	if err := database.Model(&SMSDeliveryPart{}).Where("message_id = ? AND state IN ?", messageID, []string{
		SMSDeliveryPartStateAcked,
		SMSDeliveryPartStateDeliveryPending,
		SMSDeliveryPartStateDeliveryUnconfirmed,
		SMSDeliveryPartStateDelivered,
		SMSDeliveryPartStateDeliveryFailed,
	}).Count(&acked).Error; err != nil {
		return err
	}
	var failedPart SMSDeliveryPart
	failErr := database.Model(&SMSDeliveryPart{}).
		Where("message_id = ? AND state IN ?", messageID, []string{SMSDeliveryPartStateFailed, SMSDeliveryPartStateTimeout, SMSDeliveryPartStateDeliveryFailed}).
		Order("updated_at desc").
		First(&failedPart).Error
	state := SMSDeliveryStatePending
	lastError := ""
	if failErr == nil {
		state = SMSDeliveryStateFailed
		lastError = strings.TrimSpace(failedPart.ErrorText)
	} else if errors.Is(failErr, gorm.ErrRecordNotFound) {
		var delivered int64
		if err := database.Model(&SMSDeliveryPart{}).Where("message_id = ? AND state = ?", messageID, SMSDeliveryPartStateDelivered).Count(&delivered).Error; err != nil {
			return err
		}
		var deliveryPending int64
		if err := database.Model(&SMSDeliveryPart{}).Where("message_id = ? AND state = ?", messageID, SMSDeliveryPartStateDeliveryPending).Count(&deliveryPending).Error; err != nil {
			return err
		}
		var deliveryUnconfirmed int64
		if err := database.Model(&SMSDeliveryPart{}).Where("message_id = ? AND state = ?", messageID, SMSDeliveryPartStateDeliveryUnconfirmed).Count(&deliveryUnconfirmed).Error; err != nil {
			return err
		}
		if delivered == int64(expectedTotal) && total == int64(expectedTotal) {
			state = SMSDeliveryStateDelivered
		} else if deliveryUnconfirmed > 0 && deliveryPending == 0 && delivered+deliveryUnconfirmed == int64(expectedTotal) && total == int64(expectedTotal) {
			state = SMSDeliveryStateDeliveryUnconfirmed
		} else if delivered > 0 || deliveryPending > 0 || deliveryUnconfirmed > 0 {
			state = SMSDeliveryStateDeliveryPending
		} else if acked == int64(expectedTotal) && total == int64(expectedTotal) {
			state = SMSDeliveryStateAcked
		} else if acked > 0 {
			state = SMSDeliveryStatePartialAck
		}
	} else {
		return failErr
	}
	if strings.EqualFold(strings.TrimSpace(delivery.State), SMSDeliveryStateFailed) {
		state = SMSDeliveryStateFailed
		if lastError == "" {
			lastError = strings.TrimSpace(delivery.LastError)
		}
	}
	if strings.EqualFold(strings.TrimSpace(delivery.State), SMSDeliveryStateDelivered) {
		state = SMSDeliveryStateDelivered
		lastError = ""
	}

	return database.Model(&SMSDelivery{}).Where("message_id = ?", messageID).Updates(map[string]any{
		"acks":       int(acked),
		"state":      state,
		"last_error": lastError,
		"updated_at": at,
	}).Error
}

func GetSMSDeliveryStatus(messageID string) (*SMSDeliveryStatus, error) {
	if DB == nil {
		return nil, gorm.ErrRecordNotFound
	}
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return nil, gorm.ErrRecordNotFound
	}
	var delivery SMSDelivery
	if err := DB.Where("message_id = ?", messageID).First(&delivery).Error; err != nil {
		return nil, err
	}
	var parts []SMSDeliveryPart
	if err := DB.Where("message_id = ?", messageID).Order("part_no asc").Find(&parts).Error; err != nil {
		return nil, err
	}
	out := &SMSDeliveryStatus{
		MessageID:  delivery.MessageID,
		IMSI:       delivery.IMSI,
		ICCID:      delivery.ICCID,
		DeviceID:   delivery.DeviceID,
		Peer:       delivery.Peer,
		Content:    delivery.Content,
		PartsTotal: delivery.PartsTotal,
		Acks:       delivery.Acks,
		State:      delivery.State,
		LastError:  delivery.LastError,
		CreatedAt:  delivery.CreatedAt,
		UpdatedAt:  delivery.UpdatedAt,
		Parts:      parts,
	}
	return out, nil
}

func UpdateSMSDeliveryState(messageID, state, lastError string, acks int, at time.Time) error {
	if DB == nil {
		return nil
	}
	messageID = strings.TrimSpace(messageID)
	if messageID == "" {
		return nil
	}
	if at.IsZero() {
		at = time.Now()
	}
	updates := map[string]any{"updated_at": at}
	if strings.TrimSpace(state) != "" {
		updates["state"] = strings.TrimSpace(state)
	}
	if acks >= 0 {
		updates["acks"] = acks
	}
	updates["last_error"] = strings.TrimSpace(lastError)
	return DB.Model(&SMSDelivery{}).Where("message_id = ?", messageID).Updates(updates).Error
}
