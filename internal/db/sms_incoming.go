package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
)

// SMSIncomingPartJournal retains decoded, incomplete parts across restarts.
// Completed entries retain only correlation metadata, never another plaintext copy.
type SMSIncomingPartJournal struct {
	Fingerprint string `gorm:"primaryKey"`
	AssemblyKey string `gorm:"index:idx_incoming_assembly,priority:1"`
	MessageID   string `gorm:"index:idx_incoming_assembly,priority:2"`
	Sequence    int
	Content     string
	Timestamp   time.Time `gorm:"index:idx_incoming_assembly,priority:3"`
	CreatedAt   time.Time
}

type IncomingSMSPart struct {
	Fingerprint, IMSI, Sender, Content        string
	Timestamp                                 time.Time
	Reference, ReferenceBits, Total, Sequence int
}

type IncomingSMSResult struct {
	Stored bool
	SMS    SMS
}

// StoreIncomingSMSPart commits the fragment, completed inbox row and contacts
// atomically. A successful incomplete result is durable and may be RP-ACKed.
func StoreIncomingSMSPart(part IncomingSMSPart, assemblyWindow time.Duration) (IncomingSMSResult, error) {
	var result IncomingSMSResult
	if DB == nil {
		return result, errors.New("SMS database unavailable")
	}
	if part.IMSI == "" || part.Sender == "" || part.Fingerprint == "" || part.Timestamp.IsZero() ||
		part.Total < 1 || part.Total > 255 || part.Sequence < 1 || part.Sequence > part.Total || assemblyWindow <= 0 {
		return result, errors.New("invalid incoming SMS part metadata")
	}
	identity, _ := json.Marshal([]any{part.IMSI, part.Sender, part.ReferenceBits, part.Reference, part.Total})
	key := sha256.Sum256(identity)
	journal := SMSIncomingPartJournal{Fingerprint: part.Fingerprint, AssemblyKey: hex.EncodeToString(key[:]),
		Sequence: part.Sequence, Content: part.Content, Timestamp: part.Timestamp.Truncate(time.Second)}
	// Resolve identity before opening the single-connection SQLite transaction.
	iccid := GetICCIDForIMSI(part.IMSI)
	localPhone, _ := GetSIMCardPhoneNumberByIMSI(part.IMSI)
	err := DB.Transaction(func(tx *gorm.DB) error {
		var duplicate int64
		if err := tx.Model(&SMSIncomingPartJournal{}).Where("fingerprint = ?", part.Fingerprint).Count(&duplicate).Error; err != nil {
			return err
		}
		if duplicate != 0 {
			return nil
		}
		if err := tx.Create(&journal).Error; err != nil {
			return err
		}
		fragments := []SMSIncomingPartJournal{journal}
		if part.Total > 1 {
			if err := tx.Where("assembly_key = ? AND message_id = ? AND timestamp BETWEEN ? AND ?", journal.AssemblyKey, "",
				journal.Timestamp.Add(-assemblyWindow), journal.Timestamp.Add(assemblyWindow)).Order("sequence").Find(&fragments).Error; err != nil {
				return err
			}
		}
		seen := make(map[int]bool, len(fragments))
		for _, fragment := range fragments {
			if seen[fragment.Sequence] {
				return errors.New("ambiguous incoming SMS concatenation reference")
			}
			seen[fragment.Sequence] = true
		}
		if len(fragments) < part.Total {
			return nil
		}
		if len(fragments) != part.Total {
			return errors.New("invalid incoming SMS fragment count")
		}
		var content strings.Builder
		fingerprints := make([]string, 0, len(fragments))
		for index, fragment := range fragments {
			if fragment.Sequence != index+1 {
				return fmt.Errorf("incomplete incoming SMS sequence")
			}
			content.WriteString(fragment.Content)
			fingerprints = append(fingerprints, fragment.Fingerprint)
		}
		messageID := "ims-in-" + fragments[0].Fingerprint
		sms := SMS{MessageID: messageID, IMSI: part.IMSI, ICCID: iccid, Peer: part.Sender,
			Sender: part.Sender, LocalPhone: localPhone, Recipient: localPhone, Content: content.String(),
			Type: 1, Status: 0, Timestamp: fragments[0].Timestamp}
		// A modem may deliver the same SMS over QMI as well as IMS. Only an exact
		// sender/content/service-centre-time match is a duplicate, not a later OTP.
		var existing int64
		if err := tx.Model(&SMS{}).Where("imsi = ? AND type = 1 AND sender = ? AND content = ? AND timestamp = ?",
			part.IMSI, part.Sender, sms.Content, sms.Timestamp).Count(&existing).Error; err != nil {
			return err
		}
		if existing == 0 {
			if err := tx.Create(&sms).Error; err != nil {
				return err
			}
			if err := upsertSMSContactFromSMS(tx, &sms); err != nil {
				return err
			}
			result = IncomingSMSResult{Stored: true, SMS: sms}
		}
		return tx.Model(&SMSIncomingPartJournal{}).Where("fingerprint IN ?", fingerprints).
			Updates(map[string]any{"message_id": messageID, "content": ""}).Error
	})
	if err != nil {
		return IncomingSMSResult{}, err
	}
	return result, nil
}
