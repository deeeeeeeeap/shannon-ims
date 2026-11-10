package device

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/1239t/vohive/internal/backend"
	"github.com/1239t/vohive/internal/modem"
	"github.com/1239t/vohive/pkg/logger"
	"github.com/1239t/vohive/pkg/smscodec"
)

func decodeMBIMDeliverPDUHex(pduHex string) (sender, text string, ts time.Time, concat smscodec.ConcatInfo, err error) {
	raw, err := hex.DecodeString(pduHex)
	if err != nil {
		return "", "", time.Time{}, smscodec.ConcatInfo{}, fmt.Errorf("pdu hex 解析失败: %w", err)
	}
	if len(raw) < 1 {
		return "", "", time.Time{}, smscodec.ConcatInfo{}, fmt.Errorf("pdu 为空")
	}
	scLen := int(raw[0])
	off := 1 + scLen
	if off > len(raw) {
		return "", "", time.Time{}, smscodec.ConcatInfo{}, fmt.Errorf("SMSC 长度越界: scLen=%d len=%d", scLen, len(raw))
	}
	sender, text, ts, concat, err = smscodec.DecodeDeliverTPDU(raw[off:])
	if err != nil {
		return "", "", time.Time{}, smscodec.ConcatInfo{}, fmt.Errorf("DELIVER 解码失败: %w", err)
	}
	return sender, text, ts, concat, nil
}

func (w *Worker) handleNewSMSMBIM(reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	w.drainMBIMInbox(ctx, reason)
}

func (w *Worker) drainMBIMInbox(ctx context.Context, reason string) {
	lister, ok := w.Backend.(interface {
		ListSMS(context.Context) ([]backend.SMSSummary, error)
		ReadSMS(context.Context, int) (*backend.SMS, error)
		DeleteSMS(context.Context, int) error
	})
	if !ok {
		return
	}

	summaries, err := lister.ListSMS(ctx)
	if err != nil {
		logger.Warn(fmt.Sprintf("[%s] MBIM 列举短信失败", w.ID), "reason", reason, "err", err)
		return
	}
	for _, summary := range summaries {
		msg, err := lister.ReadSMS(ctx, summary.Index)
		if err != nil || msg == nil {
			logger.Warn(fmt.Sprintf("[%s] MBIM 读取短信失败", w.ID), "index", summary.Index, "err", err)
			continue
		}
		// 先交给接收流水线：入库（含分片落库与去重）成功后才删除模组里的副本。
		switch err := w.storeCellularDeliverPDU(msg.Content); {
		case err == nil:
		case errors.Is(err, modem.ErrIncomingSMSNotTaken):
			// 流水线不接管（没有数据库，或不是可入库的 SMS-DELIVER）：走原有的内存路径。
			sender, text, ts, concat, err := decodeMBIMDeliverPDUHex(msg.Content)
			if err != nil {
				logger.Warn(fmt.Sprintf("[%s] MBIM 短信解码失败", w.ID), "index", summary.Index, "err", err)
				continue
			}
			if concat.IsConcat {
				logger.Debug(fmt.Sprintf("[%s] 收到 MBIM 短信分片", w.ID), "ref", concat.Ref, "seq", concat.Seq, "total", concat.Total)
			}
			if complete, full := w.reassembler.Add(sender, concat, text); complete {
				if ts.IsZero() {
					ts = time.Now()
				}
				w.processSMS(sender, full, ts)
			}
		default:
			logger.Warn(fmt.Sprintf("[%s] MBIM 短信暂未入库，保留在模组中等待下次轮询", w.ID), "index", summary.Index, "err", err)
			continue
		}
		if err := lister.DeleteSMS(ctx, summary.Index); err != nil {
			logger.Debug(fmt.Sprintf("[%s] MBIM 删除已读短信失败", w.ID), "index", summary.Index, "err", err)
		}
	}
}
