package backend

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/1239t/vohive/pkg/logger"
	"github.com/1239t/vohive/pkg/smscodec"
)

func (b *MBIMBackend) SendSMS(ctx context.Context, to, body string) error {
	return b.SendSMSWithOptions(ctx, to, body, smscodec.SubmitOptions{})
}

func (b *MBIMBackend) SendSMSWithOptions(ctx context.Context, to, body string, opts smscodec.SubmitOptions) error {
	submission, err := smscodec.PrepareSubmission(to, body, opts)
	if err != nil {
		return fmt.Errorf("PDU 编码失败: %w", err)
	}
	return b.SendPreparedSMS(ctx, submission)
}

// SendPreparedSMS 逐段发送一条已经校验并分段好的短信。
func (b *MBIMBackend) SendPreparedSMS(ctx context.Context, submission *smscodec.Submission) error {
	if submission == nil || submission.PartCount() == 0 {
		return errNoPreparedSMS
	}
	parts := submission.PartCount()
	for i := 0; i < parts; i++ {
		if _, err := b.source.SendSMS(ctx, submission.PDU(i)); err != nil {
			logger.Warn("MBIM 短信发送失败",
				"to_fingerprint", logger.Fingerprint(submission.To()),
				"part", i+1,
				"parts", parts,
				"err", err,
			)
			return fmt.Errorf("发送第 %d/%d 段失败: %w", i+1, parts, err)
		}
	}
	logger.Info("MBIM 短信发送成功",
		"to_fingerprint", logger.Fingerprint(submission.To()),
		"parts", parts,
		"alphabet", string(submission.Alphabet()))
	return nil
}

func (b *MBIMBackend) ReadSMS(ctx context.Context, index int) (*SMS, error) {
	rec, err := b.source.ReadSMS(ctx, uint32(index))
	if err != nil {
		return nil, err
	}
	return &SMS{Index: index, Content: hex.EncodeToString(rec.PDU)}, nil
}

func (b *MBIMBackend) DeleteSMS(ctx context.Context, index int) error {
	return b.source.DeleteSMS(ctx, uint32(index))
}

func (b *MBIMBackend) ListSMS(ctx context.Context) ([]SMSSummary, error) {
	recs, err := b.source.ListSMS(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]SMSSummary, 0, len(recs))
	for _, r := range recs {
		out = append(out, SMSSummary{Index: int(r.Index), Tag: int(r.Status)})
	}
	return out, nil
}

func (b *MBIMBackend) DeleteAllSMS(ctx context.Context) error {
	return b.source.DeleteAllSMS(ctx)
}

func (b *MBIMBackend) GetSMSC(ctx context.Context) (string, error) {
	return b.source.GetSMSC(ctx)
}

func (b *MBIMBackend) SetSMSC(ctx context.Context, smsc string) error {
	return b.source.SetSMSC(ctx, smsc)
}
