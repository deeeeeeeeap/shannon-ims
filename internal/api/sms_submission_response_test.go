package api

import "testing"

func TestSMSSubmissionResponseMessageKeepsRPAckDistinctFromDelivery(t *testing.T) {
	tests := []struct {
		state string
		want  string
	}{
		{state: "pending", want: "短信已提交，等待运营商回执"},
		{state: "acked", want: "短信中心已确认提交（不代表收件人已收到）"},
		{state: "delivery_pending", want: "短信中心已确认提交，等待最终投递状态"},
		{state: "delivery_unconfirmed", want: "短信中心已完成处理，但未确认收件终端收到"},
		{state: "delivered", want: "短信状态报告已确认收件终端收到"},
		{state: "failed", want: "短信发送失败"},
		{state: "", want: "短信已提交，等待运营商回执"},
	}
	for _, test := range tests {
		if got := smsSubmissionResponseMessage(test.state); got != test.want {
			t.Fatalf("state=%q message=%q want=%q", test.state, got, test.want)
		}
	}
}

func TestNormalizeSMSDeliveryStateUsesPathSpecificFailureFallback(t *testing.T) {
	tests := []struct {
		state    string
		fallback string
		want     string
	}{
		{state: "", fallback: "failed", want: "failed"},
		{state: "unknown", fallback: "failed", want: "failed"},
		{state: "partial_ack", fallback: "failed", want: "partial_ack"},
		{state: "ACKED", fallback: "failed", want: "acked"},
		{state: "DELIVERED", fallback: "failed", want: "delivered"},
	}
	for _, test := range tests {
		if got := normalizeSMSDeliveryState(test.state, test.fallback); got != test.want {
			t.Fatalf("state=%q fallback=%q got=%q want=%q", test.state, test.fallback, got, test.want)
		}
	}
}
