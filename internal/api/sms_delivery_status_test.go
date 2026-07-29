package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/db"
	"github.com/gin-gonic/gin"
)

func TestSMSDeliveryStatusRemainsReadableWithoutActiveVoWiFiInstance(t *testing.T) {
	previousDB := db.DB
	if err := db.Init(filepath.Join(t.TempDir(), "sms-delivery-status.db")); err != nil {
		t.Fatalf("db.Init: %v", err)
	}
	t.Cleanup(func() { db.DB = previousDB })

	at := time.Unix(1, 0).UTC()
	if err := db.CreateSMSDelivery("synthetic-message", "synthetic-imsi", "synthetic-device", "+10010", "synthetic", 1, at); err != nil {
		t.Fatalf("CreateSMSDelivery: %v", err)
	}
	if err := db.UpdateSMSDeliveryState("synthetic-message", db.SMSDeliveryStateAcked, "", 1, at.Add(time.Second)); err != nil {
		t.Fatalf("UpdateSMSDeliveryState: %v", err)
	}

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/sms/delivery/synthetic-message", nil)
	ctx.Params = gin.Params{{Key: "message_id", Value: "synthetic-message"}}

	(&Server{}).handleSMSDelivery(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 without active runtime instance", recorder.Code)
	}
	var response struct {
		Status   string `json:"status"`
		Delivery struct {
			State string `json:"state"`
		} `json:"delivery"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != "ok" || response.Delivery.State != db.SMSDeliveryStateAcked {
		t.Fatalf("delivery response status=%q state=%q", response.Status, response.Delivery.State)
	}
	for _, privateMarker := range [][]byte{[]byte("synthetic-imsi"), []byte("synthetic-device"), []byte("+10010"), []byte("synthetic\"")} {
		if bytes.Contains(recorder.Body.Bytes(), privateMarker) {
			t.Fatal("delivery status response exposed a private persistence field")
		}
	}
}
