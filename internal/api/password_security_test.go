package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/1239t/vohive/internal/config"
	"github.com/gin-gonic/gin"
)

func TestHandleChangePasswordRejectsReservedPassword(t *testing.T) {
	gin.SetMode(gin.TestMode)
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := []byte("web:\n  username: admin\n  password: current-unique-password\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	server := &Server{
		auth:       config.WebConfig{Username: "admin", Password: "current-unique-password"},
		configPath: path,
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/settings/password", bytes.NewBufferString(`{
		"old_password":"current-unique-password",
		"new_password":"admin",
		"confirm_password":"admin"
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	server.handleChangePassword(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(after, original) {
		t.Fatal("rejected password update modified the config file")
	}
}
