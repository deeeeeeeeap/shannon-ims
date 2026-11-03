package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/1239t/vohive/internal/config"
	"github.com/gin-gonic/gin"
)

func TestPasswordRotationConcurrentWithSessionValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("web:\n  username: synthetic-user\n  password: synthetic-old-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{
		auth:          config.WebConfig{Username: "synthetic-user", Password: "synthetic-old-value"},
		configPath:    path,
		sessionSecret: bytes.Repeat([]byte{0x42}, sessionSecretSize),
	}
	token, _, err := s.issueSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	started, stop, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		close(started)
		for {
			select {
			case <-stop:
				return
			default:
				s.isSessionTokenValid(token, time.Now())
			}
		}
	}()
	<-started
	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/settings/password", bytes.NewBufferString(`{"old_password":"synthetic-old-value","new_password":"synthetic-new-value","confirm_password":"synthetic-new-value"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	s.handleChangePassword(ctx)
	close(stop)
	<-done
	if response.Code != http.StatusOK {
		t.Fatalf("password change status=%d", response.Code)
	}
	if s.isSessionTokenValid(token, time.Now()) {
		t.Fatal("old session survived password rotation")
	}
	fresh, _, err := s.issueSessionToken()
	if err != nil || !s.isSessionTokenValid(fresh, time.Now()) {
		t.Fatal("new session is invalid")
	}
}
