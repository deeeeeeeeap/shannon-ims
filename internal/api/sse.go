package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	defaultSSEWriteTimeout      = 15 * time.Second
	defaultSSEHeartbeatInterval = 15 * time.Second
)

type sseStream struct {
	context      *gin.Context
	controller   *http.ResponseController
	writeTimeout time.Duration
}

func newSSEStream(c *gin.Context, writeTimeout time.Duration) (*sseStream, error) {
	if c == nil || c.Writer == nil {
		return nil, fmt.Errorf("initialize SSE stream: response writer is required")
	}
	if writeTimeout <= 0 {
		writeTimeout = defaultSSEWriteTimeout
	}
	controller := http.NewResponseController(c.Writer)
	if err := controller.SetWriteDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("initialize SSE stream write deadline: %w", err)
	}
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	return &sseStream{
		context:      c,
		controller:   controller,
		writeTimeout: writeTimeout,
	}, nil
}

func (s *sseStream) Event(name string, data any) error {
	return s.write(func() error {
		s.context.SSEvent(name, data)
		return nil
	})
}

func (s *sseStream) Data(payload string) error {
	return s.write(func() error {
		_, err := fmt.Fprintf(s.context.Writer, "data: %s\n\n", payload)
		return err
	})
}

func (s *sseStream) Heartbeat() error {
	return s.write(func() error {
		_, err := fmt.Fprint(s.context.Writer, ": heartbeat\n\n")
		return err
	})
}

func (s *sseStream) write(write func() error) error {
	if s == nil || s.context == nil || s.controller == nil {
		return fmt.Errorf("write SSE stream: stream is unavailable")
	}
	if err := s.controller.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
		return fmt.Errorf("set SSE write deadline: %w", err)
	}
	writeErr := write()
	flushErr := s.controller.Flush()
	clearErr := s.controller.SetWriteDeadline(time.Time{})
	if writeErr != nil {
		return writeErr
	}
	if flushErr != nil {
		return fmt.Errorf("flush SSE stream: %w", flushErr)
	}
	if clearErr != nil {
		return fmt.Errorf("clear SSE write deadline: %w", clearErr)
	}
	return nil
}

func newSSEHeartbeat() *time.Ticker {
	return time.NewTicker(defaultSSEHeartbeatInterval)
}
