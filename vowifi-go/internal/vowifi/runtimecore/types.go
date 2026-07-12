package runtimecore

import (
	"context"

	"github.com/1239t/vowifi-go/runtimehost/identity"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

// ProxyConfig mirrors runtimehost.ProxyConfig for the IMS/SWu session layer.
type ProxyConfig struct {
	ID       string
	Addr     string
	Username string
	Password string
	Enabled  bool
}

// SessionConfig is the runtimecore view of a VoWiFi session bootstrap request.
// It is populated from runtimehost.StartRequest via ToSessionConfig.
type SessionConfig struct {
	Ctx             context.Context
	DeviceID        string
	TraceID         string
	Prepared        *identity.PreparedSession
	Profile         identity.Profile
	NetworkMode     string
	DataplaneMode   string
	Proxy           *ProxyConfig
	PCSCFAddr       string
	CellID          string
	RegisterProfile voiceclient.RegisterProfile
	SIPInstanceURN  string
	RegisterExpiry  int64
	DeliveryStore   messaging.DeliveryStore
	OnProgress      func(string)
}

// SessionResult is the live IMS session handle produced by runtimecore.
// runtimehost.Instance keeps a pointer for observability (API imscore status).
type SessionResult struct {
	DeviceID   string
	TraceID    string
	LocalAddr  string
	PCSCFAddr  string
	IMSService messaging.Service
	IMSStatus  func() map[string]interface{}
}