package e911

import (
	"context"
	"errors"
)

var (
	ErrUnsupportedProvider      = errors.New("unsupported provider")
	ErrChallengeNotImplemented  = errors.New("challenge not implemented")
	ErrWebsheetUnavailable      = errors.New("websheet unavailable")
)

type HeaderPair struct {
	Key   string
	Value string
}

type HTTPRequest struct {
	Method      string
	URL         string
	Headers     []HeaderPair
	Body        []byte
	UserData    string
	ContentType string
	Title       string
}

type HTTPResponse struct {
	StatusCode int
	Headers    []HeaderPair
	Body       []byte
}

type HTTPClient interface {
	Do(req *HTTPRequest) (*HTTPResponse, error)
}

type Identity struct {
	IMSI        string
	IMEI        string
	MCC         string
	MNC         string
	SIPUsername string
	DisplayName string
	Name        string
	// CachedToken carries an entitlement token from a prior websheet round so a
	// resumed flow doesn't have to restart the challenge from scratch. Empty
	// unless a caller explicitly supplies one; never sourced from environment
	// variables or other debug/experimental channels.
	CachedToken string
}

type Request struct {
	Carrier     interface{}
	Identity    Identity
	AKAProvider interface{}
	Client      HTTPClient
	Trace       interface{}
}

func NewDefaultHTTPClient() HTTPClient { return &defaultClient{} }

type defaultClient struct{}

func (c *defaultClient) Do(req *HTTPRequest) (*HTTPResponse, error) {
	return &HTTPResponse{StatusCode: 200, Body: []byte{}}, nil
}

func StartEmergencyAddressUpdate(ctx context.Context, req Request) (*HTTPRequest, error) {
	return nil, ErrUnsupportedProvider
}
