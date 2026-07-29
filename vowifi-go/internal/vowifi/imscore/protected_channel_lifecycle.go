package imscore

import (
	"errors"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
)

// adoptProtectedChannelResult is the single ownership transition between the
// REGISTER attempt and the Service. The result loses its lease at the same
// linearization point, so it can never become a second close owner.
func (s *Service) adoptProtectedChannelResult(result *registerResult) (*ipsec3gpp.ProtectedChannelHandle, error) {
	if s == nil {
		return nil, errors.New("imscore: service is nil")
	}
	if s.protectedChannels == nil {
		return nil, errors.New("imscore: protected channel owner is unavailable")
	}
	if result == nil || result.channel == nil {
		return nil, errors.New("imscore: protected channel lease is unavailable")
	}
	lease := result.channel
	handle, err := s.protectedChannels.Adopt(lease)
	result.channel = nil
	if err != nil {
		_ = lease.Close()
		return nil, err
	}
	return handle, nil
}
