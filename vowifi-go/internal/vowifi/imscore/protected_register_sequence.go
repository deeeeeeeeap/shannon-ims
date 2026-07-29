package imscore

import (
	"errors"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
)

func verifyProtectedActivationMatchesChannel(channel *ipsec3gpp.ProtectedChannelLease, activation protectedTCPActivation) error {
	if channel == nil || !channel.ServerFlowReady() || !activation.ready() {
		return &protectedTCPUnavailableError{reason: protectedTransportReasonServerFlowPending}
	}
	if activation.Generation != channel.Generation() {
		return &protectedTCPUnavailableError{reason: protectedTransportReasonGenerationMismatch}
	}
	return nil
}

func verifyProtectedChannelMatchesState(channel *ipsec3gpp.ProtectedChannelLease, state registerState) error {
	if channel == nil {
		return errors.New("imscore: protected channel lease is missing")
	}
	if state.generation == 0 || channel.Generation() != state.generation {
		return &protectedTCPUnavailableError{reason: protectedTransportReasonGenerationMismatch}
	}
	if channel.ClientPort() != state.portC || channel.ServerPort() != state.portS {
		return &protectedTCPUnavailableError{reason: protectedTransportReasonPolicyMismatch}
	}
	return nil
}
