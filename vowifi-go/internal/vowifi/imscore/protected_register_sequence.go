package imscore

import (
	"errors"
	"fmt"
)

// Phase D step 3: the fixed order of the protected REGISTER exchange, and the
// checks that keep one generation's runtime from serving another's request.
//
//	install IPsec
//	  -> provisional runtime (one ESP carrier, one stack, one inbound pump)
//	    -> server listener ready on the stable port_us
//	      -> client TCP handshake from the rotating port_uc
//	        -> protected REGISTER written
//
// The listener must be ready first because TS 33.203 clause 7.1 Ports item 1
// requires the P-CSCF to open its OWN connection to port_us before sending any
// request to the UE, and TS 24.229 clause 3.1 NOTE 3 gives it no alternative
// flow. The P-CSCF may do that the moment it accepts our REGISTER, so listening
// afterwards is not a narrow race: it is a registration that looks healthy while
// silently dropping every terminating INVITE, MESSAGE and NOTIFY.
//
// Everything here is a comparison over derived integers and pointers. No SIP
// text, identity, address, port value, SPI or key material is logged.

// verifyProtectedActivationMatchesRuntime checks an activation against the
// runtime it claims to describe.
//
// The activation is passed by value through the send path, so it can go stale:
// an SA replacement retires a generation while an in-flight attempt still holds
// the old value. Comparing it back against the live runtime is what makes the
// gate reflect reality rather than a snapshot.
func verifyProtectedActivationMatchesRuntime(rt *protectedTCPRuntime, activation protectedTCPActivation) error {
	if rt == nil {
		return errors.New("imscore: protected TCP runtime is missing")
	}
	current := rt.Activation()
	if !current.ready() {
		return &protectedTCPUnavailableError{reason: protectedTransportReasonServerFlowPending}
	}
	if !activation.ready() {
		return &protectedTCPUnavailableError{reason: protectedTransportReasonServerFlowPending}
	}
	if activation.Generation != current.Generation {
		// Not merely stale: a mismatch means the caller is about to send on an SA
		// that is not the one it authorized.
		return &protectedTCPUnavailableError{reason: protectedTransportReasonGenerationMismatch}
	}
	return nil
}

// verifyProtectedRuntimeMatchesState checks that a runtime was built from the
// state that is about to use it.
//
// A runtime carries its own policy and transform. If those came from a different
// registration attempt, packets would be protected with the wrong keys and bound
// to the wrong port pair - and both failures are silent on the wire.
func verifyProtectedRuntimeMatchesState(rt *protectedTCPRuntime, state registerState) error {
	if rt == nil {
		return errors.New("imscore: protected TCP runtime is missing")
	}
	if state.generation == 0 {
		return errors.New("imscore: register state carries no SA generation")
	}
	if rt.Generation() != state.generation {
		return &protectedTCPUnavailableError{reason: protectedTransportReasonGenerationMismatch}
	}
	if rt.transform != state.transport {
		return &protectedTCPUnavailableError{reason: protectedTransportReasonPolicyMismatch}
	}
	if rt.ProtectedServerPort() != state.ipsecPolicy.FlowS.LocalPort {
		return &protectedTCPUnavailableError{reason: protectedTransportReasonPolicyMismatch}
	}
	if rt.ProtectedClientPort() != state.ipsecPolicy.FlowC.LocalPort {
		return &protectedTCPUnavailableError{reason: protectedTransportReasonPolicyMismatch}
	}
	return nil
}

// protectedResultUsesTCPRuntime reports whether a successful registration owns a
// protected TCP runtime rather than a legacy UDP secure channel.
func protectedResultUsesTCPRuntime(result *registerResult) bool {
	return result != nil && result.protectedTCP != nil
}

// shouldStartLegacyTransportRuntime decides whether service_lifecycle may start
// the pre-existing transportRuntime.
//
// It must not start alongside a protected TCP runtime. The legacy runtime opens
// its own port-s path over the SecureChannelConn, so running both would put two
// readers on one ESP carrier - and swuNetstack.dispatchRawIPPacket delivers a
// COPY to every matching raw connection, so each inbound packet would be
// processed twice by two independent replay windows.
func shouldStartLegacyTransportRuntime(result *registerResult) bool {
	if result == nil {
		return false
	}
	if protectedResultUsesTCPRuntime(result) {
		return false
	}
	return result.secureConn != nil && result.transport != nil && !result.secureConn.PacketMode()
}

// takeProtectedTCPOwnership moves the runtime out of the result exactly once.
//
// The second caller gets (nil, false) rather than the same pointer, so a
// deferred cleanup cannot close a runtime the Service now owns, and two owners
// can never both call Close.
func takeProtectedTCPOwnership(result *registerResult) (*protectedTCPRuntime, bool) {
	if result == nil || result.protectedTCP == nil {
		return nil, false
	}
	taken := result.protectedTCP
	result.protectedTCP = nil
	return taken, taken != nil
}

// adoptProtectedTCPResult moves the already-transferred runtime from a
// successful register result into the Service lifecycle. The register flow has
// already called TakeOwnership so its deferred cleanup cannot close the runtime;
// this method performs the second, pointer-level handoff exactly once.
func (s *Service) adoptProtectedTCPResult(result *registerResult) error {
	if s == nil {
		return errors.New("imscore: service is nil")
	}
	if err := assertProtectedChannelExclusivity(result); err != nil {
		return err
	}
	runtime, ok := takeProtectedTCPOwnership(result)
	if !ok || runtime == nil {
		return errors.New("imscore: protected TCP runtime ownership is unavailable")
	}
	if !runtime.Activation().ready() {
		runtime.Close()
		return errProtectedRuntimeNotReady
	}
	if s.protectedRuntimes == nil {
		s.protectedRuntimes = newProtectedRuntimeHolder()
	}
	if previous := s.protectedRuntimes.adopt(runtime); previous != nil {
		// Service.Start is an initial adoption, not a re-registration replacement.
		// Restore the incumbent and fail closed rather than silently owning two SAs.
		s.protectedRuntimes.adopt(previous)
		runtime.Close()
		return errors.New("imscore: protected TCP runtime is already active")
	}
	return nil
}

// assertProtectedChannelExclusivity fails when a result carries both transports.
//
// service_lifecycle keys several decisions off secureConn (messaging attach, the
// legacy runtime, PacketMode). A result holding both would make those decisions
// ambiguous, so the two are mutually exclusive by construction.
func assertProtectedChannelExclusivity(result *registerResult) error {
	if result == nil {
		return nil
	}
	if (result.protectedTCP == nil) != (result.protectedClientConn == nil) {
		return fmt.Errorf("imscore: protected TCP runtime and client flow must transfer together")
	}
	if result.protectedTCP != nil && result.secureConn != nil {
		return fmt.Errorf("imscore: registration carries both a protected TCP runtime and a legacy secure channel")
	}
	return nil
}
