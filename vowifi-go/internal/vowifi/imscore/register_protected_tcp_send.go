package imscore

import (
	"context"
	"errors"
	"fmt"

	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
	"github.com/emiago/sipgo/sip"
)

// Phase D step 3 wiring: the protected TCP branch of runSecureAuthenticatedRegister.
//
// The order below is the whole point of this file and is fixed by TS 33.203
// clause 7.1 Ports item 1 plus TS 24.229 clause 3.1 NOTE 3:
//
//	install IPsec                (already done by the caller)
//	  -> build the transport-neutral base request
//	    -> preview its UDP framing cost (on a clone, no mutation)
//	      -> decide the protected transport
//	        -> provisional runtime: one carrier, one stack, one pump
//	          -> server listener ready on the stable port_us
//	            -> client handshake from the rotating port_uc
//	              -> the single protected REGISTER
//
// The listener must precede the send because the P-CSCF may open its own
// port_pc -> port_us connection the instant it accepts the REGISTER, and that
// flow is the only one a terminating request can use. Registering first and
// listening afterwards yields a registration that looks healthy and silently
// drops every NOTIFY, MESSAGE and terminating INVITE.
//
// Nothing here logs SIP text, an identity, an address, a port value, an SPI or
// key material. Only derived lengths and closed enums reach a diagnostic.

// runProtectedTCPAuthenticatedRegister runs the protected exchange over a real
// TCP flow.
//
// The `handled` return distinguishes "this path owns the outcome" from "the
// caller should use the legacy UDP path". It is false only when the decision
// resolved to UDP; every TCP outcome, success or failure, is handled here and
// must not be retried on UDP.
func runProtectedTCPAuthenticatedRegister(
	ctx context.Context,
	cfg Config,
	swuTCP voiceclient.SWUTCPDialer,
	state *registerState,
	lastReq *sip.Request,
	lastRes *sip.Response,
) (result *registerResult, handled bool, err error) {
	if state == nil {
		return nil, true, newProtectedPhaseError(protectedPhaseStageRuntime,
			fmt.Errorf("imscore: protected TCP requires register state"))
	}

	// 1. The transport-neutral base request. Built once; AKA is not re-run because
	// buildAuthenticatedRegister reuses the Authorization already computed for the
	// challenged request.
	base, _, err := buildAuthenticatedRegister(cfg, *state, lastReq, lastRes)
	if err != nil {
		return nil, true, newProtectedPhaseError(protectedPhaseStageSend, err)
	}

	// 2. Preview the UDP cost on a CLONE. This must not advance CSeq, add a Via or
	// touch the base in any way, or the final request would drift.
	previewLen, err := previewProtectedRegisterUDPLen(cfg, *state, base)
	if err != nil {
		return nil, true, newProtectedPhaseError(protectedPhaseStageSend, err)
	}

	// 3. Decide. A pure function of (template, configured mode, length).
	plan, err := decideProtectedRegisterTransport(cfg, cfg.ProtectedTransport, previewLen)
	if err != nil {
		return nil, true, newProtectedPhaseError(protectedPhaseStageActivation, err)
	}
	if plan.Transport != protectedTransportTCP {
		// Not our path. The caller runs the legacy UDP flow unchanged.
		return nil, false, nil
	}

	// From here the outcome belongs to this function.
	handled = true

	// 4. The provisional runtime. It returns already listening, so a runtime whose
	// terminating path is missing is not observable.
	runtime, err := startProtectedTCPRuntime(ctx, cfg, swuTCP, *state)
	if err != nil {
		return nil, handled, newProtectedPhaseError(protectedPhaseStageRuntime, err)
	}
	// Until ownership is transferred on success, every exit closes and joins it.
	defer runtime.CloseUnlessTransferred()

	// 5. The activation gate, against the REAL runtime state rather than a
	// compile-time constant, and against this state's generation and policy.
	if gateErr := authorizeProtectedTCPActivation(plan, runtime.Activation()); gateErr != nil {
		return nil, handled, newProtectedPhaseError(protectedPhaseStageActivation, gateErr)
	}
	if gateErr := verifyProtectedActivationMatchesRuntime(runtime, runtime.Activation()); gateErr != nil {
		return nil, handled, newProtectedPhaseError(protectedPhaseStageActivation, gateErr)
	}
	if gateErr := verifyProtectedRuntimeMatchesState(runtime, *state); gateErr != nil {
		return nil, handled, newProtectedPhaseError(protectedPhaseStageActivation, gateErr)
	}

	// 6. The client flow. Bound to the rotating port_uc, connecting to the winning
	// candidate's port_ps, advertising the derived safe MSS in its SYN.
	conn, err := runtime.DialClientFlow(ctx)
	if err != nil {
		return nil, handled, newProtectedPhaseError(protectedPhaseStageHandshake, err)
	}
	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()

	// 7. The single final request, built from the untouched base for this exact
	// transport. Via carries the TCP token and no rport; Contact keeps port_us;
	// Call-ID is reused; CSeq advances exactly once.
	req, err := buildFinalProtectedRegisterRequest(cfg, *state, base, protectedTransportTCP)
	if err != nil {
		return nil, handled, newProtectedPhaseError(protectedPhaseStageSend, err)
	}

	serialized := req.String()

	// No UDP-model prediction is emitted here. logProtectedRegisterMessageSize and
	// logProtectedTransportDecision both derive inner_packet_len from
	// registerProtectedInnerPacketLen, which models ONE ESP-encapsulated UDP
	// datagram. On this path the MSS clamp splits the request into segments that
	// are each encapsulated separately, so that number describes a packet which is
	// never built. The live 2026-07-27 run reported inner_packet_len=1452 and
	// fragmented=true for exactly such a phantom packet, which made the log unable
	// to either prove or disprove fragmentation.
	//
	// What this path emits instead is measured, and it is emitted on EVERY exit
	// below - including the failures. A measurement that only appears on success is
	// useless for diagnosing a stall.
	var transport *streamRegisterTransport
	measurement := protectedTCPMeasurement{
		SerializedMessageLen: len(serialized),
		EffectiveMSS:         runtime.SafeMSS(),
		Closure:              protectedTCPClosureUnknown,
	}
	defer func() {
		mergeProtectedTCPTransportMeasurement(&measurement, transport)
		mergeProtectedTCPRuntimeStats(&measurement, runtime)
		logProtectedTCPMeasurement(measurement)
	}()

	// 8. Send once, and read the response from the SAME connection. A stream
	// framer per connection turns the byte stream back into one SIP message.
	transport, err = newStreamRegisterTransport(conn)
	if err != nil {
		measurement.Closure = protectedTCPClosureWriteFailed
		err = newProtectedPhaseError(protectedPhaseStageSend, err)
		return nil, handled, err
	}
	if err = transport.SendPayload(ctx, []byte(serialized)); err != nil {
		measurement.Closure = protectedTCPClosureWriteFailed
		err = newProtectedPhaseError(protectedPhaseStageSend, err)
		return nil, handled, err
	}
	finalRes, err := transport.ReadResponse(ctx)
	if err != nil {
		// Emit the bounded ESP counters so a silent transform or replay drop can be
		// told apart from nothing ever arriving.
		logProtectedRegisterReadFailure(state)
		measurement.Closure = classifyProtectedTCPReadFailure(err)
		err = newProtectedPhaseError(protectedPhaseStageRead, err)
		return nil, handled, err
	}
	measurement.Closure = protectedTCPClosureResponseComplete
	if !registerResponseCorrelates(req, finalRes) {
		err = newProtectedPhaseError(protectedPhaseStageResponse,
			errors.New("response correlation mismatch"))
		return nil, handled, err
	}
	if finalRes.StatusCode != sip.StatusOK {
		err = newProtectedPhaseError(protectedPhaseStageResponse, fmt.Errorf(
			"status=%d result=%s",
			finalRes.StatusCode, registerStatusResult(finalRes.StatusCode)))
		return nil, handled, err
	}

	// 9. Success. Ownership of the runtime moves to the result exactly once, so
	// the deferred CloseUnlessTransferred above becomes a no-op.
	result, err = finalizeRegisterSuccess(cfg, *state, finalRes)
	if err != nil {
		return nil, handled, err
	}
	if err = transferProtectedTCPMessagingOwnership(result, runtime, transport); err != nil {
		return nil, handled, err
	}
	// A TCP result must carry no legacy secure channel: service_lifecycle keys the
	// legacy transport runtime off secureConn, and two runtimes would mean two
	// readers of one ESP carrier.
	result.secureConn = nil
	return result, handled, nil
}

func transferProtectedTCPMessagingOwnership(result *registerResult, runtime *protectedTCPRuntime, transport *streamRegisterTransport) error {
	if result == nil || runtime == nil || transport == nil {
		return errors.New("imscore: protected TCP messaging ownership is unavailable")
	}
	if result.protectedTCP != nil || result.protectedClientConn != nil {
		return errors.New("imscore: protected TCP messaging ownership was already assigned")
	}
	clientConn := transport.ReleaseConn()
	if clientConn == nil {
		return errors.New("imscore: protected TCP client flow was not transferable at a message boundary")
	}
	transferred, ok := runtime.TakeOwnership()
	if !ok || transferred == nil {
		_ = clientConn.Close()
		return errors.New("imscore: protected TCP runtime ownership was already taken")
	}
	result.protectedTCP = transferred
	result.protectedClientConn = clientConn
	return nil
}
