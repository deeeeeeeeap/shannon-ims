package swu

import (
	"context"
	"errors"
	"fmt"

	"github.com/1239t/swu-go/pkg/ikev2"
)

type IKEAuthInitialError struct {
	result     string
	notifyType string
	protocolID uint8
	dataLen    int
	cause      error
}

func (e *IKEAuthInitialError) Error() string {
	if e == nil {
		return "IKE_AUTH initial failed"
	}
	if e.result == "error_notify" {
		return fmt.Sprintf("IKE_AUTH initial failed: result=%s notify_type=%s protocol_id=%d data_len=%d",
			e.result, e.notifyType, e.protocolID, e.dataLen)
	}
	return fmt.Sprintf("IKE_AUTH initial failed: result=%s", e.result)
}

func (*IKEAuthInitialError) Stage() string { return "ike_auth_initial" }

func (e *IKEAuthInitialError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *IKEAuthInitialError) Result() string {
	if e == nil {
		return "malformed"
	}
	return e.result
}

func (e *IKEAuthInitialError) NotifyType() string {
	if e == nil {
		return ""
	}
	return e.notifyType
}

func (e *IKEAuthInitialError) ProtocolID() uint8 {
	if e == nil {
		return 0
	}
	return e.protocolID
}

func (e *IKEAuthInitialError) DataLen() int {
	if e == nil {
		return 0
	}
	return e.dataLen
}

func initialIKEAuthError(payloads []ikev2.Payload) error {
	hasEAP := false
	for _, payload := range payloads {
		if _, ok := payload.(*ikev2.EncryptedPayloadEAP); ok {
			hasEAP = true
		}
		notify, ok := payload.(*ikev2.EncryptedPayloadNotify)
		if !ok || notify.NotifyType >= 16384 {
			continue
		}
		return &IKEAuthInitialError{
			result:     "error_notify",
			notifyType: safeIKEAuthNotifyType(notify.NotifyType),
			protocolID: uint8(notify.ProtocolID),
			dataLen:    len(notify.NotifyData),
		}
	}
	if !hasEAP {
		return &IKEAuthInitialError{result: "missing_eap"}
	}
	return nil
}

func initialIKEAuthParseError(err error) error {
	var failure *ikeMessageFailure
	if errors.As(err, &failure) {
		return &IKEAuthInitialError{result: failure.result}
	}
	return &IKEAuthInitialError{result: "malformed"}
}

func initialIKEAuthSendError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return &IKEAuthInitialError{result: "canceled", cause: err}
	}
	return err
}

func safeIKEAuthNotifyType(notifyType uint16) string {
	switch notifyType {
	case ikev2.UNSUPPORTED_CRITICAL_PAYLOAD:
		return "unsupported_critical_payload"
	case ikev2.INVALID_IKE_SPI:
		return "invalid_ike_spi"
	case ikev2.INVALID_MAJOR_VERSION:
		return "invalid_major_version"
	case ikev2.INVALID_SYNTAX:
		return "invalid_syntax"
	case ikev2.INVALID_MESSAGE_ID:
		return "invalid_message_id"
	case ikev2.INVALID_SPI:
		return "invalid_spi"
	case ikev2.NO_PROPOSAL_CHOSEN:
		return "no_proposal_chosen"
	case ikev2.INVALID_KE_PAYLOAD:
		return "invalid_ke_payload"
	case ikev2.AUTHENTICATION_FAILED:
		return "authentication_failed"
	case ikev2.SINGLE_PAIR_REQUIRED:
		return "single_pair_required"
	case ikev2.NO_ADDITIONAL_SAS:
		return "no_additional_sas"
	case ikev2.INTERNAL_ADDRESS_FAILURE:
		return "internal_address_failure"
	case ikev2.FAILED_CP_REQUIRED:
		return "failed_cp_required"
	case ikev2.TS_UNACCEPTABLE:
		return "ts_unacceptable"
	case ikev2.INVALID_SELECTORS:
		return "invalid_selectors"
	case ikev2.TEMPORARY_FAILURE:
		return "temporary_failure"
	case ikev2.CHILD_SA_NOT_FOUND:
		return "child_sa_not_found"
	default:
		return "other_error_notify"
	}
}
