package imscore

import (
	"reflect"
	"testing"

	"github.com/emiago/sipgo/sip"
)

func TestFinalizeRegisterSuccessPreservesServiceRoutes(t *testing.T) {
	want := []string{
		"<sip:pcscf.ims.example.invalid;lr>",
		"<sip:orig@scscf.ims.example.invalid;lr>",
	}
	response := sip.NewResponse(sip.StatusOK, "OK")
	for _, route := range want {
		response.AppendHeader(sip.NewHeader("Service-Route", route))
	}

	result, err := finalizeRegisterSuccess(
		Config{DeviceID: "test-device"},
		registerState{verifyHeader: "verified"},
		response,
	)
	if err != nil {
		t.Fatalf("finalizeRegisterSuccess: %v", err)
	}
	if !reflect.DeepEqual(result.serviceRoutes, want) {
		t.Fatalf("service routes = %v, want %v", result.serviceRoutes, want)
	}
}

func TestInternalConfigFromIMSPreservesSMSC(t *testing.T) {
	config := internalConfigFromIMS(
		IMSConfig{},
		StartSessionInput{SMSC: "+15550102030"},
	)
	if config.SMSC != "+15550102030" {
		t.Fatalf("SMSC was not preserved")
	}
}
