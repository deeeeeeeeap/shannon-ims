package identity

import "testing"

func TestPrepareStartGiffgaffUsesCarrierDeviceModelIdentity(t *testing.T) {
	prepared, err := PrepareStart(PrepareStartInput{
		DeviceID: "wwan0",
		Profile: Profile{
			IMSI: "001010000000001",
			MCC:  "234",
			MNC:  "10",
			IMEI: "861234567890123",
		},
	})
	if err != nil {
		t.Fatalf("PrepareStart() err=%v", err)
	}
	if prepared.EffectiveCarrier.PresetID != "giffgaff_23410" {
		t.Fatalf("preset_id=%q, want giffgaff_23410", prepared.EffectiveCarrier.PresetID)
	}
	if prepared.IdentityIMEISource != "carrier_device_model" {
		t.Fatalf("identity_source=%q, want carrier_device_model", prepared.IdentityIMEISource)
	}
	got := prepared.IMSIdentity
	if got.RequestedSource != "derived" || got.ActualSource != "derived" || got.Applied {
		t.Fatalf("ims identity=%+v", got)
	}
}