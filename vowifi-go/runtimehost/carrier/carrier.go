// Package carrier resolves per-PLMN VoWiFi behavior: ePDG address overrides,
// AKA application preference, e911 entitlement availability, and policy blocks.
//
// Every PLMN works out of the box via the 3GPP TS 23.003 default (computed in
// the identity package). This package only holds the *exceptions*: operators
// whose real-world ePDG deployment deviates from the standard FQDN, or that
// need e911/policy handling. Those exceptions are loaded from an optional
// external JSON file so they can be updated without a rebuild.
package carrier

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Preset is a single PLMN override entry in the external carrier_overrides file.
type Preset struct {
	ID               string `json:"id"`
	MCC              string `json:"mcc"`
	MNC              string `json:"mnc"`
	EPDGAddr         string `json:"epdg_addr,omitempty"`
	AKAAppPreference string `json:"aka_app_preference,omitempty"` // "usim" | "isim" | "auto"
	// IMSTAC and IMSCellID are optional LTE identities used in Cellular-Network-Info
	// when live QMI cell readings are unavailable. Values may be decimal or hex in
	// JSON; giffgaff/O2 commonly use TAC 28673 and Cell ID 12345678.
	IMSTAC    uint32 `json:"ims_tac,omitempty"`
	IMSCellID uint32 `json:"ims_cell_id,omitempty"`
	// IMSCellIDMode controls utran-cell-id selection for IMS REGISTER:
	//   "" or "qmi_first" — live QMI, then carrier preset fallback
	//   "carrier_only"  — always use ims_tac/ims_cell_id preset
	//   "none"          — skip cell-id injection (REGISTER uses zero placeholder)
	IMSCellIDMode string `json:"ims_cell_id_mode,omitempty"`
	// IMSRegisterProfile selects a handset REGISTER mimic profile (e.g. "xiaomi_mi11").
	IMSRegisterProfile string `json:"ims_register_profile,omitempty"`
	// PhoneIMEI is the IMEI used to build urn:gsma:imei:... for +sip.instance spoofing.
	PhoneIMEI string `json:"phone_imei,omitempty"`
	// IMSPcscfAddr optionally overrides the IKE-discovered P-CSCF ("host:port").
	// Useful when ePDG assigns a silent node but a known-good P-CSCF responds.
	IMSPcscfAddr string `json:"ims_pcscf_addr,omitempty"`
	E911Enabled      bool   `json:"e911_enabled,omitempty"`
	E911Provider     string `json:"e911_provider,omitempty"`
	Blocked          bool   `json:"blocked,omitempty"`
}

type EffectiveCarrierConfigInput struct {
	MCC string
	MNC string
}

type EffectiveCarrierConfig struct {
	PresetID         string
	EPDGAddr         string
	AKAAppPreference string
	E911             struct {
		Enabled  bool
		Provider string
	}
}

type LoadResult struct {
	Path    string
	Missing bool
	Count   int
}

var (
	mu      sync.RWMutex
	presets = map[string]Preset{}
)

// builtinDefaults ships known e911/ePDG exceptions that every build should
// have out of the box, independent of whether an external overrides file is
// configured. An entry loaded via LoadCarrierOverrides for the same PLMN
// always takes priority over its built-in counterpart.
var builtinDefaults = map[string]Preset{
	// AT&T (US): VoWiFi requires an e911 registered address via their TS.43-style
	// entitlement server before the network will admit the session.
	"310-280": {ID: "att-us", MCC: "310", MNC: "280", E911Enabled: true, E911Provider: "att"},
	// giffgaff (O2 MVNO): recommended LTE TAC/ECI for UK VoWiFi when QMI is unavailable.
	"234-10": {ID: "giffgaff_23410", MCC: "234", MNC: "10", IMSTAC: 28673, IMSCellID: 12345678},
	// EE UK host network (giffgaff roaming core); same O2/EE-style identifiers.
	"234-33": {ID: "ee-uk", MCC: "234", MNC: "33", IMSTAC: 28673, IMSCellID: 12345678},
}

// blockedMCCs are entire countries where VoWiFi is policy-blocked regardless
// of which network the SIM is on. Mainland China (460) restricts exactly the
// kind of always-on IPsec/IKEv2 tunnel a SWu session is, independent of
// carrier, so it's blocked at the country level rather than per-PLMN.
var blockedMCCs = map[string]bool{
	"460": true,
}

// normalizeMNC strips leading zeros so a 2-digit and 3-digit MNC for the same
// network ("10" vs "010") resolve to the same preset key.
func normalizeMNC(mnc string) string {
	mnc = strings.TrimSpace(mnc)
	trimmed := strings.TrimLeft(mnc, "0")
	if trimmed == "" && mnc != "" {
		return "0"
	}
	return trimmed
}

func plmnKey(mcc, mnc string) string {
	return strings.TrimSpace(mcc) + "-" + normalizeMNC(mnc)
}

// LoadCarrierOverrides loads a JSON array of Preset from path, replacing any
// previously loaded overrides. An empty path or a nonexistent file is not an
// error: it just means no overrides are active, so every PLMN falls back to
// the 3GPP-standard default.
func LoadCarrierOverrides(path string) (*LoadResult, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		ClearCarrierOverrides()
		return &LoadResult{Path: path, Missing: true}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			ClearCarrierOverrides()
			return &LoadResult{Path: path, Missing: true}, nil
		}
		return &LoadResult{Path: path}, fmt.Errorf("carrier: read %s: %w", path, err)
	}

	var loaded []Preset
	if err := json.Unmarshal(data, &loaded); err != nil {
		return &LoadResult{Path: path}, fmt.Errorf("carrier: parse %s: %w", path, err)
	}

	next := make(map[string]Preset, len(loaded))
	for _, p := range loaded {
		if strings.TrimSpace(p.MCC) == "" || strings.TrimSpace(p.MNC) == "" {
			continue
		}
		next[plmnKey(p.MCC, p.MNC)] = p
	}

	mu.Lock()
	presets = next
	mu.Unlock()

	return &LoadResult{Path: path, Count: len(next)}, nil
}

func ClearCarrierOverrides() {
	mu.Lock()
	presets = map[string]Preset{}
	mu.Unlock()
}

// lookup checks loaded overrides first, falling back to the built-in table.
// An override for a PLMN always wins over its built-in counterpart.
func lookup(mcc, mnc string) (Preset, bool) {
	key := plmnKey(mcc, mnc)
	mu.RLock()
	p, ok := presets[key]
	mu.RUnlock()
	if ok {
		return p, true
	}
	p, ok = builtinDefaults[key]
	return p, ok
}

// allEntries merges built-in defaults with loaded overrides (overrides win)
// for callers that need to scan every known preset, such as IsVoWiFiBlockedMCC.
func allEntries() map[string]Preset {
	mu.RLock()
	defer mu.RUnlock()
	merged := make(map[string]Preset, len(builtinDefaults)+len(presets))
	for k, v := range builtinDefaults {
		merged[k] = v
	}
	for k, v := range presets {
		merged[k] = v
	}
	return merged
}

// ResolveEffectiveCarrierConfig returns the override for the given PLMN, or a
// zero-value config (PresetID "3gpp-default") when nothing overrides it.
func ResolveEffectiveCarrierConfig(input EffectiveCarrierConfigInput) EffectiveCarrierConfig {
	cfg := EffectiveCarrierConfig{PresetID: "3gpp-default"}
	preset, ok := lookup(input.MCC, input.MNC)
	if !ok {
		return cfg
	}
	if id := strings.TrimSpace(preset.ID); id != "" {
		cfg.PresetID = id
	} else {
		cfg.PresetID = plmnKey(input.MCC, input.MNC)
	}
	cfg.EPDGAddr = strings.TrimSpace(preset.EPDGAddr)
	cfg.AKAAppPreference = strings.TrimSpace(preset.AKAAppPreference)
	cfg.E911.Enabled = preset.E911Enabled
	cfg.E911.Provider = strings.TrimSpace(preset.E911Provider)
	return cfg
}

// IsVoWiFiBlockedMCC reports whether this MCC is policy-blocked outright
// (blockedMCCs), or whether any loaded/built-in preset under it is explicitly
// marked blocked. The orchestrator only has MCC at the point it calls this
// (pre-IMSI-parse), so a per-preset block only fires for a deliberately
// configured entry, never as an accidental default.
func IsVoWiFiBlockedMCC(mcc string) bool {
	mcc = strings.TrimSpace(mcc)
	if mcc == "" {
		return false
	}
	if blockedMCCs[mcc] {
		return true
	}
	for key, p := range allEntries() {
		if p.Blocked && strings.HasPrefix(key, mcc+"-") {
			return true
		}
	}
	return false
}

type blockedMCCError struct{ mcc string }

func (e *blockedMCCError) Error() string {
	return fmt.Sprintf("vowifi blocked by carrier policy for mcc %s", e.mcc)
}

func NewVoWiFiBlockedMCCError(mcc string) error {
	return &blockedMCCError{mcc: strings.TrimSpace(mcc)}
}

func IsVoWiFiPolicyBlockedError(err error) bool {
	_, ok := err.(*blockedMCCError)
	return ok
}
