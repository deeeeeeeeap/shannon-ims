package voiceclient

import "fmt"

// FormatUTRANCellIDSuffix returns the hex suffix (TAC + ECI) used after the home
// PLMN in utran-cell-id-3gpp. When both inputs are zero an empty string is
// returned so callers can fall back to the SimAdmin-style placeholder.
func FormatUTRANCellIDSuffix(tac, eci uint32) string {
	if tac == 0 && eci == 0 {
		return ""
	}
	return fmt.Sprintf("%04X%07X", tac&0xFFFF, eci&0x0FFFFFFF)
}