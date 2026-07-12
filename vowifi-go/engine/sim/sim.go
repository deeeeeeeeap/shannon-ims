package sim

import "errors"

var ErrSyncFailure = errors.New("sync failure")

type AKAResult struct {
	RES  []byte
	CK   []byte
	IK   []byte
	AUTS []byte
}

type AKAProvider interface {
	CalculateAKA(rand16, autn16 []byte) (AKAResult, error)
}

// ISIMAKAProvider is implemented by AKA providers that can additionally
// authenticate against an ISIM application (as opposed to USIM). Callers type-assert
// for this when AKAAppPreference is "isim"/"isim_strict"/"auto" and fall back to
// plain AKAProvider (USIM) otherwise.
type ISIMAKAProvider interface {
	AKAProvider
	CalculateISIMAKA(rand16, autn16 []byte) (AKAResult, error)
}
