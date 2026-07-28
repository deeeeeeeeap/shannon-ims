package swu

import "fmt"

func normalizeMNC(mnc string) string {
	if len(mnc) == 2 {
		return "0" + mnc
	}
	return mnc
}

func normalizeMCC(mcc string) string {
	return mcc
}

func effectiveMCCMNC(imsi string, cfg *Config) (string, string) {
	mcc := ""
	mnc := ""
	if len(imsi) >= 5 {
		mcc = imsi[0:3]
		mnc = imsi[3:5]
	}
	if cfg.MCC != "" {
		mcc = cfg.MCC
	}
	if cfg.MNC != "" {
		mnc = cfg.MNC
	}
	return normalizeMCC(mcc), normalizeMNC(mnc)
}

func buildNAI(imsi string, cfg *Config) string {
	mcc, mnc := effectiveMCCMNC(imsi, cfg)
	return fmt.Sprintf("0%s@nai.epc.mnc%s.mcc%s.3gppnetwork.org", imsi, mnc, mcc)
}
