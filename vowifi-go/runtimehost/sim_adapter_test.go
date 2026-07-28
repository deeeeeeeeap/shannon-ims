package runtimehost

import (
	"testing"

	swusim "github.com/1239t/vowifi-go/engine/sim"
)

type syntheticISIMAKAProvider struct {
	isimCalls int
}

type syntheticUSIMAKAProvider struct{}

func (syntheticUSIMAKAProvider) CalculateAKA(_, _ []byte) (swusim.AKAResult, error) {
	return swusim.AKAResult{}, nil
}

func (*syntheticISIMAKAProvider) CalculateAKA(_, _ []byte) (swusim.AKAResult, error) {
	return swusim.AKAResult{}, nil
}

func (p *syntheticISIMAKAProvider) CalculateISIMAKA(_, _ []byte) (swusim.AKAResult, error) {
	p.isimCalls++
	return swusim.AKAResult{}, nil
}

func TestNewReaderSIMAdapterWithIMSIPreservesISIMAKACapability(t *testing.T) {
	provider := &syntheticISIMAKAProvider{}
	adapter := NewReaderSIMAdapterWithIMSI(provider, "synthetic-imsi")

	isimAdapter, ok := adapter.(swusim.ISIMAKAProvider)
	if !ok {
		t.Fatal("wrapped SIM adapter lost ISIM AKA capability")
	}
	if _, err := isimAdapter.CalculateISIMAKA(make([]byte, 16), make([]byte, 16)); err != nil {
		t.Fatalf("CalculateISIMAKA() error = %v", err)
	}
	if provider.isimCalls != 1 {
		t.Fatalf("ISIM AKA calls = %d, want 1", provider.isimCalls)
	}
}

func TestNewReaderSIMAdapterWithIMSICannotInventISIMAKACapability(t *testing.T) {
	adapter := NewReaderSIMAdapterWithIMSI(syntheticUSIMAKAProvider{}, "synthetic-imsi")

	if _, ok := adapter.(swusim.ISIMAKAProvider); ok {
		t.Fatal("USIM-only provider was exposed as ISIM AKA capable")
	}
}
