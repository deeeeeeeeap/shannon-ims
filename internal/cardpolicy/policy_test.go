package cardpolicy

import "testing"

type stubResolver struct{ p Policy; err error }

func (s stubResolver) Resolve(iccid string) (Policy, error) { return s.p, s.err }

func TestResolverInterface(t *testing.T) {
	var r Resolver = stubResolver{p: Policy{ICCID: "x", NetworkEnabled: true}}
	got, err := r.Resolve("x")
	if err != nil || !got.NetworkEnabled {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}
