package upstreamproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/1239t/vowifi-go/runtimehost/transport"
	"github.com/1239t/vowifi-go/runtimehost/transport/socks5sim"
)

const (
	simUser     = "sim-user"
	simPassword = "sim-pass"
)

func startSimProxy(t *testing.T, cfg socks5sim.Config) *socks5sim.Server {
	t.Helper()
	srv, err := socks5sim.Start(cfg)
	if err != nil {
		t.Fatalf("start simulated proxy: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func startSimPeer(t *testing.T) *socks5sim.UDPPeer {
	t.Helper()
	peer, err := socks5sim.StartUDPPeer()
	if err != nil {
		t.Fatalf("start simulated peer: %v", err)
	}
	t.Cleanup(peer.Close)
	return peer
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestProbeSOCKS5AgainstSimulatedProxy(t *testing.T) {
	cases := []struct {
		name     string
		auth     socks5sim.AuthMode
		faults   func(*socks5sim.Faults)
		username string
		password string
		timeout  time.Duration

		wantStage     string
		wantAuth      string
		wantDiagnosis string
		wantError     string // substring of ProbeResult.Error
		check         func(t *testing.T, result ProbeResult)
	}{
		{
			name:          "no authentication",
			auth:          socks5sim.AuthNone,
			wantStage:     ProbeStageOK,
			wantAuth:      "noauth",
			wantDiagnosis: "代理支持标准 SOCKS5 UDP Associate",
			check: func(t *testing.T, result ProbeResult) {
				if len(result.Warnings) != 0 || result.RelayAdjustment != "" || result.RelayAdvertised != "" || result.CredentialsIgnored {
					t.Fatalf("a plain proxy must probe clean, got %+v", result)
				}
				host, port, err := net.SplitHostPort(result.RelayAddr)
				if err != nil || host != "127.0.0.1" || port == "0" {
					t.Fatalf("relay address = %q (%v), want the simulated relay on 127.0.0.1", result.RelayAddr, err)
				}
			},
		},
		{
			name:      "username and password",
			auth:      socks5sim.AuthUserPass,
			username:  simUser,
			password:  simPassword,
			wantStage: ProbeStageOK,
			wantAuth:  "username_password",
		},
		{
			name:      "proxy accepts both and credentials are configured",
			auth:      socks5sim.AuthEither,
			username:  simUser,
			password:  simPassword,
			wantStage: ProbeStageOK,
			wantAuth:  "username_password",
		},
		{
			name:      "proxy accepts both and no credentials are configured",
			auth:      socks5sim.AuthEither,
			wantStage: ProbeStageOK,
			wantAuth:  "noauth",
		},
		{
			name:          "wrong password",
			auth:          socks5sim.AuthUserPass,
			username:      simUser,
			password:      "not-the-password",
			wantStage:     ProbeStageHandshake,
			wantDiagnosis: "代理用户名或密码错误",
			wantError:     "鉴权失败",
		},
		{
			name:          "credentials required but none configured",
			auth:          socks5sim.AuthUserPass,
			wantStage:     ProbeStageHandshake,
			wantDiagnosis: "代理要求用户名密码认证",
			wantError:     "0xFF",
		},
		{
			name:      "proxy without password support",
			auth:      socks5sim.AuthNone,
			username:  simUser,
			password:  simPassword,
			wantStage: ProbeStageOK,
			wantAuth:  "noauth",
			check: func(t *testing.T, result ProbeResult) {
				if !result.CredentialsIgnored || len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "凭据未被使用") {
					t.Fatalf("unused credentials must be reported, got %+v", result)
				}
			},
		},
		{
			name:          "udp associate refused",
			auth:          socks5sim.AuthNone,
			faults:        func(f *socks5sim.Faults) { f.AssociateReply = 0x07 },
			wantStage:     ProbeStageUDPAssociate,
			wantAuth:      "noauth",
			wantDiagnosis: "代理明确拒绝了 UDP Associate",
			wantError:     "状态码 0x07 (不支持该命令)",
		},
		{
			name:      "relay advertised as the wildcard address",
			auth:      socks5sim.AuthNone,
			faults:    func(f *socks5sim.Faults) { f.Advertise = socks5sim.AdvertiseUnspecified },
			wantStage: ProbeStageOK,
			check: func(t *testing.T, result ProbeResult) {
				if result.RelayAdjustment != string(transport.Socks5RelayUnspecified) {
					t.Fatalf("relay adjustment = %q, want %q", result.RelayAdjustment, transport.Socks5RelayUnspecified)
				}
				if !strings.HasPrefix(result.RelayAdvertised, "0.0.0.0:") || !strings.HasPrefix(result.RelayAddr, "127.0.0.1:") {
					t.Fatalf("advertised %q, used %q: want the proxy's own address in place of 0.0.0.0", result.RelayAdvertised, result.RelayAddr)
				}
				if len(result.Warnings) != 0 {
					t.Fatalf("a wildcard relay address is routine and needs no warning, got %v", result.Warnings)
				}
			},
		},
		{
			name: "relay advertised as a host name",
			auth: socks5sim.AuthNone,
			faults: func(f *socks5sim.Faults) {
				f.Advertise = socks5sim.AdvertiseDomain
				f.AdvertiseHost = "localhost"
			},
			wantStage: ProbeStageOK,
			check: func(t *testing.T, result ProbeResult) {
				if !strings.HasPrefix(result.RelayAdvertised, "localhost:") || !strings.HasPrefix(result.RelayAddr, "127.0.0.1:") {
					t.Fatalf("advertised %q, used %q: want the name resolved", result.RelayAdvertised, result.RelayAddr)
				}
			},
		},
		{
			name:          "relay advertised on port zero",
			auth:          socks5sim.AuthNone,
			faults:        func(f *socks5sim.Faults) { f.Advertise = socks5sim.AdvertisePortZero },
			wantStage:     ProbeStageUDPAssociate,
			wantDiagnosis: "代理返回的 UDP 中继地址不可用",
		},
		{
			name:          "not a socks5 service",
			auth:          socks5sim.AuthNone,
			faults:        func(f *socks5sim.Faults) { f.WrongVersion = true },
			wantStage:     ProbeStageHandshake,
			wantDiagnosis: "目标端口不是标准 SOCKS5 服务",
			wantError:     "版本不匹配",
		},
		{
			name:          "connection closed during the handshake",
			auth:          socks5sim.AuthNone,
			faults:        func(f *socks5sim.Faults) { f.CloseOnGreeting = true },
			wantStage:     ProbeStageHandshake,
			wantDiagnosis: "代理在 SOCKS5 握手阶段直接断开了连接",
		},
		{
			name:          "connection closed on udp associate",
			auth:          socks5sim.AuthNone,
			faults:        func(f *socks5sim.Faults) { f.CloseOnRequest = true },
			wantStage:     ProbeStageUDPAssociate,
			wantDiagnosis: "代理在 UDP Associate 阶段直接断开了连接",
		},
		{
			name:          "no answer during the handshake",
			auth:          socks5sim.AuthNone,
			faults:        func(f *socks5sim.Faults) { f.StallGreeting = true },
			timeout:       150 * time.Millisecond,
			wantStage:     ProbeStageHandshake,
			wantDiagnosis: "代理在 SOCKS5 握手阶段没有响应",
		},
		{
			name:          "no answer to udp associate",
			auth:          socks5sim.AuthNone,
			faults:        func(f *socks5sim.Faults) { f.StallRequest = true },
			timeout:       150 * time.Millisecond,
			wantStage:     ProbeStageUDPAssociate,
			wantDiagnosis: "代理在 UDP Associate 阶段没有响应",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := startSimProxy(t, socks5sim.Config{Auth: tc.auth, Username: simUser, Password: simPassword})
			if tc.faults != nil {
				srv.SetFaults(tc.faults)
			}
			timeout := tc.timeout
			if timeout == 0 {
				timeout = 2 * time.Second
			}

			started := time.Now()
			result, err := ProbeSOCKS5(context.Background(), ProbeConfig{
				ProxyAddr: srv.Addr(),
				Username:  tc.username,
				Password:  tc.password,
				Timeout:   timeout,
			})
			if elapsed := time.Since(started); elapsed > 2*timeout+time.Second {
				t.Fatalf("probe took %v, want at most twice the %v timeout", elapsed, timeout)
			}

			wantOK := tc.wantStage == ProbeStageOK
			if result.OK() != wantOK || (err == nil) != wantOK {
				t.Fatalf("OK = %v, err = %v, want success = %v; result %+v", result.OK(), err, wantOK, result)
			}
			if result.Stage != tc.wantStage {
				t.Fatalf("stage = %q, want %q; result %+v", result.Stage, tc.wantStage, result)
			}
			if !result.Reachable {
				t.Fatalf("the proxy accepted the connection, so it must be reported reachable: %+v", result)
			}
			if wantHandshake := tc.wantStage != ProbeStageHandshake; result.HandshakeOK != wantHandshake {
				t.Fatalf("handshake_ok = %v, want %v; result %+v", result.HandshakeOK, wantHandshake, result)
			}
			if tc.wantAuth != "" && result.AuthMethod != tc.wantAuth {
				t.Fatalf("auth method = %q, want %q", result.AuthMethod, tc.wantAuth)
			}
			if tc.wantDiagnosis != "" && result.Diagnosis != tc.wantDiagnosis {
				t.Fatalf("diagnosis = %q, want %q; result %+v", result.Diagnosis, tc.wantDiagnosis, result)
			}
			if tc.wantError != "" && !strings.Contains(result.Error, tc.wantError) {
				t.Fatalf("error = %q, want it to contain %q", result.Error, tc.wantError)
			}
			if !wantOK {
				if result.Hint == "" || result.Error == "" {
					t.Fatalf("a failed probe must say what to do and what happened: %+v", result)
				}
				summary := result.FailureSummary()
				for _, part := range []string{result.Diagnosis, "建议: " + result.Hint, "细节: " + result.Error} {
					if !strings.Contains(summary, part) {
						t.Fatalf("failure summary %q lacks %q", summary, part)
					}
				}
			}
			if tc.check != nil {
				tc.check(t, result)
			}
		})
	}
}

func TestProbeSOCKS5ConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	result, err := ProbeSOCKS5(context.Background(), ProbeConfig{ProxyAddr: addr, Timeout: 2 * time.Second})
	if err == nil || result.OK() {
		t.Fatalf("probe of a closed port succeeded: %+v", result)
	}
	if result.Stage != ProbeStageTCPConnect || result.Reachable {
		t.Fatalf("stage = %q, reachable = %v, want a TCP connect failure", result.Stage, result.Reachable)
	}
	if result.Diagnosis != "无法与代理建立 TCP 连接" || result.Hint != "代理地址可达，但目标端口没有监听 SOCKS5 服务" {
		t.Fatalf("diagnosis %q, hint %q: want the refused-connection explanation", result.Diagnosis, result.Hint)
	}
	if !strings.HasPrefix(result.Error, "代理 TCP 连接失败: ") {
		t.Fatalf("error = %q", result.Error)
	}
}

func TestProbeSOCKS5RejectsEmptyAddress(t *testing.T) {
	result, err := ProbeSOCKS5(context.Background(), ProbeConfig{ProxyAddr: "   "})
	if err == nil || result.OK() || result.Stage != ProbeStageTCPConnect {
		t.Fatalf("result %+v, err %v: want a failure before connecting", result, err)
	}
}

func TestProbeSOCKS5HonoursCallerCancellation(t *testing.T) {
	srv := startSimProxy(t, socks5sim.Config{Auth: socks5sim.AuthNone})
	srv.SetFaults(func(f *socks5sim.Faults) { f.StallGreeting = true })

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	result, err := ProbeSOCKS5(ctx, ProbeConfig{ProxyAddr: srv.Addr(), Timeout: 30 * time.Second})
	if err == nil || result.OK() {
		t.Fatalf("probe of a stalled proxy succeeded: %+v", result)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("probe returned after %v, want it to stop when the caller's context ends", elapsed)
	}
	if result.Stage != ProbeStageHandshake {
		t.Fatalf("stage = %q, want %q", result.Stage, ProbeStageHandshake)
	}
}

// A failed login must not put the credentials into anything that is shown,
// logged or returned by the API.
func TestProbeSOCKS5DoesNotLeakCredentials(t *testing.T) {
	const secret = "s3cr3t-do-not-print"
	srv := startSimProxy(t, socks5sim.Config{Auth: socks5sim.AuthUserPass, Username: simUser, Password: simPassword})

	result, err := ProbeSOCKS5(context.Background(), ProbeConfig{
		ProxyAddr: srv.Addr(),
		Username:  simUser,
		Password:  secret,
		Timeout:   2 * time.Second,
	})
	if err == nil {
		t.Fatalf("login with a wrong password succeeded: %+v", result)
	}
	encoded, jsonErr := json.Marshal(result)
	if jsonErr != nil {
		t.Fatalf("marshal: %v", jsonErr)
	}
	for name, text := range map[string]string{
		"error":           err.Error(),
		"json":            string(encoded),
		"failure summary": result.FailureSummary(),
	} {
		if strings.Contains(text, secret) || strings.Contains(text, simUser) {
			t.Fatalf("%s contains the credentials: %s", name, text)
		}
	}
}

// The API returns ProbeResult as is, so the names the console reads must not
// change and the fields added later must stay out of a plain result.
func TestProbeResultJSONFieldsAreStable(t *testing.T) {
	srv := startSimProxy(t, socks5sim.Config{Auth: socks5sim.AuthNone})
	result, err := ProbeSOCKS5(context.Background(), ProbeConfig{ProxyAddr: srv.Addr(), Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, name := range []string{
		"proxy_addr", "stage", "reachable", "handshake_ok", "udp_associate_ok",
		"auth_method", "relay_addr", "duration_ms", "diagnosis",
	} {
		if _, ok := fields[name]; !ok {
			t.Errorf("field %q is missing from %s", name, encoded)
		}
	}
	for _, name := range []string{"relay_advertised", "relay_adjustment", "credentials_ignored", "warnings", "hint", "error"} {
		if _, ok := fields[name]; ok {
			t.Errorf("field %q must be omitted from a clean result: %s", name, encoded)
		}
	}
}

// The probe exists to predict whether a tunnel can use the proxy. Whatever
// the proxy accepts and whatever is configured, its verdict must match what
// the tunnel's own transport then experiences, and both must negotiate with
// the proxy in the same way.
func TestProbeSOCKS5AgreesWithTunnelTransport(t *testing.T) {
	authModes := map[string]socks5sim.AuthMode{
		"proxy=noauth":   socks5sim.AuthNone,
		"proxy=userpass": socks5sim.AuthUserPass,
		"proxy=either":   socks5sim.AuthEither,
	}
	credentials := map[string][2]string{
		"client=none":  {"", ""},
		"client=right": {simUser, simPassword},
		"client=wrong": {simUser, "not-the-password"},
	}
	advertise := map[string]socks5sim.RelayAdvertise{
		"relay=actual":   socks5sim.AdvertiseActual,
		"relay=wildcard": socks5sim.AdvertiseUnspecified,
		"relay=name":     socks5sim.AdvertiseDomain,
		"relay=port0":    socks5sim.AdvertisePortZero,
	}

	for authName, auth := range authModes {
		for credName, cred := range credentials {
			for advName, adv := range advertise {
				t.Run(authName+"/"+credName+"/"+advName, func(t *testing.T) {
					newProxy := func() *socks5sim.Server {
						srv := startSimProxy(t, socks5sim.Config{Auth: auth, Username: simUser, Password: simPassword})
						srv.SetFaults(func(f *socks5sim.Faults) { f.Advertise = adv })
						return srv
					}

					probed := newProxy()
					result, _ := ProbeSOCKS5(context.Background(), ProbeConfig{
						ProxyAddr: probed.Addr(),
						Username:  cred[0],
						Password:  cred[1],
						Timeout:   2 * time.Second,
					})

					used := newProxy()
					tunnelOK, tunnelErr := tunnelRoundTrip(t, used.Addr(), cred[0], cred[1])

					if result.OK() != tunnelOK {
						t.Fatalf("probe says usable = %v but the tunnel transport got usable = %v (%v); probe result %+v",
							result.OK(), tunnelOK, tunnelErr, result)
					}
					if got, want := fmt.Sprint(probed.Greetings()), fmt.Sprint(used.Greetings()); got != want {
						t.Fatalf("probe offered methods %s, the tunnel transport offered %s", got, want)
					}
				})
			}
		}
	}
}

// tunnelRoundTrip does what a tunnel does first: send a datagram to the
// remote end through the proxy and wait for the answer.
func tunnelRoundTrip(t *testing.T, proxyAddr, username, password string) (bool, error) {
	t.Helper()
	peer := startSimPeer(t)
	tp, err := transport.NewSocks5UDPTransportWithOptions(transport.Socks5UDPOptions{
		ProxyAddr:   proxyAddr,
		Username:    username,
		Password:    password,
		Timeout:     2 * time.Second,
		MaxAttempts: 1,
	})
	if err != nil {
		return false, err
	}
	defer tp.Close()

	payload := []byte("first tunnel datagram")
	if _, err := tp.SendTo(payload, peer.Addr()); err != nil {
		return false, err
	}
	type received struct {
		data []byte
		err  error
	}
	answer := make(chan received, 1)
	go func() {
		buf := make([]byte, 2048)
		n, _, err := tp.RecvFrom(buf)
		answer <- received{data: buf[:n], err: err}
	}()
	select {
	case got := <-answer:
		if got.err != nil {
			return false, got.err
		}
		if !bytes.Equal(got.data, payload) {
			t.Fatalf("tunnel transport received %q, want the echo of %q", got.data, payload)
		}
		return true, nil
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel transport: no answer through the proxy")
		return false, nil
	}
}
