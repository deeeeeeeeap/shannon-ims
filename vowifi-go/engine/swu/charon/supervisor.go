// Package charon supervises a single strongSwan charon process shared by
// every device's SWu tunnel: one daemon, many concurrent IKE_SAs, one
// vici control socket. It owns the process lifecycle; it does not know
// anything about SWu, ePDG addresses, or EAP-AKA — engine/swu builds on
// top of it.
//
// # AppArmor
//
// On Debian/Ubuntu, `strongswan-charon` ships an enforced AppArmor profile
// (/etc/apparmor.d/usr.lib.ipsec.charon) that whitelists exactly
// /etc/strongswan.conf, /etc/strongswan.d/**, and /run/charon.* — nothing
// else. This was found the hard way: pointing STRONGSWAN_CONF at a
// byte-identical config file under a custom directory (or even just a
// differently-named file in /etc) fails with an undiagnostic
// "abort initialization due to invalid configuration", root or not, because
// AppArmor is a MAC layer independent of DAC permissions. A custom filelog
// path in the generated config fails the exact same way, for the same
// reason.
//
// So this package never introduces new paths charon itself has to open by
// name: it drops a small config fragment into /etc/strongswan.d/ (an
// allowed directory — writing into it is unconfined since it's *this*
// process, not charon, doing the write), leaves the main strongswan.conf
// alone entirely (no STRONGSWAN_CONF override), uses the default
// /run/charon.vici socket, and routes logs through the "stdout" magic
// filelog target rather than a named path — stdout is an inherited fd from
// before exec, not a new open(), so AppArmor has nothing to say about it.
// This also happens to be simpler than the rejected design. On systems
// without this confinement (most non-Debian-family distros, OpenWrt) the
// custom paths in Options would have worked fine, but there's no reason to
// carry two code paths for it.
package charon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/strongswan/govici/vici"
)

// candidateBinaryPaths are searched, in order, when Options.BinaryPath is
// empty. Covers the Debian/Ubuntu layout (validated directly against
// strongswan-charon 5.9.1) plus the other common distro/source layouts;
// router builds should just set Options.BinaryPath explicitly.
var candidateBinaryPaths = []string{
	"/usr/lib/ipsec/charon-systemd",
	"/usr/lib/ipsec/charon",
	"/usr/libexec/ipsec/charon",
	"/usr/libexec/strongswan/charon",
	"/usr/lib/strongswan/charon",
	"/usr/sbin/charon",
	"/usr/bin/charon",
}

// Dataplane mode names, mirroring engine/swu.DataplaneMode*. Duplicated
// (rather than imported) so this package has zero dependency on the rest of
// engine/swu — it only knows how to run charon.
const (
	DataplaneModeUserspace = "userspace"
	DataplaneModeKernel    = "kernel"
)

const (
	// DefaultSocketPath is charon's default vici socket location, and the
	// only one guaranteed to work under the stock AppArmor profile.
	DefaultSocketPath = "/run/charon.vici"

	// DefaultConfFragmentPath is where the plugin/logging overrides are
	// written. Must stay under /etc/strongswan.d/ for the same reason.
	DefaultConfFragmentPath = "/etc/strongswan.d/91-vohive-swu.conf"

	// DefaultAKABridgeSocketPath is where the eap-aka-vohive plugin (see
	// ../akabridge/plugin) expects to reach the Go akabridge — matches that
	// plugin's own compiled-in default, and the /run/charon.* AppArmor
	// allowance.
	DefaultAKABridgeSocketPath = "/run/charon.vohive-aka"

	// DefaultPCSCFBridgeSocketPath is where the p-cscf-vohive plugin (see
	// ../pcscfbridge/plugin) expects to push discovered P-CSCF addresses —
	// matches that plugin's own compiled-in default, and the
	// /run/charon.* AppArmor allowance.
	DefaultPCSCFBridgeSocketPath = "/run/charon.vohive-pcscf"
)

var (
	ErrBinaryNotFound = errors.New("charon: no charon binary found (set Options.BinaryPath)")
	ErrNotRunning     = errors.New("charon: supervisor is not running")
	ErrAlreadyRunning = errors.New("charon: supervisor is already running")
)

type binaryProbeResult struct {
	Path    string
	Details []string
}

// Options configures a Supervisor.
type Options struct {
	// BinaryPath is the charon executable. Empty searches candidateBinaryPaths.
	BinaryPath string

	// RunDir holds only this process's own capture of charon's stdout/stderr
	// (a regular file this process opens, not charon — safe at any path).
	// Created (mode 0700) if missing.
	RunDir string

	// SocketPath is charon's vici socket. Empty defaults to
	// DefaultSocketPath, which is the only value confirmed safe under the
	// stock Debian/Ubuntu AppArmor profile — override only on systems known
	// not to confine charon.
	SocketPath string

	// ConfFragmentPath is where the generated plugin/logging overrides are
	// written. Empty defaults to DefaultConfFragmentPath, for the same
	// AppArmor reason as SocketPath.
	ConfFragmentPath string

	// AKABridgeSocketPath is where the eap-aka-vohive plugin should reach
	// the Go akabridge. Empty defaults to DefaultAKABridgeSocketPath.
	AKABridgeSocketPath string

	// PCSCFBridgeSocketPath is where the p-cscf-vohive plugin should push
	// discovered P-CSCF addresses. Empty defaults to
	// DefaultPCSCFBridgeSocketPath.
	PCSCFBridgeSocketPath string

	// Port and PortNATT override charon's own local IKE ports (charon.port
	// and charon.port_nat_t in strongswan.conf terms; default 500/4500,
	// same as the standard IKEV2_UDP_PORT/IKEV2_NATT_PORT). Zero leaves
	// charon on the standard ports.
	//
	// The one reason to move them: something else on this host needs 500
	// and/or 4500 for itself -- e.g. a upstreamproxy.UDPRelay presenting a
	// local address as a stand-in ePDG for a remote connection routed
	// through a SOCKS5 proxy. charon's own socket-default plugin binds
	// 0.0.0.0 on its ports, which claims every local address on that port
	// number, so nothing else can bind port 500/4500 on ANY address (not
	// just the one charon actually uses) while charon sits on the
	// standard ports. Note that peers are still addressed on the standard
	// ports regardless of this setting (remote_port defaults to 500
	// independently, and IKEv2's NAT-T float to port 4500 is a hardcoded
	// protocol constant, not derived from this) -- this only frees up
	// this host's own 500/4500 for something else to claim.
	Port     int
	PortNATT int

	// DataplaneMode selects kernel-libipsec (DataplaneModeUserspace, the
	// default — no kernel XFRM required) or kernel-netlink
	// (DataplaneModeKernel — needs full kernel IPsec support).
	DataplaneMode string

	// StartTimeout bounds how long Start waits for the vici socket to accept
	// connections. Defaults to 10s.
	StartTimeout time.Duration

	// StopTimeout bounds how long Stop waits after SIGTERM before SIGKILL.
	// Defaults to 5s.
	StopTimeout time.Duration
}

func (o Options) withDefaults() Options {
	if o.DataplaneMode == "" {
		o.DataplaneMode = DataplaneModeUserspace
	}
	if o.SocketPath == "" {
		o.SocketPath = DefaultSocketPath
	}
	if o.ConfFragmentPath == "" {
		o.ConfFragmentPath = DefaultConfFragmentPath
	}
	if o.AKABridgeSocketPath == "" {
		o.AKABridgeSocketPath = DefaultAKABridgeSocketPath
	}
	if o.PCSCFBridgeSocketPath == "" {
		o.PCSCFBridgeSocketPath = DefaultPCSCFBridgeSocketPath
	}
	if o.StartTimeout <= 0 {
		o.StartTimeout = 10 * time.Second
	}
	if o.StopTimeout <= 0 {
		o.StopTimeout = 5 * time.Second
	}
	return o
}

// Supervisor manages one charon process. It is not safe to call Start/Stop
// concurrently from multiple goroutines, but Session may be called anytime
// after a successful Start.
type Supervisor struct {
	opts Options

	mu      sync.Mutex
	cmd     *exec.Cmd
	logFile *os.File
	// done is closed exactly once, by the reaper goroutine, when charon
	// exits for any reason. A closed channel (unlike a single-value one) can
	// be observed by any number of readers — Stop() and an independent
	// crash-watching caller of Wait() both need to see the same exit without
	// racing to be the one that "consumes" it.
	done    chan struct{}
	exitErr error // valid only once done is closed
}

// NewSupervisor validates opts and resolves the charon binary path, but does
// not start anything.
func NewSupervisor(opts Options) (*Supervisor, error) {
	opts = opts.withDefaults()

	if opts.RunDir == "" {
		return nil, errors.New("charon: Options.RunDir is required")
	}
	if opts.DataplaneMode != DataplaneModeUserspace && opts.DataplaneMode != DataplaneModeKernel {
		return nil, fmt.Errorf("charon: invalid DataplaneMode %q", opts.DataplaneMode)
	}

	if opts.BinaryPath == "" {
		probe := resolveBinaryPath()
		opts.BinaryPath = probe.Path
		if opts.BinaryPath == "" {
			return nil, binaryNotFoundError(probe)
		}
	} else if st, err := os.Stat(opts.BinaryPath); err != nil || st.IsDir() {
		return nil, fmt.Errorf("charon: BinaryPath %q: %w", opts.BinaryPath, ErrBinaryNotFound)
	}

	return &Supervisor{opts: opts}, nil
}

func resolveBinaryPath() binaryProbeResult {
	var details []string

	for _, key := range []string{"VOHIVE_CHARON_BINARY", "CHARON_BINARY"} {
		if p := os.Getenv(key); p != "" {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				details = append(details, fmt.Sprintf("env %s=%s (found)", key, p))
				return binaryProbeResult{Path: p, Details: details}
			}
			details = append(details, fmt.Sprintf("env %s=%s (missing or invalid)", key, p))
		} else {
			details = append(details, fmt.Sprintf("env %s is empty", key))
		}
	}

	for _, name := range []string{"charon", "charon-systemd"} {
		if p, err := exec.LookPath(name); err == nil {
			details = append(details, fmt.Sprintf("PATH lookup %s -> %s", name, p))
			return binaryProbeResult{Path: p, Details: details}
		}
		details = append(details, fmt.Sprintf("PATH lookup %s not found", name))
	}

	for _, p := range candidateBinaryPaths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			details = append(details, fmt.Sprintf("candidate %s (found)", p))
			return binaryProbeResult{Path: p, Details: details}
		}
		details = append(details, fmt.Sprintf("candidate %s (missing)", p))
	}

	return binaryProbeResult{Details: details}
}

func binaryNotFoundError(probe binaryProbeResult) error {
	if len(probe.Details) == 0 {
		return ErrBinaryNotFound
	}
	return fmt.Errorf("%w; searched: %s", ErrBinaryNotFound, strings.Join(probe.Details, "; "))
}

func (s *Supervisor) logPath() string { return s.opts.RunDir + "/charon.log" }

// SocketPath returns the vici socket path charon is (or will be) listening on.
func (s *Supervisor) SocketPath() string { return s.opts.SocketPath }

// AKABridgeSocketPath returns the path the eap-aka-vohive plugin is
// configured to reach the Go akabridge on.
func (s *Supervisor) AKABridgeSocketPath() string { return s.opts.AKABridgeSocketPath }

// PCSCFBridgeSocketPath returns the path the p-cscf-vohive plugin is
// configured to push discovered P-CSCF addresses to.
func (s *Supervisor) PCSCFBridgeSocketPath() string { return s.opts.PCSCFBridgeSocketPath }

// confFragment is dropped into /etc/strongswan.d/ (never into the main
// strongswan.conf, never at a custom path — see the package doc comment).
// Deliberately does not set `vici { socket = ... }`: when SocketPath is left
// at its default, that's already where the vici plugin listens, and setting
// it explicitly would work too but there's no reason to touch it when it
// isn't changing.
const confFragmentTemplate = `# generated by vohive's charon supervisor — do not edit, do not commit
charon {
{{- if .Port}}
    port = {{.Port}}
{{- end}}
{{- if .PortNATT}}
    port_nat_t = {{.PortNATT}}
{{- end}}
    plugins {
        eap-aka-vohive {
            load = yes
            socket = {{.AKABridgeSocketPath}}
        }
        p-cscf-vohive {
            load = yes
            socket = {{.PCSCFBridgeSocketPath}}
        }
        kernel-libipsec {
            load = {{.LibipsecLoad}}
        }
        kernel-netlink {
            load = {{.NetlinkLoad}}
        }
    }
    filelog {
        stdout {
            default = 1
            ike = 2
            cfg = 2
        }
    }
}
`

var confFragmentTmpl = template.Must(template.New("vohive-swu.conf").Parse(confFragmentTemplate))

func (s *Supervisor) renderConfFragment() ([]byte, error) {
	libipsecLoad := "no"
	netlinkLoad := "yes"
	if s.opts.DataplaneMode == DataplaneModeUserspace {
		// Priority 2 beats kernel-netlink's default (yes == priority 1) for the
		// KERNEL_IPSEC feature specifically; kernel-netlink stays loaded for
		// routing/interface info. Confirmed via spike: kernel-netlink logs
		// "feature CUSTOM:kernel-ipsec ... failed to load" once this wins,
		// while it keeps providing KERNEL_NET.
		libipsecLoad = "2"
	}

	data := struct {
		LibipsecLoad, NetlinkLoad, AKABridgeSocketPath, PCSCFBridgeSocketPath string
		Port, PortNATT                                                        int
	}{
		LibipsecLoad:          libipsecLoad,
		NetlinkLoad:           netlinkLoad,
		AKABridgeSocketPath:   s.opts.AKABridgeSocketPath,
		PCSCFBridgeSocketPath: s.opts.PCSCFBridgeSocketPath,
		Port:                  s.opts.Port,
		PortNATT:              s.opts.PortNATT,
	}

	var buf bytes.Buffer
	if err := confFragmentTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("charon: render conf fragment: %w", err)
	}
	return buf.Bytes(), nil
}

// Start writes the config fragment, launches charon, and blocks until its
// vici socket accepts connections or ctx/StartTimeout expires. On failure,
// any partially-started process is killed before returning.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cmd != nil {
		return ErrAlreadyRunning
	}

	if err := os.MkdirAll(s.opts.RunDir, 0o700); err != nil {
		return fmt.Errorf("charon: create rundir %s: %w", s.opts.RunDir, err)
	}

	// A socket left behind by a previous, uncleanly-stopped run would make
	// charon fail to bind.
	_ = os.Remove(s.opts.SocketPath)

	fragBytes, err := s.renderConfFragment()
	if err != nil {
		return err
	}
	if err := os.WriteFile(s.opts.ConfFragmentPath, fragBytes, 0o644); err != nil {
		return fmt.Errorf("charon: write %s: %w", s.opts.ConfFragmentPath, err)
	}

	logFile, err := os.OpenFile(s.logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("charon: open log file %s: %w", s.logPath(), err)
	}

	startCtx, cancel := context.WithTimeout(ctx, s.opts.StartTimeout)
	defer cancel()

	// Deliberately not exec.CommandContext(startCtx, ...): the process must
	// outlive Start() (only the socket-readiness wait is time-boxed).
	cmd := exec.Command(s.opts.BinaryPath)
	// No STRONGSWAN_CONF: the main config stays untouched, see package doc.
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("charon: start %s: %w", s.opts.BinaryPath, err)
	}

	done := make(chan struct{})
	go func() {
		// s.exitErr is written here and only ever read after a receive from
		// (or observing the close of) done, so the channel close below is
		// the synchronization point — no mutex needed for the field itself,
		// and importantly none is taken: Start/Stop hold s.mu across their
		// own blocking wait on done, so this goroutine locking it too would
		// deadlock against them.
		s.exitErr = cmd.Wait()
		close(done)
	}()

	if err := waitForSocket(startCtx, s.opts.SocketPath); err != nil {
		_ = killProcessGroup(cmd)
		<-done
		logFile.Close()
		return fmt.Errorf("charon: vici socket never became ready: %w", err)
	}

	s.cmd = cmd
	s.logFile = logFile
	s.done = done
	return nil
}

// waitForSocket polls until a unix socket at path accepts a connection, or
// ctx is done. charon creates the vici socket only after it finishes loading
// plugins, so this is the correct "daemon is up" signal — not just process
// liveness.
func waitForSocket(ctx context.Context, path string) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		if sess, err := vici.NewSession(vici.WithSocketPath(path)); err == nil {
			_ = sess.Close()
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Session dials a new vici session against the running charon. Callers own
// its lifecycle (Close it when done); the Supervisor doesn't hand out a
// shared session because govici's Session is meant to be used from one
// goroutine's command/response flow plus its own internal event-listen
// goroutine, and different callers (config load vs. event subscription vs.
// SA introspection) are cleaner with independent sessions.
func (s *Supervisor) Session() (*vici.Session, error) {
	s.mu.Lock()
	running := s.cmd != nil
	s.mu.Unlock()
	if !running {
		return nil, ErrNotRunning
	}
	return vici.NewSession(vici.WithSocketPath(s.opts.SocketPath))
}

// Wait returns a channel that is closed when charon exits for any reason —
// including a crash the Supervisor didn't ask for. Unlike a single-value
// channel, closing supports any number of independent readers: both Stop()
// and a caller using this for crash monitoring can observe the same exit
// without racing to consume it. Call ExitErr after the channel closes to get
// the exit error. The caller (not this package) decides whether/how to
// restart; this package only reports.
func (s *Supervisor) Wait() (<-chan struct{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd == nil {
		return nil, ErrNotRunning
	}
	return s.done, nil
}

// ExitErr returns the error charon's process exited with (nil for a clean
// exit). Only meaningful after the channel returned by Wait has closed.
func (s *Supervisor) ExitErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.exitErr
}

// Stop sends SIGTERM, waits up to StopTimeout, then SIGKILLs the process
// group if it hasn't exited. Safe to call after the process has already
// exited on its own (e.g. observed via Wait). Removes the config fragment
// and socket so a stopped supervisor leaves nothing behind for an unrelated
// strongSwan use on the same host.
func (s *Supervisor) Stop(ctx context.Context) error {
	s.mu.Lock()
	cmd := s.cmd
	done := s.done
	logFile := s.logFile
	s.cmd = nil
	s.done = nil
	s.logFile = nil
	s.mu.Unlock()

	if cmd == nil {
		return ErrNotRunning
	}
	defer func() {
		if logFile != nil {
			logFile.Close()
		}
		_ = os.Remove(s.opts.SocketPath)
		_ = os.Remove(s.opts.ConfFragmentPath)
	}()

	if cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}

	stopCtx, cancel := context.WithTimeout(ctx, s.opts.StopTimeout)
	defer cancel()

	select {
	case <-done:
		return s.ExitErr()
	case <-stopCtx.Done():
		_ = killProcessGroup(cmd)
		<-done
		return stopCtx.Err()
	}
}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	// Setpgid was set at Start; -pid signals the whole group so charon can't
	// leave an orphaned child (e.g. a plugin helper) behind.
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		return cmd.Process.Kill()
	}
	return nil
}
