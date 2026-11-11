package notify

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// smtpSim is a mail server on the loopback interface. It speaks as much SMTP
// as a client needs to hand over a message, keeps what it is handed, and
// behaves as its exported fields, set before it is started, say.
type smtpSim struct {
	// ImplicitTLS: the connection is encrypted from the first byte.
	ImplicitTLS bool
	// OfferSTARTTLS: an unencrypted connection can be upgraded.
	OfferSTARTTLS bool
	// Mechanisms it announces for authentication, as in "PLAIN LOGIN".
	// Empty: it offers none.
	Mechanisms string
	// AuthOnlyEncrypted: it offers authentication on an encrypted connection
	// only.
	AuthOnlyEncrypted bool
	// Username and Password of the one account it knows.
	Username string
	Password string
	// RequireAuth: it refuses a sender that has not authenticated.
	RequireAuth bool
	// RefusedRecipient is the address it does not accept mail for.
	RefusedRecipient string
	// Mute: it accepts the connection and says nothing.
	Mute bool
	// MuteAfterMessage: it takes the message and never confirms it.
	MuteAfterMessage bool

	listener    net.Listener
	certificate tls.Certificate
	roots       *x509.CertPool
	done        chan struct{}
	stopOnce    sync.Once
	sessions    sync.WaitGroup

	mu       sync.Mutex
	conns    map[net.Conn]struct{}
	accepted int
	received []smtpSimMessage
}

// smtpSimMessage is one message the simulator was handed.
type smtpSimMessage struct {
	From string
	To   []string
	// Raw is the message as it came over the wire, line ends included.
	Raw string
	// Encrypted tells whether the connection was encrypted when the sender
	// was named.
	Encrypted bool
	// Mechanism the sender authenticated with. Empty: it did not.
	Mechanism string
}

func startSMTPSim(t *testing.T, sim *smtpSim) *smtpSim {
	t.Helper()
	sim.done = make(chan struct{})
	sim.conns = make(map[net.Conn]struct{})
	sim.certificate, sim.roots = newLoopbackCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen on the loopback interface: %v", err)
	}
	sim.listener = listener
	sim.sessions.Add(1)
	go sim.accept()
	t.Cleanup(sim.stop)
	return sim
}

func (s *smtpSim) stop() {
	s.stopOnce.Do(func() {
		close(s.done)
		_ = s.listener.Close()
		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
	})
	s.sessions.Wait()
}

func (s *smtpSim) port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

// messages returns what the simulator has been handed so far.
func (s *smtpSim) messages() []smtpSimMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]smtpSimMessage(nil), s.received...)
}

// connections returns how many connections the simulator has accepted.
func (s *smtpSim) connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

func (s *smtpSim) accept() {
	defer s.sessions.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.accepted++
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.sessions.Add(1)
		go func() {
			defer s.sessions.Done()
			defer func() {
				_ = conn.Close()
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			s.session(conn)
		}()
	}
}

func (s *smtpSim) tlsConfig() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{s.certificate}}
}

func (s *smtpSim) offers(mechanism string) bool {
	for _, offered := range strings.Fields(s.Mechanisms) {
		if strings.EqualFold(offered, mechanism) {
			return true
		}
	}
	return false
}

func (s *smtpSim) session(conn net.Conn) {
	if s.Mute {
		<-s.done
		return
	}
	encrypted := false
	if s.ImplicitTLS {
		secured := tls.Server(conn, s.tlsConfig())
		if err := secured.Handshake(); err != nil {
			return
		}
		conn, encrypted = secured, true
	}
	reader := bufio.NewReader(conn)
	say := func(line string) {
		_, _ = conn.Write([]byte(line + "\r\n"))
	}
	hear := func() (string, bool) {
		line, err := reader.ReadString('\n')
		return strings.TrimRight(line, "\r\n"), err == nil
	}
	unbase64 := func(text string) string {
		decoded, _ := base64.StdEncoding.DecodeString(text)
		return string(decoded)
	}

	say("220 smtp-sim ESMTP")
	var message smtpSimMessage
	mechanism := ""
	for {
		line, ok := hear()
		if !ok {
			return
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"):
			features := []string{"smtp-sim"}
			if s.OfferSTARTTLS && !encrypted {
				features = append(features, "STARTTLS")
			}
			if s.Mechanisms != "" && (encrypted || !s.AuthOnlyEncrypted) {
				features = append(features, "AUTH "+s.Mechanisms)
			}
			for i, feature := range features {
				separator := "-"
				if i == len(features)-1 {
					separator = " "
				}
				say("250" + separator + feature)
			}

		case strings.HasPrefix(upper, "HELO"):
			say("250 smtp-sim")

		case upper == "STARTTLS":
			if !s.OfferSTARTTLS || encrypted {
				say("502 5.5.1 not available")
				continue
			}
			say("220 2.0.0 ready to start TLS")
			secured := tls.Server(conn, s.tlsConfig())
			if err := secured.Handshake(); err != nil {
				return
			}
			conn, encrypted = secured, true
			reader = bufio.NewReader(conn)
			mechanism = ""

		case strings.HasPrefix(upper, "AUTH "):
			fields := strings.Fields(line)
			requested := strings.ToUpper(fields[1])
			if !s.offers(requested) || (s.AuthOnlyEncrypted && !encrypted) {
				say("504 5.5.4 unrecognized authentication type")
				continue
			}
			username, password := "", ""
			switch requested {
			case "PLAIN":
				response := ""
				if len(fields) > 2 {
					response = fields[2]
				} else {
					say("334 ")
					if response, ok = hear(); !ok {
						return
					}
				}
				if parts := strings.Split(unbase64(response), "\x00"); len(parts) == 3 {
					username, password = parts[1], parts[2]
				}
			case "LOGIN":
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Username:")))
				answer, ok := hear()
				if !ok {
					return
				}
				username = unbase64(answer)
				say("334 " + base64.StdEncoding.EncodeToString([]byte("Password:")))
				if answer, ok = hear(); !ok {
					return
				}
				password = unbase64(answer)
			default:
				say("504 5.5.4 unrecognized authentication type")
				continue
			}
			if s.Username != "" && username == s.Username && password == s.Password {
				mechanism = requested
				say("235 2.7.0 authentication successful")
			} else {
				say("535 5.7.8 authentication credentials invalid")
			}

		case strings.HasPrefix(upper, "MAIL FROM:"):
			if s.RequireAuth && mechanism == "" {
				say("530 5.7.0 authentication required")
				continue
			}
			message = smtpSimMessage{
				From:      smtpSimAddress(line[len("MAIL FROM:"):]),
				Encrypted: encrypted,
				Mechanism: mechanism,
			}
			say("250 2.1.0 sender ok")

		case strings.HasPrefix(upper, "RCPT TO:"):
			recipient := smtpSimAddress(line[len("RCPT TO:"):])
			if recipient == s.RefusedRecipient {
				say("550 5.1.1 no such user")
				continue
			}
			message.To = append(message.To, recipient)
			say("250 2.1.5 recipient ok")

		case upper == "DATA":
			say("354 end with a line that holds a dot and nothing else")
			var raw strings.Builder
			for {
				dataLine, ok := hear()
				if !ok {
					return
				}
				if dataLine == "." {
					break
				}
				// The sender doubles a dot at the start of a line.
				raw.WriteString(strings.TrimPrefix(dataLine, "."))
				raw.WriteString("\r\n")
			}
			if s.MuteAfterMessage {
				<-s.done
				return
			}
			message.Raw = raw.String()
			s.mu.Lock()
			s.received = append(s.received, message)
			s.mu.Unlock()
			say("250 2.0.0 message accepted")

		case upper == "RSET", upper == "NOOP":
			say("250 2.0.0 ok")

		case upper == "QUIT":
			say("221 2.0.0 bye")
			return

		default:
			say("502 5.5.1 command not implemented")
		}
	}
}

// smtpSimAddress returns the address between the angle brackets of a MAIL or
// RCPT argument.
func smtpSimAddress(argument string) string {
	start := strings.IndexByte(argument, '<')
	end := strings.IndexByte(argument, '>')
	if start < 0 || end < start {
		return strings.TrimSpace(argument)
	}
	return argument[start+1 : end]
}

// newLoopbackCertificate makes a certificate for a server on the loopback
// interface, and the pool a client needs to trust it. It lives as long as the
// test: no key is kept in the repository.
func newLoopbackCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("cannot make a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "smtp-sim"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cannot make a certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("cannot read the certificate back: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}
