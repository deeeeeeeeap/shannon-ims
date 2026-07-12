// Package voiceclient is the network-facing IMS SIP UAC: REGISTER against
// the P-CSCF (IMS-AKA per RFC 3310, via runtimehost/simauth) and SMS-over-IP
// via SIP MESSAGE (3GPP TS 24.341), on top of an already-established SWu
// tunnel. It's the production home for the mechanics validated across
// spike/sipspike/{main,challenge,imsaka,resync,message} -- this package is
// what actually gets exercised by Instance.SendSMS, not a repeat of those
// spikes.
//
// Two things are intentionally NOT solved here, matching the honest-gap
// pattern already used for engine/swu.Config.CACerts:
//
//   - P-CSCF discovery. The real mechanism (3GPP TS 24.302) is an IKE_AUTH
//     configuration-attribute exchange, symmetric to how engine/swu/akabridge
//     bridges EAP-AKA -- a matching engine/swu/pcscfbridge C plugin was
//     started but paused. Config.PCSCFAddr is a required, caller-supplied
//     address for now.
//   - IMPU derivation. A real UE uses a distinct IMS public identity from
//     the EAP-AKA NAI/IMPI. Config.Identity reuses the SAME identity
//     already resolved for the tunnel (identity.PreparedSession.EAPIdentity())
//     -- simpler, not a spec claim.
//
// Inbound SMS (an unsolicited MESSAGE carrying an RP-DATA SMS-DELIVER, i.e.
// someone texting the UE) is also out of scope here: decoding a DELIVER
// TPDU into sender/text needs vohive's pkg/smscodec, which this module
// can't import (wrong dependency direction) -- symmetric to why
// messaging.SMSPart carries pre-encoded bytes for the outbound direction.
// Delivery *reports* for our own outbound SMS (RP-ACK/RP-ERROR) don't have
// this problem: correlating them only needs the RP envelope's message type
// and RP-MR (a few fixed bytes per 3GPP TS 24.011), not the TPDU, so that
// part IS implemented here (see sms.go's classifyRPEnvelope).
package voiceclient

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/1239t/swu-go/pkg/logger"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"

	"github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
)

// Config configures a Client.
type Config struct {
	DeviceID string
	TraceID  string

	// LocalIP is the tunnel's assigned virtual IP (swu.Session.LocalIP());
	// the SIP UA binds here so traffic actually flows through the SWu
	// tunnel rather than the host's default route.
	LocalIP net.IP

	// Dataplane sends and receives inner IP packets through the SWu Child SA.
	// When present, SIP UDP runs fully in-process and does not bind the
	// tunnel IP on the host kernel.
	Dataplane PacketDataplane

	// LocalPort is the port to listen on at LocalIP. 0 defaults to 5060.
	LocalPort int

	// PCSCFAddr is the P-CSCF ("host:port") to REGISTER against and route
	// MESSAGE through. See the package doc comment: required because
	// discovery isn't wired up yet.
	PCSCFAddr string

	// SecurityVerify is the verified Security-Server mechanism from the
	// authenticated REGISTER. Protected non-REGISTER requests must mirror it.
	SecurityVerify string

	// SMSC is the service-centre address used to construct the SC PSI for
	// originating SMS-over-IMS MESSAGE requests.
	SMSC string

	// ServiceRoutes are the raw Service-Route values learned from REGISTER.
	ServiceRoutes []string

	// RegistrarCandidates is the ordered IKE/ePDG P-CSCF list for imscore
	// registrar probing. When empty, imscore falls back to PCSCFAddr.
	RegistrarCandidates []string

	// Transport is the IMS SIP transport for this carrier profile: "udp" or "tcp".
	// When empty, legacy behavior falls back to UDP if Dataplane is present, else TCP.
	Transport string

	// Realm is the IMS realm used in REGISTER/Authorization (e.g.
	// "ims.mnc001.mcc001.3gppnetwork.org").
	Realm string

	// PrivateID is the IMS private identity / IMPI used for digest AKA auth.
	PrivateID string

	// PublicURI is the SIP public identity / IMPU used in From/To/P-Preferred-Identity.
	PublicURI string

	// IMSI is the live SIM IMSI used to build handset-mimic IMS identities.
	IMSI string

	// EAPPrivateID is the SWu tunnel EAP-AKA identity (nai.epc...), kept for
	// REGISTER variants that fall back to the default private-id shape.
	EAPPrivateID string

	// HomeDomain is the registrar/home domain used in the REGISTER Request-URI.
	HomeDomain string

	// AKA computes IMS-AKA (RFC 3310) responses. The same sim.AKAProvider
	// already authenticating the SWu tunnel's EAP-AKA -- a second,
	// independent AKA run against the P-CSCF/S-CSCF's own RAND/AUTN.
	AKA sim.AKAProvider

	DeliveryStore messaging.DeliveryStore

	// RegisterExpiry is the requested REGISTER expiration. <= 0 defaults to
	// 600s; the Client re-registers at half that interval.
	RegisterExpiry time.Duration

	// MCC/MNC identify the home PLMN for carrier-specific REGISTER headers.
	// When empty, PLMN is derived from HomeDomain.
	MCC string
	MNC string

	// CellID is an optional E-UTRAN cell identity suffix (hex) appended to the
	// home PLMN in Cellular-Network-Info. When empty, SimAdmin-style placeholder
	// zeros are used.
	CellID string

	// RegisterProfile optionally overrides carrier-specific REGISTER headers.
	RegisterProfile RegisterProfile

	// SIPInstanceURN optionally overrides the +sip.instance value (e.g. urn:gsma:imei:...).
	SIPInstanceURN string

	// SkipRegister skips the REGISTER handshake when IMS registration was already
	// completed by imscore (ipsec-3gpp path).
	SkipRegister bool
}

func (c Config) contactURI() string {
	transport := c.transportNetwork()
	user := c.contactUser()
	if user == "" {
		user = "anonymous"
	}
	return fmt.Sprintf("sip:%s@%s;transport=%s", user, net.JoinHostPort(c.LocalIP.String(), strconv.Itoa(c.localPort())), transport)
}

func (c Config) contactUser() string {
	publicURI := strings.TrimSpace(c.PublicURI)
	if strings.HasPrefix(strings.ToLower(publicURI), "sip:") {
		publicURI = publicURI[4:]
	}
	if idx := strings.Index(publicURI, "@"); idx > 0 {
		return publicURI[:idx]
	}
	return strings.TrimSpace(c.PrivateID)
}

func (c Config) transportNetwork() string {
	switch strings.ToLower(strings.TrimSpace(c.Transport)) {
	case "tcp", "udp":
		return strings.ToLower(strings.TrimSpace(c.Transport))
	default:
		if c.Dataplane != nil {
			return "udp"
		}
		return "tcp"
	}
}

func (c Config) localPort() int {
	if c.LocalPort > 0 {
		return c.LocalPort
	}
	return 5060
}

func (c Config) registerExpiry() time.Duration {
	if c.RegisterExpiry > 0 {
		return c.RegisterExpiry
	}
	return 3600 * time.Second
}

// Client is a registered (or attempting-to-register) IMS SIP UAC for one
// device.
type Client struct {
	cfg        Config
	ua         *sipgo.UserAgent
	client     *sipgo.Client
	server     *sipgo.Server
	packetConn net.PacketConn
	swuTCP     *swuNetstack
	secure     *secureMessagingTransport

	registerProfile RegisterProfile
	sipInstanceURN  string
	contactUser     string
	basePrivateID   string
	basePublicURI   string
	securityClient  securityClientState

	mu       sync.Mutex
	closed   bool
	stopCh   chan struct{}
	stopDone chan struct{}
}

// Dial builds the SIP UA/client/server bound to cfg.LocalIP, performs the
// initial REGISTER (including an IMS-AKA sync-failure/auts retry if the SIM
// reports one), and starts a background re-register loop. Returns an error
// if REGISTER doesn't succeed -- no fake-success Client, same principle as
// engine/swu.Dial.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.AKA == nil {
		return nil, fmt.Errorf("voiceclient: Config.AKA is required")
	}
	if cfg.LocalIP == nil {
		return nil, fmt.Errorf("voiceclient: Config.LocalIP is required")
	}
	if cfg.PCSCFAddr == "" {
		return nil, fmt.Errorf("voiceclient: Config.PCSCFAddr is required (P-CSCF discovery isn't wired up yet)")
	}
	if strings.TrimSpace(cfg.PrivateID) == "" {
		return nil, fmt.Errorf("voiceclient: Config.PrivateID is required")
	}
	if strings.TrimSpace(cfg.PublicURI) == "" {
		return nil, fmt.Errorf("voiceclient: Config.PublicURI is required")
	}
	if strings.TrimSpace(cfg.HomeDomain) == "" {
		return nil, fmt.Errorf("voiceclient: Config.HomeDomain is required")
	}
	logger.Info("IMS voiceclient dialing",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
		logger.String("pcscf", cfg.PCSCFAddr),
		logger.String("local_ip", cfg.LocalIP.String()),
		logger.Int("local_port", cfg.localPort()),
		logger.String("transport", cfg.transportNetwork()),
		logger.Bool("dataplane", cfg.Dataplane != nil))
	installSIPTrace(cfg.TraceID, cfg.DeviceID)
	var err error
	var swuTCP *swuNetstack
	if cfg.Dataplane != nil && cfg.transportNetwork() == "tcp" {
		swuTCP, err = newSWUNetstack(cfg.LocalIP, cfg.Dataplane)
		if err != nil {
			return nil, err
		}
	}
	registerProfile := registerProfileForConfig(cfg).Normalized()
	if strings.TrimSpace(cfg.RegisterProfile.ContactFeatures) != "" {
		registerProfile = cfg.RegisterProfile.Normalized()
	}
	uaOptions := []sipgo.UserAgentOption{
		sipgo.WithUserAgent(registerProfile.UserAgent),
	}
	if swuTCP != nil {
		uaOptions = append(uaOptions, sipgo.WithUserAgentTransportLayerOptions(
			sip.WithTransportLayerTransports(sip.TransportsConfig{
				TCP: &sip.TransportTCP{
					DialContext: func(ctx context.Context, laddr net.Addr, raddr net.Addr) (net.Conn, error) {
						tcpAddr, ok := raddr.(*net.TCPAddr)
						if !ok || tcpAddr == nil {
							return nil, fmt.Errorf("voiceclient: invalid SWu TCP remote addr %v", raddr)
						}
						localPort := cfg.localPort()
						if localTCP, ok := laddr.(*net.TCPAddr); ok && localTCP != nil {
							if localTCP.Port > 0 {
								localPort = localTCP.Port
							}
						}
						return swuTCP.DialContextTCP(ctx, cfg.LocalIP, localPort, tcpAddr.IP, tcpAddr.Port)
					},
				},
			}),
		))
	}
	ua, err := sipgo.NewUA(uaOptions...)
	if err != nil {
		if swuTCP != nil {
			_ = swuTCP.Close()
		}
		return nil, fmt.Errorf("voiceclient: new UA: %w", err)
	}
	if cfg.Dataplane == nil {
		if err := waitLocalIPBindable(ctx, cfg.LocalIP, 5*time.Second); err != nil {
			if swuTCP != nil {
				_ = swuTCP.Close()
			}
			return nil, err
		}
	}
	clientOptions := []sipgo.ClientOption{
		sipgo.WithClientHostname(cfg.LocalIP.String()),
		sipgo.WithClientPort(cfg.localPort()),
		sipgo.WithClientConnectionAddr(net.JoinHostPort(cfg.LocalIP.String(), strconv.Itoa(cfg.localPort()))),
	}
	if cfg.Dataplane != nil && cfg.transportNetwork() == "udp" {
		clientOptions = []sipgo.ClientOption{
			sipgo.WithClientHostname(cfg.LocalIP.String()),
			sipgo.WithClientPort(cfg.localPort()),
			sipgo.WithClientConnectionAddr(net.JoinHostPort(cfg.LocalIP.String(), strconv.Itoa(cfg.localPort()))),
			sipgo.WithClientNAT(),
		}
	}
	sipClient, err := sipgo.NewClient(ua, clientOptions...)
	if err != nil {
		if swuTCP != nil {
			_ = swuTCP.Close()
		}
		return nil, fmt.Errorf("voiceclient: new client: %w", err)
	}
	sipServer, err := sipgo.NewServer(ua)
	if err != nil {
		if swuTCP != nil {
			_ = swuTCP.Close()
		}
		sipClient.Close()
		return nil, fmt.Errorf("voiceclient: new server: %w", err)
	}

	sipInstanceURN := strings.TrimSpace(cfg.SIPInstanceURN)
	if sipInstanceURN == "" {
		sipInstanceURN = NewSIPInstanceURN()
	}
	contactUser := ""
	if registerProfile.ContactUserRandom {
		contactUser = newContactUserUUID()
	}
	if cfg.RegisterExpiry <= 0 && registerProfile.RegisterExpirySeconds > 0 {
		cfg.RegisterExpiry = time.Duration(registerProfile.RegisterExpirySeconds) * time.Second
	}
	c := &Client{
		cfg:             cfg,
		ua:              ua,
		client:          sipClient,
		server:          sipServer,
		swuTCP:          swuTCP,
		registerProfile: registerProfile,
		sipInstanceURN:  sipInstanceURN,
		contactUser:     contactUser,
		basePrivateID:   cfg.PrivateID,
		basePublicURI:   cfg.PublicURI,
		securityClient:  newSecurityClientState(),
		stopCh:          make(chan struct{}),
		stopDone:        make(chan struct{}),
	}
	sipServer.OnMessage(c.handleIncomingMessage)

	serverDone := make(chan error, 1)
	go func() {
		if cfg.Dataplane != nil && cfg.transportNetwork() == "udp" {
			pc := newSWUPacketConn(cfg.LocalIP, cfg.localPort(), cfg.Dataplane)
			c.packetConn = pc
			serverDone <- sipServer.ServeUDP(pc)
			return
		}
		if cfg.Dataplane != nil && cfg.transportNetwork() == "tcp" {
			// For IMS-over-TCP on the userspace SWu dataplane, inbound SIP
			// requests and responses arrive on the client-established TCP
			// connection to the P-CSCF; no kernel listener should be started.
			serverDone <- nil
			return
		}
		serverDone <- sipServer.ListenAndServe(context.Background(), cfg.transportNetwork(), imsListenAddr(cfg.LocalIP, cfg.localPort()))
	}()

	// Give the listener a moment to bind before we register (mirrors the
	// same settle delay used across the sipspike/* spikes).
	select {
	case <-time.After(200 * time.Millisecond):
	case err := <-serverDone:
		if err == nil {
			break
		}
		sipClient.Close()
		if swuTCP != nil {
			_ = swuTCP.Close()
		}
		return nil, fmt.Errorf("voiceclient: server failed to start: %w", err)
	}

	if !cfg.SkipRegister {
		registerCtx, registerCancel := context.WithTimeout(ctx, registerDialTimeout)
		defer registerCancel()
		if err := c.registerWithResync(registerCtx); err != nil {
			_ = c.shutdownSIPStack()
			return nil, fmt.Errorf("voiceclient: register: %w", err)
		}
		logger.Info("IMS voiceclient registered",
			logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
			logger.String("pcscf", cfg.PCSCFAddr),
			logger.String("transport", cfg.transportNetwork()))
		go c.reregisterLoop()
	} else {
		logger.Info("IMS voiceclient skipping REGISTER (already registered)",
			logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
			logger.String("pcscf", cfg.PCSCFAddr))
	}

	return c, nil
}

func imsListenAddr(localIP net.IP, port int) string {
	return net.JoinHostPort(localIP.String(), strconv.Itoa(port))
}

func waitLocalIPBindable(ctx context.Context, localIP net.IP, timeout time.Duration) error {
	if localIP == nil {
		return fmt.Errorf("voiceclient: LocalIP is required")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var lastErr error
	for {
		if err := probeTCPBind(localIP); err == nil {
			return nil
		} else {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("voiceclient: wait for tunnel IP %s bindable: %w (last bind error: %v)", localIP, ctx.Err(), lastErr)
		case <-deadline.C:
			return fmt.Errorf("voiceclient: tunnel IP %s is not bindable after %s (last bind error: %v)", localIP, timeout, lastErr)
		case <-ticker.C:
		}
	}
}

func probeTCPBind(localIP net.IP) error {
	network := "tcp4"
	if localIP.To4() == nil {
		network = "tcp6"
	}
	ln, err := net.Listen(network, net.JoinHostPort(localIP.String(), "0"))
	if err != nil {
		return err
	}
	return ln.Close()
}

// Close stops the re-register loop and the SIP listener/client. Best
// effort: does not attempt an explicit un-REGISTER (Expires: 0) since the
// registration will simply lapse, and the caller tearing down the SWu
// tunnel underneath makes an explicit un-REGISTER round trip moot anyway.
func (c *Client) Close(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	close(c.stopCh)
	<-c.stopDone
	return c.shutdownSIPStack()
}

func (c *Client) shutdownSIPStack() error {
	if c.secure != nil {
		_ = c.secure.Close()
		c.secure = nil
	}
	if c.packetConn != nil {
		_ = c.packetConn.Close()
		c.packetConn = nil
	}
	if c.swuTCP != nil {
		_ = c.swuTCP.Close()
		c.swuTCP = nil
	}
	if c.server != nil {
		_ = c.server.Close()
		c.server = nil
	}
	if c.client != nil {
		_ = c.client.Close()
		c.client = nil
	}
	if c.ua != nil {
		_ = c.ua.Close()
		c.ua = nil
	}
	return nil
}

func (c *Client) newRequest(method sip.RequestMethod, target string, initialRegister bool) (*sip.Request, error) {
	recipient, err := c.requestURI(method, target)
	if err != nil {
		return nil, err
	}
	req := sip.NewRequest(method, recipient)
	if method == sip.MESSAGE {
		for _, route := range c.cfg.ServiceRoutes {
			if value := strings.TrimSpace(route); value != "" {
				req.AppendHeader(sip.NewHeader("Route", value))
			}
		}
		if identity := strings.TrimSpace(c.cfg.PublicURI); identity != "" {
			req.AppendHeader(sip.NewHeader("P-Preferred-Identity", "<"+identity+">"))
		}
	}
	req.AppendHeader(sip.NewHeader("From", "<"+c.cfg.PublicURI+">;tag="+sip.GenerateTagN(16)))
	toURI := c.registerToURI(method)
	if method == sip.MESSAGE {
		toURI = recipient.String()
	}
	req.AppendHeader(sip.NewHeader("To", "<"+toURI+">"))
	req.AppendHeader(sip.NewHeader("Contact", c.cfg.buildContactHeader(c.registerProfile, c.sipInstanceURN, c.contactUser)))
	if method == sip.REGISTER {
		requestURI := "sip:" + strings.TrimSpace(c.cfg.HomeDomain)
		if initialRegister {
			if auth := buildInitialAuthorization(c.cfg, c.registerProfile, requestURI); auth != "" {
				req.AppendHeader(sip.NewHeader("Authorization", auth))
			}
		}
		if c.registerProfile.IncludeRoute {
			req.AppendHeader(sip.NewHeader("Route", "<sip:"+target+";lr>"))
		}
		req.AppendHeader(sip.NewHeader("Expires", strconv.Itoa(int(c.cfg.contactExpires(c.registerProfile).Seconds()))))
		if c.registerProfile.IncludeRequireSecAgree {
			req.AppendHeader(sip.NewHeader("Require", "sec-agree"))
			req.AppendHeader(sip.NewHeader("Proxy-Require", "sec-agree"))
		}
		req.AppendHeader(sip.NewHeader("Supported", c.registerProfile.SupportedHeader))
		req.AppendHeader(sip.NewHeader("Allow", "INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,NOTIFY,INFO,OPTIONS"))
		if c.registerProfile.IncludePPreferredID {
			req.AppendHeader(sip.NewHeader("P-Preferred-Identity", "<"+c.cfg.PublicURI+">"))
		}
		if c.registerProfile.IncludePVisitedNetworkID {
			req.AppendHeader(sip.NewHeader("P-Visited-Network-ID", "\""+c.cfg.HomeDomain+"\""))
		}
		if c.registerProfile.IncludePAccessNetworkInfo {
			req.AppendHeader(sip.NewHeader("P-Access-Network-Info", buildPAccessNetworkInfo(c.registerProfile)))
		}
		if c.registerProfile.IncludeCellularNetwork {
			plmn := plmnFromIMSDomain(c.cfg.HomeDomain)
			if plmn == "" {
				plmn = plmnFromIMSDomain(c.cfg.Realm)
			}
			req.AppendHeader(sip.NewHeader("Cellular-Network-Info", buildCellularNetworkInfo(plmn, c.cfg.CellID)))
		}
		if c.registerProfile.IncludeAcceptContact {
			req.AppendHeader(sip.NewHeader("Accept-Contact", "*;+g.3gpp.smsip"))
			req.AppendHeader(sip.NewHeader("Accept-Contact", "*;+g.3gpp.icsi-ref=\""+imsMmtelICSIRef+"\""))
		}
		if c.registerProfile.IncludeSecurityClient {
			req.AppendHeader(sip.NewHeader("Security-Client", buildSecurityClientHeader(c.registerProfile, c.securityClient)))
		}
		req.AppendHeader(sip.NewHeader("User-Agent", c.registerProfile.UserAgent))
		if !c.registerProfile.IncludeRoute && strings.TrimSpace(c.cfg.PCSCFAddr) != "" {
			// Handset-style REGISTER omits Route but still sends over the discovered P-CSCF.
			req.SetDestination(c.cfg.PCSCFAddr)
		}
	}
	if c.cfg.transportNetwork() == "udp" {
		req.SetTransport("UDP")
	} else {
		req.SetTransport("TCP")
	}
	return req, nil
}

func (c *Client) registerToURI(method sip.RequestMethod) string {
	if method == sip.REGISTER {
		return strings.TrimSpace(c.cfg.PublicURI)
	}
	return strings.TrimSpace(c.cfg.PublicURI)
}

func (c *Client) requestURI(method sip.RequestMethod, target string) (sip.Uri, error) {
	raw := strings.TrimSpace(target)
	if method == sip.REGISTER {
		raw = "sip:" + strings.TrimSpace(c.cfg.HomeDomain)
	} else if !strings.HasPrefix(strings.ToLower(raw), "sip:") && !strings.HasPrefix(strings.ToLower(raw), "sips:") {
		raw = "sip:" + raw
	}
	recipient := sip.Uri{}
	if err := sip.ParseUri(raw, &recipient); err != nil {
		return sip.Uri{}, fmt.Errorf("voiceclient: parse target uri %q: %w", raw, err)
	}
	return recipient, nil
}
