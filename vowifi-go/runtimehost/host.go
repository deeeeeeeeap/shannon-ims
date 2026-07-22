package runtimehost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	swulogger "github.com/1239t/swu-go/pkg/logger"
	swusim "github.com/1239t/vowifi-go/engine/sim"
	"github.com/1239t/vowifi-go/internal/vowifi/imscore"
	"github.com/1239t/vowifi-go/internal/vowifi/policy"
	"github.com/1239t/vowifi-go/internal/vowifi/runtimecore"
	"github.com/1239t/vowifi-go/runtimehost/identity"
	"github.com/1239t/vowifi-go/runtimehost/messaging"
	"github.com/1239t/vowifi-go/runtimehost/transport"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
	"go.uber.org/zap"
)

var ErrAPDUBusy = errors.New("apdu busy")

type StartMode string

const StartModeMain StartMode = "main"

type Profile = identity.Profile
type PreparedSession = identity.PreparedSession

type Modem interface {
	DeviceID() string
	IsHealthy() bool
	IsSimInserted() bool
	QuerySIMInserted() (bool, error)
	GetRegStatus() (int, string)
	ExecuteATSilent(cmd string, timeout time.Duration) (string, error)
	OpenLogicalChannel(aid string) (int, error)
	ResolveLogicalChannelAID(app string, fallbackAID string) (string, string, error)
	CloseLogicalChannel(channel int) error
	TransmitAPDU(channel int, hexAPDU string) (string, error)
	GetISIMIdentity() (identity.Identity, error)
	GetNetworkMode() string
	Stop()
}

type SIMAdapter interface {
	GetIMSI() (string, error)
	CalculateAKA(rand16, autn16 []byte) (swusim.AKAResult, error)
	Close() error
}

type providerOnlyAdapter struct {
	provider interface{}
	imsi     string
}

func (a *providerOnlyAdapter) GetIMSI() (string, error) {
	if a != nil && strings.TrimSpace(a.imsi) != "" {
		return strings.TrimSpace(a.imsi), nil
	}
	return "", errors.New("runtimehost: provider-only SIM adapter cannot read IMSI")
}

func (a *providerOnlyAdapter) CalculateAKA(rand16, autn16 []byte) (swusim.AKAResult, error) {
	if a == nil || a.provider == nil {
		return swusim.AKAResult{}, errors.New("runtimehost: SIM provider unavailable")
	}
	p, ok := a.provider.(swusim.AKAProvider)
	if !ok {
		return swusim.AKAResult{}, errors.New("runtimehost: wrapped provider does not implement AKAProvider")
	}
	return p.CalculateAKA(rand16, autn16)
}

func (a *providerOnlyAdapter) Close() error { return nil }

type ProxyConfig struct {
	ID       string
	Addr     string
	Host     string
	Address  string
	Port     int
	Username string
	Password string
	Enabled  bool
}

type State struct {
	LastErrorClass string
	LastError      string
	LastReason     string
	NetworkMode    string
	DataplaneMode  string
	DeviceID       string
	Phase          string
	SIMReady       bool
	AccessReady    bool
	TunnelReady    bool
	IMSReady       bool
	SMSReady       bool
	RegStatus      int
	RegStatusText  string
	UpdatedAt      time.Time
	IMSI           string
	PhoneNumber    string
}

const PhaseSIMReady = "sim_ready"

type SessionConfig struct {
	IMSISecret    []byte
	DataplaneMode string
	TraceID       string
	DeviceID      string
	NetworkMode   string
}

type Event struct {
	State State
}

type Observer interface {
	Observe(ctx context.Context, ev Event)
}

type ObserverFunc func(context.Context, Event)

func (f ObserverFunc) Observe(ctx context.Context, ev Event) { f(ctx, ev) }

type DataplanePolicy struct {
	Mode string
}

type StartRequest struct {
	Mode         StartMode
	DeviceID     string
	TraceID      string
	Profile      Profile
	Prepared     *PreparedSession
	NetworkMode  string
	VoiceGateway interface{}
	SIM          SIMAdapter
	Access       ModemAccess
	Dataplane    DataplanePolicy
	Proxy        *ProxyConfig
	PCSCFAddr    string
	// CellID is the utran-cell-id-3gpp suffix (TAC+ECI hex) injected from live QMI
	// readings before flight mode. When empty, IMS REGISTER uses placeholder zeros.
	CellID string

	// RegisterProfile optionally overrides carrier-specific REGISTER headers.
	RegisterProfile voiceclient.RegisterProfile
	// SIPInstanceURN optionally overrides +sip.instance (e.g. urn:gsma:imei:...).
	SIPInstanceURN string
	// RegisterExpiry optionally overrides the REGISTER Expires value.
	RegisterExpiry time.Duration

	DeliveryStore messaging.DeliveryStore
	Dispatch      interface{}
	BeforeStart   func(context.Context, SessionConfig) error
	ShouldRun     func() bool
}

type ModemAccess interface {
	GetISIMIdentity() (identity.Identity, error)
}

type modemAccessAdapter struct {
	modem Modem
}

func (a *modemAccessAdapter) GetISIMIdentity() (identity.Identity, error) {
	if a == nil || a.modem == nil {
		return identity.Identity{}, errors.New("modem unavailable")
	}
	return a.modem.GetISIMIdentity()
}

type swuSnapshot struct {
	Established bool
	TUNName     string
	IPv4        net.IP
	IPv6        net.IP
	PCSCFv4     []net.IP
	PCSCFv6     []net.IP
}

type Instance struct {
	deviceID        string
	shouldRun       func() bool
	akaProvider     swusim.AKAProvider
	imsPrivateID    string
	imsPublicURI    string
	imsEAPPrivateID string
	imsIMSI         string
	imsDomain       string
	imsRealm        string
	imsTransport    string
	imsMCC          string
	imsMNC          string
	imsCellID       string
	registerProfile voiceclient.RegisterProfile
	sipInstanceURN  string
	registerExpiry  time.Duration
	traceID         string
	pcscfOverride   string
	deliveryStore   messaging.DeliveryStore

	mu                  sync.Mutex
	serviceUsers        int
	serviceIdle         chan struct{}
	state               State
	observers           []Observer
	notifier            func(string)
	smsNotifier         func(string, string, string, time.Time)
	stopped             bool
	lifecycleGeneration uint64

	svc             messaging.Service
	session         *runtimecore.SessionResult
	transport       transport.DatagramTransport
	swuCancel       context.CancelFunc
	pipelineCancel  context.CancelFunc
	swuMobike       func(oldIP, newIP string) error
	watchDone       chan struct{}
	stopCleanupDone chan struct{}
}

func (i *Instance) Service() messaging.Service {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped {
		return nil
	}
	return i.svc
}

const messagingServiceCleanupTimeout = 5 * time.Second

func closeMessagingService(_ context.Context, svc messaging.Service) {
	if closer, ok := svc.(interface{ Close(context.Context) error }); ok && closer != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), messagingServiceCleanupTimeout)
		defer cancel()
		_ = closer.Close(cleanupCtx)
	}
}

func isClosed(ch <-chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func (i *Instance) installService(
	ctx context.Context,
	generation uint64,
	svc messaging.Service,
	status func() map[string]interface{},
	localAddr string,
	pcscf string,
) bool {
	i.mu.Lock()
	if i.stopped || i.lifecycleGeneration != generation {
		i.mu.Unlock()
		closeMessagingService(ctx, svc)
		return false
	}
	runtimecore.AttachIMSService(i.session, svc, status, localAddr, pcscf)
	i.svc = svc
	i.mu.Unlock()
	return true
}

func (i *Instance) acquireServiceUseLocked() {
	if i.serviceUsers == 0 {
		i.serviceIdle = make(chan struct{})
	}
	i.serviceUsers++
}

func (i *Instance) releaseServiceUse() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.serviceUsers <= 0 {
		return
	}
	i.serviceUsers--
	if i.serviceUsers == 0 && i.serviceIdle != nil {
		close(i.serviceIdle)
		i.serviceIdle = nil
	}
}

func (i *Instance) installPipelineCancel(generation uint64, cancel context.CancelFunc) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped || i.lifecycleGeneration != generation {
		return false
	}
	i.pipelineCancel = cancel
	return true
}

func (i *Instance) installSWUCancel(generation uint64, cancel context.CancelFunc) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped || i.lifecycleGeneration != generation {
		return false
	}
	i.swuCancel = cancel
	return true
}

func (i *Instance) currentSWUCancel(generation uint64) context.CancelFunc {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped || i.lifecycleGeneration != generation {
		return nil
	}
	return i.swuCancel
}

func (i *Instance) installMOBIKE(generation uint64, mobike func(oldIP, newIP string) error) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped || i.lifecycleGeneration != generation {
		return false
	}
	i.swuMobike = mobike
	return true
}

func (i *Instance) updateStateForGeneration(generation uint64, mut func(*State)) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped || i.lifecycleGeneration != generation {
		return false
	}
	mut(&i.state)
	return true
}

func (i *Instance) Status() string {
	st := i.State()
	switch {
	case st.IMSReady && st.SMSReady:
		return "running"
	case st.TunnelReady:
		return "tunnel_ready"
	case st.AccessReady:
		return "connecting"
	case st.Phase != "":
		return "starting"
	default:
		return "stopped"
	}
}

func (i *Instance) State() State {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.state
}

func (i *Instance) Obs() map[string]interface{} {
	i.mu.Lock()
	st := i.state
	runtimecoreActive := i.session != nil
	var imsStatus func() map[string]interface{}
	if !i.stopped && i.session != nil && i.session.IMSStatus != nil {
		imsStatus = i.session.IMSStatus
		i.acquireServiceUseLocked()
	}
	i.mu.Unlock()
	obs := map[string]interface{}{
		"sim_ready":      st.SIMReady,
		"access_ready":   st.AccessReady,
		"tunnel_ready":   st.TunnelReady,
		"ims_ready":      st.IMSReady,
		"sms_ready":      st.SMSReady,
		"phase":          st.Phase,
		"last_reason":    st.LastReason,
		"last_error":     st.LastError,
		"error_class":    st.LastErrorClass,
		"dataplane_mode": st.DataplaneMode,
		"runtimecore":    runtimecoreActive,
	}
	if imsStatus != nil {
		defer i.releaseServiceUse()
		for k, v := range imsStatus() {
			obs[k] = v
		}
	}
	return obs
}

func (i *Instance) Stop(ctx context.Context) error {
	if i == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	i.mu.Lock()
	if i.stopped {
		cleanupDone := i.stopCleanupDone
		i.mu.Unlock()
		return waitForStopCleanup(ctx, cleanupDone)
	}
	i.stopped = true
	i.lifecycleGeneration++
	pipelineCancel := i.pipelineCancel
	cancel := i.swuCancel
	done := i.watchDone
	svc := i.svc
	tp := i.transport
	serviceIdle := i.serviceIdle
	cleanupDone := make(chan struct{})
	i.stopCleanupDone = cleanupDone
	i.pipelineCancel = nil
	i.swuCancel = nil
	i.svc = nil
	i.session = nil
	i.transport = nil
	i.swuMobike = nil
	i.mu.Unlock()

	if pipelineCancel != nil {
		pipelineCancel()
	}
	if cancel != nil {
		cancel()
	}
	go i.finishStopCleanup(ctx, done, serviceIdle, svc, tp, cleanupDone)
	return waitForStopCleanup(ctx, cleanupDone)
}

func waitForStopCleanup(ctx context.Context, cleanupDone <-chan struct{}) error {
	if cleanupDone == nil {
		return nil
	}
	select {
	case <-cleanupDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (i *Instance) finishStopCleanup(
	ctx context.Context,
	done <-chan struct{},
	serviceIdle <-chan struct{},
	svc messaging.Service,
	tp transport.DatagramTransport,
	cleanupDone chan struct{},
) {
	if done != nil {
		<-done
	}
	if serviceIdle != nil {
		<-serviceIdle
	}
	closeMessagingService(ctx, svc)
	if tp != nil {
		_ = tp.Close()
	}
	i.mu.Lock()
	if done == nil || isClosed(done) {
		i.watchDone = nil
	}
	i.mu.Unlock()
	close(cleanupDone)
}

func (i *Instance) AddObserver(o Observer) {
	if i == nil || o == nil {
		return
	}
	i.mu.Lock()
	i.observers = append(i.observers, o)
	i.mu.Unlock()
}

func (i *Instance) SetNotifier(fn func(string)) {
	i.mu.Lock()
	i.notifier = fn
	i.mu.Unlock()
}

func (i *Instance) SetSMSNotifier(fn func(string, string, string, time.Time)) {
	i.mu.Lock()
	i.smsNotifier = fn
	i.mu.Unlock()
}

func (i *Instance) TriggerMOBIKE(oldIP, newIP string) error {
	i.mu.Lock()
	mobike := i.swuMobike
	i.mu.Unlock()
	if mobike == nil {
		return errors.New("runtimehost: active tunnel does not support MOBIKE")
	}
	return mobike(oldIP, newIP)
}

func (i *Instance) GetSMSDeliveryStatus(messageID string) (*messaging.DeliveryStatus, error) {
	if i == nil || i.deliveryStore == nil {
		return nil, messaging.ErrDeliveryNotFound
	}
	return i.deliveryStore.GetSMSDeliveryStatus(messageID)
}

func (i *Instance) SendSMS(ctx context.Context, peer, content string, parts []messaging.SMSPart) (messaging.SendOutcome, error) {
	if i == nil {
		return messaging.SendOutcome{}, errors.New("runtimehost: instance is nil")
	}
	i.mu.Lock()
	if i.stopped {
		i.mu.Unlock()
		return messaging.SendOutcome{}, errors.New("runtimehost: instance stopped")
	}
	svc := i.svc
	if svc == nil {
		i.mu.Unlock()
		return messaging.SendOutcome{}, errors.New("runtimehost: IMS messaging service not ready")
	}
	i.acquireServiceUseLocked()
	i.mu.Unlock()
	defer i.releaseServiceUse()
	return svc.SendSMS(ctx, peer, content, parts)
}

func (i *Instance) updateState(mut func(*State)) State {
	i.mu.Lock()
	defer i.mu.Unlock()
	mut(&i.state)
	return i.state
}

func (i *Instance) snapshotForGeneration(generation uint64) (State, []Observer, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.stopped || i.lifecycleGeneration != generation {
		return State{}, nil, false
	}
	state := i.state
	observers := append([]Observer(nil), i.observers...)
	return state, observers, true
}

func (i *Instance) notifyObserversForGeneration(ctx context.Context, generation uint64) bool {
	state, observers, ok := i.snapshotForGeneration(generation)
	if !ok {
		return false
	}
	ev := Event{State: state}
	for _, o := range observers {
		o.Observe(ctx, ev)
	}
	return true
}

func (i *Instance) failStageForGeneration(ctx context.Context, generation uint64, class, errMsg, reason string) {
	if !i.updateStateForGeneration(generation, func(s *State) {
		s.LastErrorClass = class
		s.LastError = errMsg
		s.LastReason = reason
		s.UpdatedAt = time.Now()
	}) {
		return
	}
	i.notifyObserversForGeneration(ctx, generation)
}

func Start(ctx context.Context, req StartRequest) (*Instance, error) {
	if req.ShouldRun != nil && !req.ShouldRun() {
		return nil, fmt.Errorf("runtimehost: start canceled")
	}
	if req.Prepared == nil {
		return nil, errors.New("runtimehost: StartRequest.Prepared is required")
	}

	deviceID := strings.TrimSpace(req.DeviceID)
	if deviceID == "" {
		return nil, errors.New("runtimehost: StartRequest.DeviceID is required")
	}
	if req.SIM == nil {
		return nil, errors.New("runtimehost: StartRequest.SIM is required")
	}

	eapIdentity := req.Prepared.EAPIdentity()
	if eapIdentity == "" {
		return nil, errors.New("runtimehost: could not resolve EAP/IKE identity from prepared session")
	}

	akaProvider, ok := req.SIM.(interface {
		CalculateAKA([]byte, []byte) (swusim.AKAResult, error)
	})
	if !ok {
		return nil, errors.New("runtimehost: SIM does not implement AKAProvider")
	}

	provider := swusim.AKAProvider(akaProvider)
	if pref := req.Prepared.IMSIdentity.AKAAppPreference; pref == identity.AKAAppPreferenceISIM || pref == identity.AKAAppPreferenceISIMStrict {
		if isimProvider, ok := req.SIM.(swusim.ISIMAKAProvider); ok {
			provider = isimAKAAdapter{isimProvider}
		} else if pref == identity.AKAAppPreferenceISIMStrict {
			return nil, fmt.Errorf("runtimehost: AKA app preference is %q but SIM provider does not support ISIM AKA", pref)
		}
	}

	dataplaneMode := strings.TrimSpace(req.Dataplane.Mode)
	if dataplaneMode == "" {
		dataplaneMode = "userspace"
	}

	if req.BeforeStart != nil {
		if err := req.BeforeStart(ctx, SessionConfig{
			DataplaneMode: dataplaneMode,
			TraceID:       req.TraceID,
			DeviceID:      deviceID,
			NetworkMode:   req.NetworkMode,
		}); err != nil {
			return nil, fmt.Errorf("runtimehost: BeforeStart: %w", err)
		}
	}

	imsi := strings.TrimSpace(req.Profile.IMSI)
	if liveIMSI, err := req.SIM.GetIMSI(); err == nil && strings.TrimSpace(liveIMSI) != "" {
		imsi = strings.TrimSpace(liveIMSI)
	}
	if imsi == "" {
		return nil, errors.New("runtimehost: SIM stage failed: IMSI unavailable")
	}

	registerProfile := req.RegisterProfile.Normalized()
	imsPrivateID, imsPublicURI := resolveIMSRegisterIdentities(eapIdentity, imsi, req.Prepared, registerProfile)

	session := runtimecore.BeginSession(toRuntimecoreSessionConfig(req))

	inst := &Instance{
		deviceID:        deviceID,
		session:         session,
		shouldRun:       req.ShouldRun,
		akaProvider:     provider,
		imsPrivateID:    imsPrivateID,
		imsPublicURI:    imsPublicURI,
		imsEAPPrivateID: eapIdentity,
		imsIMSI:         imsi,
		imsDomain:       resolveIMSDomain(req.Prepared),
		imsRealm:        req.Prepared.IMSRealm(),
		imsTransport:    simAdminIMSTransport(req.Profile.MCC, req.Profile.MNC),
		imsMCC:          strings.TrimSpace(req.Profile.MCC),
		imsMNC:          strings.TrimSpace(req.Profile.MNC),
		imsCellID:       strings.TrimSpace(req.CellID),
		registerProfile: registerProfile,
		sipInstanceURN:  strings.TrimSpace(req.SIPInstanceURN),
		registerExpiry:  req.RegisterExpiry,
		traceID:         strings.TrimSpace(req.TraceID),
		pcscfOverride:   req.PCSCFAddr,
		deliveryStore:   req.DeliveryStore,

		lifecycleGeneration: 1,
		watchDone:           make(chan struct{}),
		state: State{
			DeviceID:      deviceID,
			DataplaneMode: dataplaneMode,
			NetworkMode:   req.NetworkMode,
			Phase:         PhaseSIMReady,
			SIMReady:      true,
			IMSI:          imsi,
			UpdatedAt:     time.Now(),
			LastReason:    "sim_ready",
		},
	}

	routePolicy := buildRoutePolicy(req.Proxy)
	var tp transport.DatagramTransport
	var err error
	switch routePolicy.Kind {
	case transport.ProxySocks5UDPAssociate:
		tp, err = transport.NewSocks5UDPTransport(routePolicy.Addr, routePolicy.Username, routePolicy.Password)
	default:
		tp, err = transport.NewDirectUDPTransport()
	}
	if err != nil {
		inst.failStageForGeneration(ctx, 1, "access", fmt.Sprintf("transport create: %v", err), "access_transport_create_failed")
		return inst, fmt.Errorf("runtimehost: access transport: %w", err)
	}
	inst.transport = tp
	inst.updateState(func(s *State) {
		s.AccessReady = true
		s.LastReason = "access_ready"
		s.UpdatedAt = time.Now()
	})

	go inst.runStagedPipeline(ctx, req, 1)
	return inst, nil
}

func (i *Instance) runStagedPipeline(ctx context.Context, req StartRequest, generation uint64) {
	defer close(i.watchDone)

	pipelineCtx, pipelineCancel := context.WithCancel(ctx)
	if !i.installPipelineCancel(generation, pipelineCancel) {
		pipelineCancel()
		return
	}
	defer pipelineCancel()

	if i.shouldRun != nil && !i.shouldRun() {
		i.failStageForGeneration(ctx, generation, "canceled", "runtime canceled before tunnel start", "start_canceled")
		return
	}

	if !i.updateStateForGeneration(generation, func(s *State) {
		s.LastReason = "tunnel_resolving"
		s.UpdatedAt = time.Now()
	}) || !i.notifyObserversForGeneration(ctx, generation) {
		return
	}

	epdgHost, epdgPort := resolveEPDGHost(req)
	if epdgHost == "" {
		i.failStageForGeneration(ctx, generation, "tunnel", "ePDG FQDN not found", "tunnel_epdg_not_found")
		return
	}

	resolvedIPs, err := net.LookupHost(epdgHost)
	if err != nil || len(resolvedIPs) == 0 {
		i.failStageForGeneration(ctx, generation, "tunnel", fmt.Sprintf("ePDG DNS failed: %s -> %v", epdgHost, err), "tunnel_dns_failed")
		return
	}
	epdgIP := resolvedIPs[0]
	if !i.updateStateForGeneration(generation, func(s *State) {
		s.LastReason = fmt.Sprintf("tunnel_starting ePDG=%s:%s", epdgIP, epdgPort)
		s.UpdatedAt = time.Now()
	}) || !i.notifyObserversForGeneration(ctx, generation) {
		return
	}

	tunnelCtx, cancel := context.WithCancel(context.Background())
	if !i.installSWUCancel(generation, cancel) {
		cancel()
		return
	}

	snapshot, localIP, dataplane, mobike, err := i.startSWuSession(tunnelCtx, req, epdgIP, epdgPort)
	if err != nil {
		reason := classifyTunnelFailure(err)
		i.failStageForGeneration(ctx, generation, "tunnel", err.Error(), formatTunnelFailureReason(reason, err))
		return
	}

	if !i.installMOBIKE(generation, mobike) {
		cancel()
		return
	}

	pcscfCandidates := resolvePCSCFCandidates(snapshot, i.pcscfOverride, localIP)
	pcscfAddr := ""
	if len(pcscfCandidates) > 0 {
		pcscfAddr = pcscfCandidates[0]
	}
	tunnelReason := fmt.Sprintf("tunnel_ready ePDG=%s", epdgIP)
	if pcscfAddr != "" {
		if len(pcscfCandidates) > 1 {
			tunnelReason = fmt.Sprintf("%s pcscf=%s candidates=%d", tunnelReason, pcscfAddr, len(pcscfCandidates))
		} else {
			tunnelReason = fmt.Sprintf("%s pcscf=%s", tunnelReason, pcscfAddr)
		}
	} else {
		tunnelReason = fmt.Sprintf("%s pcscf=unavailable", tunnelReason)
	}

	if !i.updateStateForGeneration(generation, func(s *State) {
		s.TunnelReady = true
		s.LastReason = tunnelReason
		s.UpdatedAt = time.Now()
	}) || !i.notifyObserversForGeneration(ctx, generation) {
		return
	}

	if pcscfAddr == "" {
		i.failStageForGeneration(ctx, generation, "ims", "P-CSCF unavailable after tunnel establishment", "ims_pcscf_missing")
		return
	}

	voiceCfg := voiceclient.Config{
		DeviceID:            i.deviceID,
		TraceID:             i.traceID,
		LocalIP:             localIP,
		Dataplane:           dataplane,
		PCSCFAddr:           pcscfAddr,
		RegistrarCandidates: pcscfCandidates,
		Realm:               i.imsRealm,
		PrivateID:           i.imsPrivateID,
		PublicURI:           i.imsPublicURI,
		HomeDomain:          i.imsDomain,
		IMSI:                i.imsIMSI,
		SMSC:                strings.TrimSpace(req.Profile.SMSC),
		EAPPrivateID:        i.imsEAPPrivateID,
		Transport:           i.imsTransport,
		MCC:                 i.imsMCC,
		MNC:                 i.imsMNC,
		CellID:              i.imsCellID,
		AKA:                 i.akaProvider,
		DeliveryStore:       i.deliveryStore,
	}
	if strings.TrimSpace(i.registerProfile.ContactFeatures) != "" {
		voiceCfg.RegisterProfile = i.registerProfile
	}
	if strings.TrimSpace(i.sipInstanceURN) != "" {
		voiceCfg.SIPInstanceURN = i.sipInstanceURN
	}
	if i.registerExpiry > 0 {
		voiceCfg.RegisterExpiry = i.registerExpiry
	}
	imsTemplate := resolveIMSRegisterTemplate(i.imsMCC, i.imsMNC)
	voiceCfg.RegisterProfile.UserAgent = resolveIMSUserAgent(imsTemplate, voiceCfg.RegisterProfile.UserAgent)
	presetID := ""
	if req.Prepared != nil {
		presetID = strings.TrimSpace(req.Prepared.EffectiveCarrier.PresetID)
	}
	coreCfg := imscore.IMSConfigFromVoice(voiceCfg, imsTemplate, presetID)
	network, err := imscore.NewUserspaceIMSNetwork(localIP, dataplane)
	if err != nil {
		i.failStageForGeneration(ctx, generation, "ims", fmt.Sprintf("IMS network setup failed: %v", err), formatStageFailureReason("ims_network_failed", err))
		if cancel := i.currentSWUCancel(generation); cancel != nil {
			cancel()
		}
		return
	}
	svc, err := imscore.StartSessionIMSCore(pipelineCtx, coreCfg, network, imscore.StartSessionInput{
		TraceID:               i.traceID,
		LocalIP:               localIP,
		Dataplane:             dataplane,
		RegistrarCandidates:   pcscfCandidates,
		AKA:                   i.akaProvider,
		DeliveryStore:         i.deliveryStore,
		IMSI:                  i.imsIMSI,
		SMSC:                  strings.TrimSpace(req.Profile.SMSC),
		MCC:                   i.imsMCC,
		MNC:                   i.imsMNC,
		CellID:                i.imsCellID,
		RegisterExpirySeconds: int(i.registerExpiry / time.Second),
	})
	if err != nil {
		i.failStageForGeneration(ctx, generation, "ims", fmt.Sprintf("IMS dial failed: %v", err), formatStageFailureReason("ims_dial_failed", err))
		if cancel := i.currentSWUCancel(generation); cancel != nil {
			cancel()
		}
		return
	}

	winningPCSCF := pcscfAddr
	if status := svc.Status(); status != nil {
		if v, ok := status["registrar"].(string); ok && strings.TrimSpace(v) != "" {
			winningPCSCF = strings.TrimSpace(v)
		}
	}
	if !i.installService(ctx, generation, svc, svc.Status, localIP.String(), winningPCSCF) {
		return
	}

	if !i.updateStateForGeneration(generation, func(s *State) {
		s.IMSReady = true
		s.SMSReady = true
		s.LastReason = fmt.Sprintf("ims_ready pcscf=%s", winningPCSCF)
		s.UpdatedAt = time.Now()
	}) {
		return
	}
	i.notifyObserversForGeneration(ctx, generation)
}

func resolveEPDGHost(req StartRequest) (string, string) {
	port := "500"
	if req.Prepared != nil && strings.TrimSpace(req.Prepared.EPDGAddr) != "" {
		addr := strings.TrimSpace(req.Prepared.EPDGAddr)
		if host, p, err := net.SplitHostPort(addr); err == nil {
			return host, p
		}
		if net.ParseIP(addr) != nil {
			return addr, port
		}
		return addr, port
	}

	mcc := strings.TrimSpace(req.Profile.MCC)
	mnc := strings.TrimSpace(req.Profile.MNC)
	if mcc == "" || mnc == "" {
		return "", ""
	}
	if len(mnc) < 3 {
		mnc = strings.Repeat("0", 3-len(mnc)) + mnc
	}
	if host := simAdminEPDGHost(mcc, mnc); host != "" {
		return host, port
	}
	return fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", mnc, mcc), port
}

func simAdminEPDGHost(mcc, mnc string) string {
	key := simAdminProfileKeyForPLMN(mcc, mnc)
	switch key {
	case "234-33":
		return "epdg.epc.mnc033.mcc001.pub.3gppnetwork.org"
	case "204-04":
		return "epdg.epc.mnc004.mcc204.pub.3gppnetwork.org"
	case "310-260":
		return "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org"
	case "310-410":
		return "epdg.epc.att.net"
	case "262-07":
		return "epdg.epc.mnc007.mcc262.pub.3gppnetwork.org"
	case "530-05":
		return "epdg.epc.mnc005.mcc530.pub.3gppnetwork.spark.co.nz"
	default:
		return ""
	}
}

func resolveIMSDomain(prepared *identity.PreparedSession) string {
	if prepared == nil {
		return ""
	}
	return strings.TrimSpace(prepared.IMSRealm())
}

// resolveIMSRegisterIdentities chooses IMS Digest IMPI/IMPU.
// Default (and all imsi_* shapes) use IMSI@home-domain per 3GPP 24.229.
// Only an explicit private_id keeps the SWu EAP-AKA NAI as Digest username.
func resolveIMSRegisterIdentities(eapIdentity, imsi string, prepared *identity.PreparedSession, registerProfile voiceclient.RegisterProfile) (privateID, publicURI string) {
	privateID = strings.TrimSpace(eapIdentity)
	publicURI = resolveIMSPublicURI(prepared, imsi)
	shape := strings.TrimSpace(registerProfile.AuthorizationIdentity)
	if shape == "" || voiceclient.UsesIMSIHomeDomainIdentity(registerProfile) {
		if shape == "" {
			shape = "imsi_home_domain"
		}
		realm := ""
		domain := resolveIMSDomain(prepared)
		if prepared != nil {
			realm = strings.TrimSpace(prepared.IMSRealm())
		}
		if builtPrivate, builtPublic := voiceclient.BuildIMSIdentity(imsi, realm, domain, shape); builtPrivate != "" {
			privateID = builtPrivate
			if builtPublic != "" {
				publicURI = builtPublic
			}
		}
	}
	return privateID, publicURI
}

func resolveIMSRegisterTemplate(mcc, mnc string) policy.IMSRegisterTemplate {
	return policy.ResolveIMSRegisterTemplate(mcc, mnc)
}

func resolveIMSUserAgent(template policy.IMSRegisterTemplate, fallback string) string {
	if userAgent := strings.TrimSpace(template.UserAgent); userAgent != "" {
		return userAgent
	}
	if fallback = strings.TrimSpace(fallback); fallback != "" {
		return fallback
	}
	return "SimAdmin VoWiFi"
}

func resolveIMSPublicURI(prepared *identity.PreparedSession, fallbackIMSI string) string {
	if prepared != nil {
		if impu := strings.TrimSpace(prepared.IMSIdentity.IMPU); impu != "" {
			return impu
		}
		domain := strings.TrimSpace(prepared.IMSRealm())
		if domain != "" {
			imsi := strings.TrimSpace(fallbackIMSI)
			if imsi == "" {
				imsi = strings.TrimSpace(prepared.Profile.IMSI)
			}
			if imsi != "" {
				return "sip:" + imsi + "@" + domain
			}
		}
	}
	imsi := strings.TrimSpace(fallbackIMSI)
	if imsi == "" {
		return ""
	}
	return "sip:" + imsi
}

func simAdminProfileKeyForPLMN(mcc, mnc string) string {
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimSpace(mnc)
	if len(mnc) > 2 {
		mnc = strings.TrimLeft(mnc, "0")
	}
	if mnc == "" {
		mnc = "0"
	}
	if len(mnc) == 1 {
		mnc = "0" + mnc
	}
	return fmt.Sprintf("%s-%s", mcc, mnc)
}

func classifyTunnelFailure(err error) string {
	if err == nil {
		return "tunnel_swu_failed"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "last_snapshot=established=true") && (strings.Contains(msg, "ipv4=") || strings.Contains(msg, "ipv6=")):
		return "tunnel_ready_incomplete"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "timed out") || strings.Contains(msg, "window"):
		return "tunnel_ike_timeout"
	case strings.Contains(msg, "eap") || strings.Contains(msg, "aka") || strings.Contains(msg, "authentication") || strings.Contains(msg, "auth"):
		return "tunnel_auth_failed"
	case strings.Contains(msg, "bind socket") || strings.Contains(msg, "socket") || strings.Contains(msg, "network") || strings.Contains(msg, "unreachable"):
		return "tunnel_network_failed"
	case strings.Contains(msg, "child sa") || strings.Contains(msg, "child_sa"):
		return "tunnel_child_sa_failed"
	case strings.Contains(msg, "xfrm") ||
		strings.Contains(msg, "udp_encap") ||
		strings.Contains(msg, "dataplane") ||
		strings.Contains(msg, "cap_net_admin") ||
		strings.Contains(msg, "permission denied") && (strings.Contains(msg, "addr add") || strings.Contains(msg, "route add") || strings.Contains(msg, "link set")) ||
		strings.Contains(msg, "newtundevice") ||
		strings.Contains(msg, "new tun") ||
		strings.Contains(msg, "tun device") ||
		strings.Contains(msg, "tuntap") ||
		strings.Contains(msg, "/dev/net/tun") ||
		strings.Contains(msg, "setlinkup") ||
		strings.Contains(msg, "addaddress") ||
		strings.Contains(msg, "addroute"):
		return "tunnel_dataplane_failed"
	default:
		return "tunnel_swu_failed"
	}
}

func formatTunnelFailureReason(reason string, err error) string {
	return formatStageFailureReason(reason, err)
}

func formatStageFailureReason(reason string, err error) string {
	if err == nil {
		return reason
	}
	detail := strings.TrimSpace(err.Error())
	if detail == "" {
		return reason
	}
	const maxDetail = 240
	if len(detail) > maxDetail {
		detail = detail[:maxDetail] + "..."
	}
	return fmt.Sprintf("%s: %s", reason, detail)
}

type isimAKAAdapter struct {
	swusim.ISIMAKAProvider
}

func (a isimAKAAdapter) CalculateAKA(rand16, autn16 []byte) (swusim.AKAResult, error) {
	return a.ISIMAKAProvider.CalculateISIMAKA(rand16, autn16)
}

func buildRoutePolicy(proxy *ProxyConfig) transport.RoutePolicy {
	if proxy == nil || !proxy.Enabled {
		return transport.DefaultRoutePolicy()
	}

	addr := strings.TrimSpace(proxy.Addr)
	if addr == "" {
		host := strings.TrimSpace(proxy.Host)
		if host == "" {
			host = strings.TrimSpace(proxy.Address)
		}
		if host != "" && proxy.Port > 0 {
			addr = net.JoinHostPort(host, fmt.Sprintf("%d", proxy.Port))
		}
	}
	if addr == "" {
		return transport.DefaultRoutePolicy()
	}

	return transport.RoutePolicy{
		Kind:     transport.ProxySocks5UDPAssociate,
		Addr:     addr,
		Username: proxy.Username,
		Password: proxy.Password,
	}
}

func NewModemAccessAdapter(m Modem) ModemAccess {
	if m == nil {
		return nil
	}
	return &modemAccessAdapter{modem: m}
}

func NewReaderSIMAdapter(provider interface{}) SIMAdapter {
	return NewReaderSIMAdapterWithIMSI(provider, "")
}

func NewReaderSIMAdapterWithIMSI(provider interface{}, imsi string) SIMAdapter {
	if provider == nil {
		return nil
	}
	if simProvider, ok := provider.(SIMAdapter); ok {
		imsi = strings.TrimSpace(imsi)
		if imsi != "" {
			if liveIMSI, err := simProvider.GetIMSI(); err != nil || strings.TrimSpace(liveIMSI) == "" {
				if p, ok := simProvider.(swusim.AKAProvider); ok {
					return &providerOnlyAdapter{provider: p, imsi: imsi}
				}
			}
		}
		return simProvider
	}
	if _, ok := provider.(swusim.AKAProvider); ok {
		return &providerOnlyAdapter{provider: provider, imsi: strings.TrimSpace(imsi)}
	}
	return nil
}

type traceIDContextKey struct{}

func NewTraceID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("vowifi-%d", time.Now().UnixNano())
	}
	return "vowifi-" + hex.EncodeToString(b[:])
}

func WithTraceID(ctx context.Context, traceID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	traceID = strings.TrimSpace(traceID)
	if traceID == "" {
		traceID = NewTraceID()
	}
	return context.WithValue(ctx, traceIDContextKey{}, traceID)
}

func SetLogger(l interface{}) {
	log, ok := l.(*zap.Logger)
	if !ok || log == nil {
		return
	}
	swulogger.SetLogger(log)
}
