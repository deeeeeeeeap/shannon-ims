package imscore

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/1239t/swu-go/pkg/logger"

	"github.com/1239t/vowifi-go/internal/vowifi/ipsec3gpp"
	"github.com/1239t/vowifi-go/runtimehost/voiceclient"
)

type sipWriteTask struct {
	payload []byte
	done    chan error
}

type transportRuntime struct {
	cfg       Config
	policy    ipsec3gpp.Policy
	transport *ipsec3gpp.Transport

	portSListener *singleConnListener
	tcpWriteCh    chan sipWriteTask

	portCConn *ipsec3gpp.SecureChannelConn

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func startTransportRuntime(parent context.Context, cfg Config, swu voiceclient.SWUTCPDialer, policy ipsec3gpp.Policy, transport *ipsec3gpp.Transport, portCConn *ipsec3gpp.SecureChannelConn) (*transportRuntime, error) {
	if portCConn == nil || transport == nil {
		return nil, fmt.Errorf("imscore: transport runtime requires secure port-c connection")
	}
	if swu == nil {
		return nil, fmt.Errorf("imscore: transport runtime requires SWu dialer")
	}
	if policy.LocalPortS <= 0 {
		return nil, fmt.Errorf("imscore: transport runtime missing port-s")
	}

	ctx, cancel := context.WithCancel(parent)
	rt := &transportRuntime{
		cfg:       cfg,
		policy:    policy,
		transport: transport,
		portCConn: portCConn,
		tcpWriteCh: make(chan sipWriteTask, 8),
		cancel:    cancel,
	}
	rt.portSListener = newSingleConnListener(&net.TCPAddr{
		IP:   cfg.LocalIP,
		Port: policy.LocalPortS,
	})

	rt.wg.Add(1)
	go rt.runTCPWriteChannel(ctx)

	rt.wg.Add(1)
	go rt.runPortSListener(ctx, swu)

	logger.Info("IMS transport runtime started",
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(cfg.DeviceID)),
		logger.Int("port_c", policy.LocalPortC),
		logger.Int("port_s", policy.LocalPortS),
		logger.String("registrar", cfg.PCSCFAddr),
		logger.String("transport_target", effectiveTransportAddr(cfg)))
	return rt, nil
}

func (rt *transportRuntime) Close() {
	if rt == nil {
		return
	}
	if rt.cancel != nil {
		rt.cancel()
	}
	if rt.portSListener != nil {
		_ = rt.portSListener.Close()
	}
	if rt.portCConn != nil {
		_ = rt.portCConn.Close()
	}
	rt.wg.Wait()
}

func (rt *transportRuntime) runTCPWriteChannel(ctx context.Context) {
	defer rt.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case task := <-rt.tcpWriteCh:
			_, err := rt.portCConn.Write(task.payload)
			if task.done != nil {
				task.done <- err
				close(task.done)
			}
			if err != nil {
				logger.Warn("IMS port-c write failed",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
					logger.String("error", err.Error()))
			}
		}
	}
}

func (rt *transportRuntime) enqueueWrite(payload []byte) error {
	if rt == nil || rt.tcpWriteCh == nil {
		return fmt.Errorf("imscore: tcp write channel unavailable")
	}
	done := make(chan error, 1)
	rt.tcpWriteCh <- sipWriteTask{payload: append([]byte(nil), payload...), done: done}
	return <-done
}

func (rt *transportRuntime) runPortSListener(ctx context.Context, swu voiceclient.SWUTCPDialer) {
	defer rt.wg.Done()
	listener, err := swu.ListenContextTCP(ctx, rt.cfg.LocalIP, rt.policy.LocalPortS)
	if err != nil {
		logger.Warn("IMS port-s listen failed",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.Int("port_s", rt.policy.LocalPortS),
			logger.String("error", err.Error()))
		return
	}
	defer listener.Close()

	logger.Info(fmt.Sprintf("[%s] 准备启动 IMS TCP 入站监听", strings.TrimSpace(rt.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
		logger.Int("port", rt.policy.LocalPortS))

	for {
		rawConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				logger.Warn("IMS port-s accept failed",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
					logger.String("error", err.Error()))
				return
			}
		}
		secure := ipsec3gpp.WrapSecureChannel(rawConn, rt.transport, rt.policy)
		logger.Info("IMS port-s accepted inbound push",
			logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
			logger.String("remote", rawConn.RemoteAddr().String()),
			logger.String("local", rawConn.LocalAddr().String()))
		rt.portSListener.deliver(secure)
		rt.wg.Add(1)
		go rt.drainInboundPortS(ctx, secure)
	}
}

func (rt *transportRuntime) drainInboundPortS(ctx context.Context, conn *ipsec3gpp.SecureChannelConn) {
	defer rt.wg.Done()
	defer conn.Close()
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				logger.Warn("IMS port-s read ended",
					logger.String("trace_id", strings.TrimSpace(rt.cfg.TraceID)),
					logger.String("error", err.Error()))
			}
			return
		}
		if n == 0 {
			continue
		}
		installSIPTrace(rt.cfg.TraceID, rt.cfg.DeviceID)
		sipTraceLogger{traceID: rt.cfg.TraceID, deviceID: rt.cfg.DeviceID}.
			SIPTraceRead("tcp", conn.LocalAddr().String(), conn.RemoteAddr().String(), buf[:n])
	}
}
