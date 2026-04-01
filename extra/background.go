// this file provide api for launching and stopping client

package extra

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rep1ace/wssocks/client"
	"github.com/rep1ace/wssocks/wss"
	"github.com/rep1ace/wssocks/wss/term_view"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/ver"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn/passwd"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/sync/errgroup"
	"nhooyr.io/websocket"
)

const (
	heartbeatInterval = 15 * time.Second
	heartbeatTimeout  = 10 * time.Second
	backoffBase       = 2 * time.Second
	backoffMax        = 30 * time.Second
)

type ConnectionState string

const (
	StateIdle           ConnectionState = "idle"
	StateAuthenticating ConnectionState = "authenticating"
	StateConnecting     ConnectionState = "connecting"
	StateConnected      ConnectionState = "connected"
	StateDegraded       ConnectionState = "degraded"
	StateReconnecting   ConnectionState = "reconnecting"
	StateStopped        ConnectionState = "stopped"
)

type failureClass string

const (
	failureVPNExpired   failureClass = "vpn auth/session expired"
	failureTransient    failureClass = "transient network/websocket timeout"
	failureServerClosed failureClass = "server rejected/closed"
	failureLocalStop    failureClass = "local shutdown"
	failureFatalConfig  failureClass = "fatal configuration/authentication error"
)

type Options struct {
	client.Options
	vpn.UstbVpn
	RemoteAddr string
	AuthToken  string
}

type TaskHandles struct {
	mu sync.RWMutex

	options    Options
	cancel     context.CancelFunc
	eg         *errgroup.Group
	running    bool
	state      ConnectionState
	stateCause string

	record *wss.ConnRecord

	socksClient *wss.Client
	httpServer  *http.Server

	socksProvider *wss.SwappableWebSocketClientProvider
	httpProvider  *wss.SwappableWebSocketClientProvider

	socksTunnel *managedTunnel
	httpTunnel  *managedTunnel

	vpnPlugin *vpn.UstbVpn
}

type managedTunnel struct {
	name         string
	wsc          *wss.WebSocketClient
	hb           *wss.HeartBeat
	cancel       context.CancelFunc
	ctx          context.Context
	eg           *errgroup.Group
	stopWatching func()
}

type reconnectBackoff struct {
	attempt int
	rand    *rand.Rand
}

func (h *TaskHandles) NotifyCloseWrapper() {
	h.Stop()
}

func (h *TaskHandles) Stop() {
	h.mu.RLock()
	cancel := h.cancel
	httpServer := h.httpServer
	socksTunnel := h.socksTunnel
	httpTunnel := h.httpTunnel
	h.mu.RUnlock()

	h.setState(StateStopped, "manual stop")
	if cancel != nil {
		cancel()
	}
	if socksTunnel != nil {
		socksTunnel.Close()
	}
	if httpTunnel != nil {
		httpTunnel.Close()
	}
	if httpServer != nil {
		_ = httpServer.Shutdown(context.Background())
	}
}

func (h *TaskHandles) Wait() error {
	h.mu.RLock()
	eg := h.eg
	h.mu.RUnlock()
	if eg == nil {
		return nil
	}

	err := eg.Wait()
	if errors.Is(err, context.Canceled) || errors.Is(err, wss.StoppedError) || errors.Is(err, http.ErrServerClosed) {
		err = nil
	}

	h.mu.Lock()
	h.running = false
	h.socksTunnel = nil
	h.httpTunnel = nil
	h.mu.Unlock()

	if err == nil {
		h.setState(StateStopped, "")
	}
	return err
}

func (h *TaskHandles) CurrentState() (string, string) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return string(h.state), h.stateCause
}

var vpnPlugin *vpn.UstbVpn

func loadPlugins(v vpn.UstbVpn) (*vpn.UstbVpn, error) {
	if vpnPlugin == nil {
		vpnPlugin = &v
		vpnPlugin.ApplyConfig(v)
		// vpn.UstbVpn has implementations of both option plugin and request plugin
		if err := client.AddPluginOption(vpnPlugin); err != nil {
			return nil, err
		}
		if err := client.AddPluginRequest(vpnPlugin); err != nil {
			return nil, err
		}
		if err := client.AddPluginVersion(&ver.PluginVersionNeg{}); err != nil {
			return nil, err
		}
	} else {
		vpnPlugin.ApplyConfig(v)
	}
	return vpnPlugin, nil
}

func (h *TaskHandles) StartWssocks(options Options) error {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return errors.New("client already running")
	}
	h.mu.Unlock()

	pluginRef, err := loadPlugins(options.UstbVpn)
	if err != nil {
		return err
	}

	if options.RemoteAddr == "" {
		return errors.New("empty remote address")
	}

	remoteURL, err := url.Parse(options.RemoteAddr)
	if err != nil {
		return err
	}

	options.RemoteUrl = remoteURL
	headers := make(http.Header)
	for key, values := range options.RemoteHeaders {
		copied := make([]string, len(values))
		copy(copied, values)
		headers[key] = copied
	}
	options.RemoteHeaders = headers
	if options.AuthToken != "" {
		options.RemoteHeaders.Set("Key", options.AuthToken)
	}

	ctx, cancel := context.WithCancel(context.Background())
	eg, egCtx := errgroup.WithContext(ctx)

	record := h.newConnRecord()
	socksProvider := wss.NewSwappableWebSocketClientProvider()
	httpProvider := wss.NewSwappableWebSocketClientProvider()
	socksClient := wss.NewClient()

	h.mu.Lock()
	h.options = options
	h.cancel = cancel
	h.eg = eg
	h.record = record
	h.socksProvider = socksProvider
	h.httpProvider = httpProvider
	h.socksClient = socksClient
	h.httpServer = nil
	h.socksTunnel = nil
	h.httpTunnel = nil
	h.vpnPlugin = pluginRef
	h.running = true
	h.state = StateIdle
	h.stateCause = ""
	h.mu.Unlock()

	if options.HttpEnabled {
		handle := wss.NewHttpProxy(httpProvider, record)
		httpServer := &http.Server{Addr: options.LocalHttpAddr, Handler: &handle}
		h.mu.Lock()
		h.httpServer = httpServer
		h.mu.Unlock()
		eg.Go(func() error {
			return h.runHTTPListener(egCtx, httpServer, options.LocalHttpAddr)
		})
	}

	eg.Go(func() error {
		return h.runSocksListener(egCtx, socksClient, socksProvider, record, options)
	})
	eg.Go(func() error {
		return h.supervise(egCtx)
	})
	return nil
}

func (h *TaskHandles) runHTTPListener(ctx context.Context, httpServer *http.Server, address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("http listener failed: %w", err)
	}

	stopWatching := watchContextDone(ctx, func() {
		_ = listener.Close()
	})
	defer stopWatching()

	log.WithField("http listen address", address).
		Info("listening on local address for incoming proxy requests.")

	if ctx.Err() != nil {
		_ = listener.Close()
	}

	err = httpServer.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
		return nil
	}
	return fmt.Errorf("http listener failed: %w", err)
}

func (h *TaskHandles) runSocksListener(ctx context.Context, socksClient *wss.Client, provider *wss.SwappableWebSocketClientProvider, record *wss.ConnRecord, options Options) error {
	started := make(chan struct{})
	errCh := make(chan error, 1)

	go func() {
		errCh <- socksClient.ListenAndServe(record, provider, options.LocalSocks5Addr, options.HttpEnabled, func() {
			if options.HttpEnabled {
				log.WithField("socks5 listen address", options.LocalSocks5Addr).
					WithField("https listen address", options.LocalSocks5Addr).
					Info("listening on local address for incoming proxy requests.")
			} else {
				log.WithField("socks5 listen address", options.LocalSocks5Addr).
					Info("listening on local address for incoming proxy requests.")
			}
			close(started)
		})
	}()

	select {
	case err := <-errCh:
		if ctx.Err() != nil {
			return nil
		}
		return err
	case <-started:
	case <-ctx.Done():
		select {
		case err := <-errCh:
			if ctx.Err() != nil {
				return nil
			}
			return err
		case <-started:
		}
	}

	stopWatching := watchContextDone(ctx, func() {
		h.closeSocksClient(socksClient)
	})
	defer stopWatching()

	if ctx.Err() != nil {
		h.closeSocksClient(socksClient)
	}

	err := <-errCh
	if errors.Is(err, wss.StoppedError) || errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

func (h *TaskHandles) closeSocksClient(target *wss.Client) {
	if target == nil {
		return
	}

	h.mu.Lock()
	if h.socksClient != target {
		h.mu.Unlock()
		return
	}
	h.socksClient = nil
	h.mu.Unlock()

	_ = target.Close(false)
}

func watchContextDone(ctx context.Context, fn func()) func() {
	done := make(chan struct{})
	var stopOnce sync.Once
	go func() {
		select {
		case <-ctx.Done():
			fn()
		case <-done:
		}
	}()
	return func() {
		stopOnce.Do(func() {
			close(done)
		})
	}
}

type vpnSessionInvalidator interface {
	InvalidateSession()
}

func invalidateVPNSessionOnFailure(enabled bool, invalidator vpnSessionInvalidator, class failureClass) {
	if !enabled || invalidator == nil || class != failureVPNExpired {
		return
	}
	invalidator.InvalidateSession()
}

func (h *TaskHandles) supervise(ctx context.Context) error {
	backoff := newReconnectBackoff()
	for {
		if ctx.Err() != nil {
			return nil
		}

		if h.vpnPlugin != nil && h.vpnPlugin.Enable {
			h.setState(StateAuthenticating, "")
		}
		h.setState(StateConnecting, "")

		socksTunnel, httpTunnel, err := h.connectAllTunnels(ctx)
		if err != nil {
			class := classifyFailure(err)
			invalidateVPNSessionOnFailure(h.vpnPlugin != nil && h.vpnPlugin.Enable, h.vpnPlugin, class)
			if class == failureFatalConfig {
				h.setState(StateStopped, err.Error())
				return err
			}
			if class == failureLocalStop || ctx.Err() != nil {
				return nil
			}
			h.setState(StateReconnecting, fmt.Sprintf("%s: %v", class, err))
			if err := waitForBackoff(ctx, backoff.Next()); err != nil {
				return nil
			}
			continue
		}

		backoff.Reset()
		h.setActiveTunnels(socksTunnel, httpTunnel)
		h.setState(StateConnected, "")

		err = h.waitForActiveFailure(ctx, socksTunnel, httpTunnel)
		h.clearActiveTunnels()
		socksTunnel.Close()
		if httpTunnel != nil {
			httpTunnel.Close()
		}

		if ctx.Err() != nil {
			return nil
		}

		class := classifyFailure(err)
		invalidateVPNSessionOnFailure(h.vpnPlugin != nil && h.vpnPlugin.Enable, h.vpnPlugin, class)
		if class == failureFatalConfig {
			h.setState(StateStopped, err.Error())
			return err
		}
		if class == failureLocalStop {
			return nil
		}

		h.setState(StateDegraded, fmt.Sprintf("%s: %v", class, err))
		if err := waitForBackoff(ctx, backoff.Next()); err != nil {
			return nil
		}
		h.setState(StateReconnecting, fmt.Sprintf("%s: %v", class, err))
	}
}

func (h *TaskHandles) connectAllTunnels(ctx context.Context) (*managedTunnel, *managedTunnel, error) {
	socksTunnel, err := h.connectTunnel(ctx, "socks")
	if err != nil {
		return nil, nil, err
	}

	var httpTunnel *managedTunnel
	if h.options.HttpEnabled {
		httpTunnel, err = h.connectTunnel(ctx, "http")
		if err != nil {
			socksTunnel.Close()
			return nil, nil, err
		}
	}

	return socksTunnel, httpTunnel, nil
}

func (h *TaskHandles) connectTunnel(ctx context.Context, tunnelName string) (*managedTunnel, error) {
	hdl := client.NewClientHandles()
	connectOptions := cloneClientOptions(h.options)

	connectCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	wsc, err := hdl.CreateServerConn(&connectOptions, connectCtx)
	if err != nil {
		if h.vpnPlugin != nil {
			err = h.vpnPlugin.NormalizeDialFailure(err)
		}
		return nil, fmt.Errorf("%s tunnel connect failed: %w", tunnelName, err)
	}
	if err := hdl.NegotiateVersion(connectCtx, h.options.RemoteAddr); err != nil {
		_ = wsc.Close()
		return nil, fmt.Errorf("%s tunnel version negotiation failed: %w", tunnelName, err)
	}

	return newManagedTunnel(ctx, tunnelName, wsc), nil
}

func newManagedTunnel(parent context.Context, name string, wsc *wss.WebSocketClient) *managedTunnel {
	return newManagedTunnelWithHeartbeat(parent, name, wsc, heartbeatInterval, heartbeatTimeout)
}

func newManagedTunnelWithHeartbeat(parent context.Context, name string, wsc *wss.WebSocketClient, interval, timeout time.Duration) *managedTunnel {
	ctx, cancel := context.WithCancel(parent)
	eg, egCtx := errgroup.WithContext(ctx)
	hb, _ := wss.NewHeartBeat(wsc)

	tunnel := &managedTunnel{
		name:         name,
		wsc:          wsc,
		hb:           hb,
		cancel:       cancel,
		ctx:          ctx,
		eg:           eg,
		stopWatching: watchContextDone(egCtx, func() { _ = wsc.Close() }),
	}

	eg.Go(func() error {
		if err := wsc.ListenIncomeMsg(1 << 29); err != nil {
			if egCtx.Err() != nil {
				return nil
			}
			return fmt.Errorf("%s tunnel read failed: %w", name, err)
		}
		if egCtx.Err() == nil {
			return fmt.Errorf("%s tunnel closed unexpectedly", name)
		}
		return nil
	})
	eg.Go(func() error {
		if err := hb.StartWithInterval(egCtx, interval, timeout); err != nil && egCtx.Err() == nil {
			return fmt.Errorf("%s tunnel health check failed: %w", name, err)
		}
		return nil
	})
	return tunnel
}

func (t *managedTunnel) Close() {
	if t == nil {
		return
	}
	if t.stopWatching != nil {
		t.stopWatching()
	}
	if t.hb != nil {
		t.hb.Close()
	}
	if t.cancel != nil {
		t.cancel()
	}
	if t.wsc != nil {
		_ = t.wsc.Close()
	}
}

func (t *managedTunnel) waitAsync(ch chan<- error) {
	err := t.eg.Wait()
	if t.stopWatching != nil {
		t.stopWatching()
	}
	if err == nil && t.ctx.Err() == nil {
		err = fmt.Errorf("%s tunnel stopped", t.name)
	}
	ch <- err
}

func (h *TaskHandles) waitForActiveFailure(ctx context.Context, socksTunnel, httpTunnel *managedTunnel) error {
	errCh := make(chan error, 3)
	go socksTunnel.waitAsync(errCh)
	if httpTunnel != nil {
		go httpTunnel.waitAsync(errCh)
	}

	maintainCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if h.vpnPlugin != nil && h.vpnPlugin.Enable {
		go func() {
			errCh <- h.vpnPlugin.MaintainSession(maintainCtx)
		}()
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (h *TaskHandles) setActiveTunnels(socksTunnel, httpTunnel *managedTunnel) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.socksTunnel = socksTunnel
	h.httpTunnel = httpTunnel
	if h.socksProvider != nil {
		h.socksProvider.Set(socksTunnel.wsc)
	}
	if h.httpProvider != nil {
		if httpTunnel != nil {
			h.httpProvider.Set(httpTunnel.wsc)
		} else {
			h.httpProvider.Set(nil)
		}
	}
}

func (h *TaskHandles) clearActiveTunnels() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.socksTunnel = nil
	h.httpTunnel = nil
	if h.socksProvider != nil {
		h.socksProvider.Set(nil)
	}
	if h.httpProvider != nil {
		h.httpProvider.Set(nil)
	}
}

func (h *TaskHandles) setState(state ConnectionState, cause string) {
	h.mu.Lock()
	changed := h.state != state || h.stateCause != cause
	h.state = state
	h.stateCause = cause
	h.mu.Unlock()
	if !changed {
		return
	}

	entry := log.WithField("state", state)
	if cause != "" {
		entry = entry.WithField("reason", cause)
	}
	entry.Info("connection manager state updated")
}

func (h *TaskHandles) newConnRecord() *wss.ConnRecord {
	record := wss.NewConnRecord()
	if terminal.IsTerminal(int(os.Stdout.Fd())) {
		plog := term_view.NewPLog(record)
		log.SetOutput(plog)
		record.OnChange = func(wss.ConnStatus) {
			plog.SetLogBuffer(record)
			plog.Writer.Flush(nil)
		}
		return record
	}

	record.OnChange = func(status wss.ConnStatus) {
		if status.IsNew {
			log.WithField("address", status.Address).Traceln("new proxy connection")
			return
		}
		log.WithField("address", status.Address).Traceln("close proxy connection")
	}
	return record
}

func cloneClientOptions(options Options) client.Options {
	cloned := options.Options
	if options.RemoteUrl != nil {
		remoteCopy := *options.RemoteUrl
		cloned.RemoteUrl = &remoteCopy
	}

	cloned.RemoteHeaders = make(http.Header)
	for key, values := range options.RemoteHeaders {
		copied := make([]string, len(values))
		copy(copied, values)
		cloned.RemoteHeaders[key] = copied
	}
	return cloned
}

func classifyFailure(err error) failureClass {
	if err == nil {
		return failureTransient
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, wss.StoppedError) || errors.Is(err, http.ErrServerClosed) {
		return failureLocalStop
	}
	if errors.Is(err, passwd.ErrAuthFailed) || errors.Is(err, vpn.ErrSessionExpired) {
		return failureVPNExpired
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return failureTransient
	}
	var handshakeErr *wss.HandshakeError
	if errors.As(err, &handshakeErr) {
		switch handshakeErr.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return failureFatalConfig
		default:
			if strings.Contains(strings.ToLower(handshakeErr.FinalPath), "login") {
				return failureFatalConfig
			}
			return failureServerClosed
		}
	}
	if status := websocket.CloseStatus(err); status != -1 {
		switch status {
		case websocket.StatusNormalClosure, websocket.StatusGoingAway:
			return failureServerClosed
		default:
			return failureTransient
		}
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return failureTransient
		}
	}

	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "status 401"),
		strings.Contains(message, "status 403"),
		strings.Contains(message, "status 404"),
		strings.Contains(message, "incompatible protocol version"),
		strings.Contains(message, "empty remote address"),
		strings.Contains(message, "bad http header"),
		strings.Contains(message, "x509"):
		return failureFatalConfig
	case strings.Contains(message, "expired"),
		strings.Contains(message, "captcha"),
		strings.Contains(message, "登录失败"):
		return failureVPNExpired
	case strings.Contains(message, "timeout"),
		strings.Contains(message, "connection reset"),
		strings.Contains(message, "broken pipe"),
		strings.Contains(message, "network is unreachable"),
		strings.Contains(message, "connection refused"),
		strings.Contains(message, "temporary"):
		return failureTransient
	default:
		return failureServerClosed
	}
}

func newReconnectBackoff() *reconnectBackoff {
	return &reconnectBackoff{
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (b *reconnectBackoff) Reset() {
	b.attempt = 0
}

func (b *reconnectBackoff) Next() time.Duration {
	delay := backoffBase << b.attempt
	if delay > backoffMax {
		delay = backoffMax
	} else {
		b.attempt++
	}
	jitter := time.Duration(b.rand.Int63n(int64(delay / 2)))
	return delay + jitter
}

func waitForBackoff(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
