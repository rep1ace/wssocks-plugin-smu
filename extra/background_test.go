package extra

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rep1ace/wssocks/client"
	"github.com/rep1ace/wssocks/wss"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn/passwd"
	"golang.org/x/sync/errgroup"
	"nhooyr.io/websocket"
)

type fakeSessionInvalidator struct {
	calls int
}

func (f *fakeSessionInvalidator) InvalidateSession() {
	f.calls++
}

func TestClassifyFailure(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		class failureClass
	}{
		{name: "local stop", err: context.Canceled, class: failureLocalStop},
		{name: "vpn auth", err: passwd.ErrAuthFailed, class: failureVPNExpired},
		{name: "session expired", err: vpn.ErrSessionExpired, class: failureVPNExpired},
		{
			name: "fatal handshake status",
			err: &wss.HandshakeError{
				StatusCode: http.StatusUnauthorized,
				Err:        errors.New("bad handshake"),
			},
			class: failureFatalConfig,
		},
		{
			name: "fatal handshake login redirect",
			err: &wss.HandshakeError{
				StatusCode: http.StatusOK,
				FinalPath:  "/login",
				Err:        errors.New("bad handshake"),
			},
			class: failureFatalConfig,
		},
		{name: "transient", err: errors.New("connection reset by peer"), class: failureTransient},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyFailure(tt.err); got != tt.class {
				t.Fatalf("classifyFailure(%v) = %s, want %s", tt.err, got, tt.class)
			}
		})
	}
}

func TestWaitForBackoffHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := waitForBackoff(ctx, 50*time.Millisecond); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestErrgroupCancellationClosesLocalListeners(t *testing.T) {
	fatalErr := errors.New("fatal startup failure")
	h := &TaskHandles{}
	socksClient := wss.NewClient()
	h.socksClient = socksClient

	eg, egCtx := errgroup.WithContext(context.Background())
	eg.Go(func() error {
		return h.runSocksListener(egCtx, socksClient, wss.NewSwappableWebSocketClientProvider(), wss.NewConnRecord(), Options{
			Options: client.Options{
				LocalSocks5Addr: "127.0.0.1:0",
			},
		})
	})
	eg.Go(func() error {
		return h.runHTTPListener(egCtx, &http.Server{Handler: http.NewServeMux()}, "127.0.0.1:0")
	})
	eg.Go(func() error {
		return fatalErr
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- eg.Wait()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, fatalErr) {
			t.Fatalf("eg.Wait() = %v, want %v", err, fatalErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("eg.Wait() did not return after errgroup cancellation")
	}
}

func TestInvalidateVPNSessionOnFailure(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		class   failureClass
		want    int
	}{
		{name: "disabled", enabled: false, class: failureVPNExpired, want: 0},
		{name: "transient failure", enabled: true, class: failureTransient, want: 0},
		{name: "expired session", enabled: true, class: failureVPNExpired, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalidator := &fakeSessionInvalidator{}
			invalidateVPNSessionOnFailure(tt.enabled, invalidator, tt.class)
			if invalidator.calls != tt.want {
				t.Fatalf("invalidateVPNSessionOnFailure() invalidated %d times, want %d", invalidator.calls, tt.want)
			}
		})
	}

	invalidateVPNSessionOnFailure(true, nil, failureVPNExpired)
}

func TestManagedTunnelStopsAfterWebsocketClose(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept websocket: %v", err)
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "")
		time.AfterFunc(30*time.Millisecond, func() {
			_ = conn.Close(websocket.StatusGoingAway, "")
		})
		for {
			if _, _, err := conn.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	wsc, err := wss.NewWebSocketClient(ctx, wsURL, &http.Client{}, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}

	tunnel := newManagedTunnelWithHeartbeat(context.Background(), "socks", wsc, 10*time.Millisecond, 20*time.Millisecond)
	defer tunnel.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- tunnel.eg.Wait()
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected websocket close to stop the tunnel")
		}
		if !strings.Contains(err.Error(), "health check failed") && !strings.Contains(err.Error(), "read failed") {
			t.Fatalf("unexpected tunnel error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("managed tunnel did not stop after websocket close")
	}
}
