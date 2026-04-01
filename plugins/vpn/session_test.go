package vpn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/rep1ace/wssocks/wss"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn/qrcode"
)

func TestKeepAliveInvalidatesExpiredSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}

	vpnClient := UstbVpn{
		Enable:     true,
		AuthMethod: VpnAuthMethodPasswd,
		TargetVpn:  u.Host,
	}
	vpnClient.ensureRuntime()
	vpnClient.setSession(&vpnSession{
		sslEnabled: false,
		cookies: []*http.Cookie{
			{Name: "vpn", Value: "cookie"},
		},
		refreshed: time.Now(),
	})

	err = vpnClient.keepAlive(context.Background())
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected session expired error, got %v", err)
	}
	if vpnClient.snapshotSession() != nil {
		t.Fatal("expected vpn session to be invalidated after expiry")
	}
}

type qrAuthStub struct {
	calls int
}

func (q *qrAuthStub) ShowQrCodeAndWait(client *http.Client, cookies []*http.Cookie, qr qrcode.QrImg) ([]*http.Cookie, error) {
	q.calls++
	return nil, errors.New("unexpected qr auth")
}

func TestQrCodeAuthForCookieReusesCachedSession(t *testing.T) {
	qrAuth := &qrAuthStub{}
	vpnClient := UstbVpn{
		Enable:     true,
		AuthMethod: VpnAuthMethodQRCode,
		QrCodeAuth: qrAuth,
		TargetVpn:  "vpn.example",
	}
	vpnClient.ensureRuntime()
	vpnClient.setSession(&vpnSession{
		sslEnabled: true,
		cookies: []*http.Cookie{
			{Name: "vpn", Value: "cookie"},
		},
		refreshed: time.Now(),
	})

	for i := 0; i < 2; i++ {
		targetURL, err := url.Parse("ws://origin.example/path")
		if err != nil {
			t.Fatalf("parse target url: %v", err)
		}
		transport := &http.Transport{}
		client := &http.Client{}

		if err := vpnClient.BeforeRequest(client, transport, targetURL, &http.Header{}); err != nil {
			t.Fatalf("before request #%d: %v", i+1, err)
		}
		if targetURL.String() != "wss://vpn.example/ws/origin.example/path" {
			t.Fatalf("unexpected rewritten target url on call %d: %s", i+1, targetURL.String())
		}
		if client.Jar == nil {
			t.Fatalf("expected cookies to be applied on call %d", i+1)
		}

		cookieURL := *targetURL
		cookieURL.Scheme = "https"
		cookies := client.Jar.Cookies(&cookieURL)
		if len(cookies) != 1 || cookies[0].Value != "cookie" {
			t.Fatalf("unexpected cookies on call %d: %#v", i+1, cookies)
		}
	}

	if qrAuth.calls != 0 {
		t.Fatalf("expected cached session to skip qr auth, got %d calls", qrAuth.calls)
	}
}

func TestNormalizeDialFailureExpiresCachedSessionOnUnauthorizedHandshake(t *testing.T) {
	vpnClient := UstbVpn{
		Enable:     true,
		AuthMethod: VpnAuthMethodPasswd,
		TargetVpn:  "vpn.example",
	}
	vpnClient.ensureRuntime()
	vpnClient.setSession(&vpnSession{
		sslEnabled: true,
		cookies:    []*http.Cookie{{Name: "vpn", Value: "cookie"}},
		refreshed:  time.Now(),
	})

	targetURL, err := url.Parse("ws://origin.example/path")
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}
	if err := vpnClient.BeforeRequest(&http.Client{}, &http.Transport{}, targetURL, &http.Header{}); err != nil {
		t.Fatalf("before request: %v", err)
	}

	err = vpnClient.NormalizeDialFailure(&wss.HandshakeError{
		StatusCode: http.StatusUnauthorized,
		Err:        errors.New("bad handshake"),
	})
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
	if vpnClient.snapshotSession() != nil {
		t.Fatal("expected cached session to be invalidated")
	}
}

func TestNormalizeDialFailureExpiresCachedSessionOnLoginRedirect(t *testing.T) {
	vpnClient := UstbVpn{
		Enable:     true,
		AuthMethod: VpnAuthMethodQRCode,
		TargetVpn:  "vpn.example",
	}
	vpnClient.ensureRuntime()
	vpnClient.setSession(&vpnSession{
		sslEnabled: true,
		cookies:    []*http.Cookie{{Name: "vpn", Value: "cookie"}},
		refreshed:  time.Now(),
	})

	targetURL, err := url.Parse("ws://origin.example/path")
	if err != nil {
		t.Fatalf("parse target url: %v", err)
	}
	if err := vpnClient.BeforeRequest(&http.Client{}, &http.Transport{}, targetURL, &http.Header{}); err != nil {
		t.Fatalf("before request: %v", err)
	}

	err = vpnClient.NormalizeDialFailure(&wss.HandshakeError{
		StatusCode: http.StatusOK,
		FinalPath:  "/login",
		Err:        errors.New("bad handshake"),
	})
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
	if vpnClient.snapshotSession() != nil {
		t.Fatal("expected cached session to be invalidated")
	}
}

func TestNormalizeDialFailurePreservesOriginalErrorWithoutCachedReuse(t *testing.T) {
	original := &wss.HandshakeError{
		StatusCode: http.StatusUnauthorized,
		Err:        errors.New("bad handshake"),
	}

	tests := []struct {
		name    string
		enabled bool
		reused  bool
	}{
		{name: "fresh login attempt", enabled: true, reused: false},
		{name: "vpn disabled", enabled: false, reused: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpnClient := UstbVpn{
				Enable:     tt.enabled,
				AuthMethod: VpnAuthMethodPasswd,
				TargetVpn:  "vpn.example",
			}
			vpnClient.ensureRuntime()
			vpnClient.setSession(&vpnSession{
				sslEnabled: true,
				cookies:    []*http.Cookie{{Name: "vpn", Value: "cookie"}},
				refreshed:  time.Now(),
			})
			vpnClient.rememberDialSessionReuse(tt.reused)

			got := vpnClient.NormalizeDialFailure(original)
			if got != original {
				t.Fatalf("expected original error to be preserved, got %v", got)
			}
			if vpnClient.snapshotSession() == nil {
				t.Fatal("expected session to remain cached")
			}
		})
	}
}
