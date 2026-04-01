package vpn

import (
	"net/http"
	"testing"
	"time"

	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn/passwd"
)

func TestApplyConfigInvalidatesSessionWhenAuthSettingsChange(t *testing.T) {
	tests := []struct {
		name string
		cfg  UstbVpn
	}{
		{
			name: "vpn host changed",
			cfg: UstbVpn{
				TargetVpn:  "new.example",
				AuthMethod: VpnAuthMethodPasswd,
				PasswdAuth: passwd.UstbVpnPasswdAuth{Username: "u1", Password: "p1"},
			},
		},
		{
			name: "username changed",
			cfg: UstbVpn{
				TargetVpn:  "old.example",
				AuthMethod: VpnAuthMethodPasswd,
				PasswdAuth: passwd.UstbVpnPasswdAuth{Username: "u2", Password: "p1"},
			},
		},
		{
			name: "password changed",
			cfg: UstbVpn{
				TargetVpn:  "old.example",
				AuthMethod: VpnAuthMethodPasswd,
				PasswdAuth: passwd.UstbVpnPasswdAuth{Username: "u1", Password: "p2"},
			},
		},
		{
			name: "auth method changed",
			cfg: UstbVpn{
				TargetVpn:  "old.example",
				AuthMethod: VpnAuthMethodQRCode,
				PasswdAuth: passwd.UstbVpnPasswdAuth{Username: "u1", Password: "p1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &UstbVpn{
				TargetVpn:  "old.example",
				AuthMethod: VpnAuthMethodPasswd,
				PasswdAuth: passwd.UstbVpnPasswdAuth{Username: "u1", Password: "p1"},
			}
			v.ensureRuntime()
			v.setSession(&vpnSession{
				sslEnabled: true,
				cookies:    []*http.Cookie{{Name: "s", Value: "old"}},
				refreshed:  time.Now(),
			})

			v.ApplyConfig(tt.cfg)

			if sess := v.snapshotSession(); sess != nil {
				t.Fatalf("expected session to be invalidated, got %#v", sess)
			}
		})
	}
}

func TestApplyConfigPreservesSessionWhenAuthSettingsMatch(t *testing.T) {
	v := &UstbVpn{
		TargetVpn:   "old.example",
		AuthMethod:  VpnAuthMethodPasswd,
		HostEncrypt: true,
		PasswdAuth:  passwd.UstbVpnPasswdAuth{Username: "u1", Password: "p1"},
	}
	v.ensureRuntime()
	v.setSession(&vpnSession{
		sslEnabled: true,
		cookies:    []*http.Cookie{{Name: "s", Value: "old"}},
		refreshed:  time.Now(),
	})

	v.ApplyConfig(UstbVpn{
		TargetVpn:   "old.example",
		AuthMethod:  VpnAuthMethodPasswd,
		HostEncrypt: false,
		PasswdAuth:  passwd.UstbVpnPasswdAuth{Username: "u1", Password: "p1"},
	})

	if sess := v.snapshotSession(); sess == nil || len(sess.cookies) == 0 || sess.cookies[0].Value != "old" {
		t.Fatalf("expected session to be preserved, got %#v", sess)
	}
}

func TestApplyConfigPreservesSessionWhenCredentialsArePrompted(t *testing.T) {
	v := &UstbVpn{
		TargetVpn:  "old.example",
		AuthMethod: VpnAuthMethodPasswd,
	}
	v.ensureRuntime()
	v.setSession(&vpnSession{
		sslEnabled: true,
		cookies:    []*http.Cookie{{Name: "s", Value: "old"}},
		refreshed:  time.Now(),
	})

	v.ApplyConfig(UstbVpn{
		TargetVpn:  "old.example",
		AuthMethod: VpnAuthMethodPasswd,
	})

	if sess := v.snapshotSession(); sess == nil || len(sess.cookies) == 0 || sess.cookies[0].Value != "old" {
		t.Fatalf("expected prompted-credential session to be preserved, got %#v", sess)
	}
}
