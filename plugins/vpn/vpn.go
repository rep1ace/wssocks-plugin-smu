package vpn

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/genshen/cmds"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn/passwd"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn/qrcode"
	plugin "github.com/rep1ace/wssocks/client"
	"github.com/rep1ace/wssocks/cmd/client"
	"github.com/rep1ace/wssocks/wss"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	VpnAuthMethodPasswd = iota
	VpnAuthMethodQRCode
)

const USTBVpnHost = passwd.USTBVpnHost

const (
	defaultVPNKeepAliveInterval = 2 * time.Minute
	defaultVPNKeepAliveTimeout  = 20 * time.Second
)

var ErrSessionExpired = errors.New("vpn session expired")

type UstbVpn struct {
	Enable                   bool
	AuthMethod               int // value of VpnAuthMethodPasswd or VpnAuthMethodQRCode
	PasswdAuth               passwd.UstbVpnPasswdAuth
	QrCodeAuth               qrcode.QrCodeAuth
	TargetVpn                string
	HostEncrypt              bool
	ForceLogout              bool
	ConnOptions              plugin.Options // normal connection options
	CaptchaHandler           passwd.CaptchaHandler
	PhoneVerificationHandler passwd.PhoneVerificationHandler

	runtime *runtimeState
}

type runtimeState struct {
	mu                      sync.Mutex
	session                 *vpnSession
	lastDialUsedCachedState bool
}

type vpnSessionKey struct {
	targetVpn  string
	authMethod int
	username   string
	password   string
}

type vpnSession struct {
	key        vpnSessionKey
	sslEnabled bool
	cookies    []*http.Cookie
	refreshed  time.Time
}

// create a UstbVpn instance, and add necessary command options to client sub-command.
func NewUstbVpnCli() *UstbVpn {
	vpn := UstbVpn{}
	vpn.ensureRuntime()
	// add more command options for client sub-command.
	if ok, clientCmd := cmds.Find(client.CommandNameClient); ok {
		clientCmd.FlagSet.BoolVar(&vpn.Enable, "vpn-enable", false, `enable USTB vpn feature.`)
		clientCmd.FlagSet.StringVar(&vpn.PasswdAuth.Username, "vpn-username", "", `username to login vpn.`)
		clientCmd.FlagSet.StringVar(&vpn.PasswdAuth.Password, "vpn-password", "", `password to login vpn.`)
		clientCmd.FlagSet.StringVar(&vpn.TargetVpn, "vpn-host", passwd.SMUVpnHost, `hostname of vpn server.`)
		clientCmd.FlagSet.BoolVar(&vpn.ForceLogout, "vpn-force-logout", false,
			`force logout account on other devices.`)
		clientCmd.FlagSet.BoolVar(&vpn.HostEncrypt, "vpn-host-encrypt", true,
			`encrypt proxy host using aes algorithm.`)
		vpn.AuthMethod = VpnAuthMethodPasswd // todo: for cli, only support password auth.
	}
	return &vpn
}

func (v *UstbVpn) ensureRuntime() {
	if v.runtime == nil {
		v.runtime = &runtimeState{}
	}
}

func (v *UstbVpn) sessionKey() vpnSessionKey {
	key := vpnSessionKey{
		targetVpn:  v.TargetVpn,
		authMethod: v.AuthMethod,
	}
	if v.AuthMethod == VpnAuthMethodPasswd {
		key.username = v.PasswdAuth.Username
		key.password = v.PasswdAuth.Password
	}
	return key
}

func (v *UstbVpn) ApplyConfig(cfg UstbVpn) {
	v.ensureRuntime()
	runtime := v.runtime
	runtime.mu.Lock()
	defer runtime.mu.Unlock()

	*v = cfg
	v.runtime = runtime
	if runtime.session != nil && runtime.session.key != v.sessionKey() {
		runtime.session = nil
	}
}

func (v *UstbVpn) InvalidateSession() {
	v.ensureRuntime()
	v.runtime.mu.Lock()
	defer v.runtime.mu.Unlock()
	v.runtime.session = nil
}

func (v *UstbVpn) snapshotSession() *vpnSession {
	v.ensureRuntime()
	v.runtime.mu.Lock()
	defer v.runtime.mu.Unlock()
	if v.runtime.session == nil {
		return nil
	}
	if v.runtime.session.key != v.sessionKey() {
		v.runtime.session = nil
		return nil
	}
	session := *v.runtime.session
	session.cookies = cloneCookies(v.runtime.session.cookies)
	return &session
}

func (v *UstbVpn) setSession(session *vpnSession) {
	v.ensureRuntime()
	v.runtime.mu.Lock()
	defer v.runtime.mu.Unlock()
	if session == nil {
		v.runtime.session = nil
		return
	}
	cloned := *session
	cloned.key = v.sessionKey()
	cloned.cookies = cloneCookies(session.cookies)
	v.runtime.session = &cloned
}

func cloneCookies(cookies []*http.Cookie) []*http.Cookie {
	if len(cookies) == 0 {
		return nil
	}
	out := make([]*http.Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		cp := *cookie
		out = append(out, &cp)
	}
	return out
}

func (v *UstbVpn) rememberDialSessionReuse(reused bool) {
	v.ensureRuntime()
	v.runtime.mu.Lock()
	defer v.runtime.mu.Unlock()
	v.runtime.lastDialUsedCachedState = reused
}

func (v *UstbVpn) takeDialSessionReuse() bool {
	v.ensureRuntime()
	v.runtime.mu.Lock()
	defer v.runtime.mu.Unlock()
	reused := v.runtime.lastDialUsedCachedState
	v.runtime.lastDialUsedCachedState = false
	return reused
}

// BeforeRequest is implementation of interface RequestPlugin
// In the UstbVpn plugin, we use it for vpn auth (password auth and QR code auth).
func (v *UstbVpn) BeforeRequest(hc *http.Client, transport *http.Transport, url *url.URL, header *http.Header) error {
	if !v.Enable {
		return nil
	}
	v.rememberDialSessionReuse(false)

	if v.AuthMethod == VpnAuthMethodPasswd {
		return v.PasswordAuthForCookie(hc, transport, url)
	} else if v.AuthMethod == VpnAuthMethodQRCode {
		return v.QrCodeAuthForCookie(hc, transport, url)
	}
	return fmt.Errorf("unknown auth method")
}

// PasswordAuthForCookie send password to vpn server for auth,
// and keep cookie for websocket request.
// It can support cli and gui client.
func (v *UstbVpn) PasswordAuthForCookie(hc *http.Client, transport *http.Transport, url *url.URL) error {
	session, reused, err := v.ensurePasswordSession(false)
	if err != nil {
		return err
	}
	v.rememberDialSessionReuse(reused)
	return v.applySessionToRequest(session, hc, transport, url)
}

func (v *UstbVpn) ensurePasswordSession(forceRefresh bool) (*vpnSession, bool, error) {
	if !forceRefresh {
		if session := v.snapshotSession(); session != nil {
			return session, true, nil
		}
	}

	username := v.PasswdAuth.Username
	// read username and password if they are empty.
	if username == "" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Enter username: ")
		text, err := reader.ReadString('\n')
		if err != nil {
			return nil, false, fmt.Errorf("error while reading username, %w", err)
		}
		username = strings.TrimSpace(text)
	}
	password := v.PasswdAuth.Password
	if password == "" {
		fmt.Print("Enter Password: ")
		bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, false, fmt.Errorf("error while parsing password, %w", err)
		}
		fmt.Println()
		password = string(bytePassword)
	}

	al := passwd.AutoLogin{
		Host:                     v.TargetVpn,
		ForceLogout:              v.ForceLogout,
		SkipTLSVerify:            v.ConnOptions.SkipTLSVerify,
		CaptchaHandler:           v.CaptchaHandler,
		PhoneVerificationHandler: v.PhoneVerificationHandler,
	}
	cookies, err := al.VpnLogin(username, password)
	if err != nil {
		return nil, false, fmt.Errorf("error vpn login: %w", err)
	}

	session := &vpnSession{
		sslEnabled: al.SSLEnabled,
		cookies:    cloneCookies(cookies),
		refreshed:  time.Now(),
	}
	v.setSession(session)
	return v.snapshotSession(), false, nil
}

func (v *UstbVpn) applySessionToRequest(session *vpnSession, hc *http.Client, transport *http.Transport, targetURL *url.URL) error {
	if session == nil {
		return errors.New("vpn session not initialized")
	}
	// In vpnLogin, we can test https support.
	// If the vpn support https, we can set transport.SkipTLSVerify if necessary.
	if session.sslEnabled && v.ConnOptions.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	// change target url.
	vpnUrl(v.HostEncrypt, v.TargetVpn, session.sslEnabled, targetURL)
	log.Infof("real url: %s, ssl enabled:%t", targetURL.String(), session.sslEnabled)

	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	cookieURL := *targetURL
	// replace url scheme "wss" to "https" and "ws" to "http"
	cookieURL.Scheme = strings.Replace(cookieURL.Scheme, "ws", "http", 1)
	jar.SetCookies(&cookieURL, cloneCookies(session.cookies))
	hc.Jar = jar
	return nil
}

func (v *UstbVpn) QrCodeAuthForCookie(hc *http.Client, transport *http.Transport, url *url.URL) error {
	if session := v.snapshotSession(); session != nil {
		v.rememberDialSessionReuse(true)
		return v.applySessionToRequest(session, hc, transport, url)
	}
	if v.QrCodeAuth == nil {
		return fmt.Errorf("QrCodeAuth is not configed")
	}
	// Note: todo: check https enabled for the vpn host
	// currently, it only support https schema.
	authHttpClient := http.Client{}
	var cookies []*http.Cookie

	// step1: send request to get a frame and SID in the frame.
	var qr qrcode.QrImg
	if err := qr.ParseQRCodeImgUrl(&authHttpClient, &cookies); err != nil {
		return err
	}

	// step2: pass qr code content to show qr code in ui and wait for scan status.
	if _, err := v.QrCodeAuth.ShowQrCodeAndWait(&authHttpClient, cookies, qr); err != nil {
		return err
	}

	session := &vpnSession{
		sslEnabled: true,
		cookies:    cloneCookies(cookies),
		refreshed:  time.Now(),
	}
	v.setSession(session)
	return v.applySessionToRequest(session, hc, transport, url)
}

func (v *UstbVpn) NormalizeDialFailure(err error) error {
	if err == nil || !v.Enable {
		return err
	}
	if !v.takeDialSessionReuse() {
		return err
	}

	var handshakeErr *wss.HandshakeError
	if !errors.As(err, &handshakeErr) {
		return err
	}

	if handshakeErr.StatusCode == http.StatusUnauthorized || handshakeErr.StatusCode == http.StatusForbidden ||
		strings.Contains(strings.ToLower(handshakeErr.FinalPath), "login") {
		v.InvalidateSession()
		return ErrSessionExpired
	}
	return err
}

func (v *UstbVpn) MaintainSession(ctx context.Context) error {
	if !v.Enable || v.AuthMethod != VpnAuthMethodPasswd {
		<-ctx.Done()
		return nil
	}

	ticker := time.NewTicker(defaultVPNKeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			keepAliveCtx, cancel := context.WithTimeout(ctx, defaultVPNKeepAliveTimeout)
			err := v.keepAlive(keepAliveCtx)
			cancel()
			if err != nil {
				return err
			}
		}
	}
}

func (v *UstbVpn) keepAlive(ctx context.Context) error {
	session := v.snapshotSession()
	if session == nil {
		return ErrSessionExpired
	}

	transport := &http.Transport{}
	if session.sslEnabled && v.ConnOptions.SkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	client := &http.Client{
		Transport: transport,
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	scheme := passwd.USTBVpnHttpsScheme
	if !session.sslEnabled {
		scheme = passwd.USTBVpnHttpScheme
	}
	keepAliveURL, err := url.Parse(scheme + "://" + v.TargetVpn + "/")
	if err != nil {
		return err
	}
	jar.SetCookies(keepAliveURL, cloneCookies(session.cookies))
	client.Jar = jar

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keepAliveURL.String(), nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		v.InvalidateSession()
		return ErrSessionExpired
	}

	if resp.Request != nil && strings.Contains(strings.ToLower(resp.Request.URL.Path), "login") {
		v.InvalidateSession()
		return ErrSessionExpired
	}

	log.WithField("refreshed_at", session.refreshed.Format(time.RFC3339)).Debug("vpn session keepalive ok")
	return nil
}

// ssl specific the protocol(whether to use ssl) used in the real connection
func vpnUrl(hostEncrypt bool, vpnHost string, ssl bool, u *url.URL) {
	// replace https://abc.com to "http://n.ustb.edu.cn/https/abc.com"
	// replace https://abc.com:8080 to "http://n.ustb.edu.cn/https-8080/abc.com"

	// split host and port if it could
	port := u.Port()
	if strings.ContainsRune(u.Host, ':') {
		if h, p, err := net.SplitHostPort(u.Host); err != nil {
			panic(err)
		} else {
			u.Host = h
			if port != "" {
				port = p
			}
		}
	}

	schemeWithPort := u.Scheme
	if (u.Scheme == "wss" || u.Scheme == "https") && port != "" && port != "443" {
		schemeWithPort = u.Scheme + "-" + port
	}
	if (u.Scheme == "ws" || u.Scheme == "http") && port != "" && port != "80" {
		schemeWithPort = u.Scheme + "-" + port
	}

	if hostEncrypt {
		const key = "SmuisformalFimmu"
		var aes_e = newAesEncrypt(key)
		encryptHost, _ := aes_e.Encrypt(u.Host)
		u.Path = "/" + schemeWithPort + "/" + hex.EncodeToString([]byte(key)) + hex.EncodeToString(encryptHost) + u.Path
	} else {
		u.Path = "/" + schemeWithPort + "/" + u.Host + u.Path
	}
	u.Host = vpnHost

	// set scheme
	if u.Scheme == "wss" || u.Scheme == "ws" {
		if ssl {
			u.Scheme = passwd.USTBVpnWSSScheme
		} else {
			u.Scheme = passwd.USTBVpnWSScheme
		}
	} else { // http or https
		if ssl {
			u.Scheme = passwd.USTBVpnHttpsScheme
		} else {
			u.Scheme = passwd.USTBVpnHttpScheme
		}
	}
}
