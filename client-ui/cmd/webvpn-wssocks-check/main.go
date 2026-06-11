package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rep1ace/wssocks-plugin-smu/client-ui/internal/captcha"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn/passwd"
	"github.com/rep1ace/wssocks/wss"
	"github.com/segmentio/ksuid"
)

const encryptedHost = "536d756973666f726d616c46696d6d75fa9b923c51c9a48bb382"

type checkResult struct {
	Step  string `json:"step"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Info  string `json:"info,omitempty"`
}

func main() {
	username := os.Getenv("SMU_VPN_USERNAME")
	password := os.Getenv("SMU_VPN_PASSWORD")
	authKey := os.Getenv("WSSOCKS_AUTH_KEY")
	if username == "" || password == "" || authKey == "" {
		fatalf("SMU_VPN_USERNAME, SMU_VPN_PASSWORD and WSSOCKS_AUTH_KEY are required")
	}

	cookies, sslEnabled := login(username, password)
	printResult(checkResult{Step: "webvpn-login", OK: true, Info: fmt.Sprintf("cookies=%d ssl=%t", len(cookies), sslEnabled)})

	jar, err := cookiejar.New(nil)
	if err != nil {
		fatalf("cookie jar: %v", err)
	}
	webvpnRoot, _ := url.Parse("https://webvpn.smu.edu.cn/")
	jar.SetCookies(webvpnRoot, cookies)

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2: false,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{Transport: transport, Jar: jar, Timeout: 35 * time.Second}
	header := http.Header{}
	header.Set("Key", authKey)
	header.Set("Origin", "https://webvpn.smu.edu.cn")

	remote := "wss://webvpn.smu.edu.cn/ws-55555/" + encryptedHost
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	wsc, err := wss.NewWebSocketClient(ctx, remote, client, header)
	if err != nil {
		printResult(checkResult{Step: "connect", OK: false, Error: err.Error()})
		os.Exit(1)
	}
	defer wsc.Close()
	printResult(checkResult{Step: "connect", OK: true, Info: remote})

	version, err := wss.ExchangeVersion(ctx, wsc.WsConn)
	if err != nil {
		printResult(checkResult{Step: "version", OK: false, Error: err.Error()})
		os.Exit(1)
	}
	printResult(checkResult{Step: "version", OK: true, Info: fmt.Sprintf("server=%s code=%d", version.Version, version.VersionCode)})

	if err := checkEchoProxy(ctx, wsc); err != nil {
		printResult(checkResult{Step: "proxy-echo", OK: false, Error: err.Error()})
		os.Exit(1)
	}
	printResult(checkResult{Step: "proxy-echo", OK: true})
}

func login(username, password string) ([]*http.Cookie, bool) {
	al := passwd.AutoLogin{
		Host: passwd.SMUVpnHost,
		CaptchaHandler: func(imgData []byte) (string, error) {
			return captcha.Predict(imgData)
		},
		PhoneVerificationHandler: func(challenge passwd.PhoneVerificationChallenge) (string, error) {
			code := os.Getenv("SMU_VPN_SMS_CODE")
			if code == "" {
				fmt.Fprintf(os.Stderr, "SMS code requested for %s. Enter code: ", challenge.Phone)
				text, err := bufio.NewReader(os.Stdin).ReadString('\n')
				if err != nil {
					return "", err
				}
				code = strings.TrimSpace(text)
			}
			return code, nil
		},
	}
	cookies, err := al.VpnLogin(username, password)
	if err != nil {
		fatalf("vpn login: %v", err)
	}
	return cookies, al.SSLEnabled
}

func checkEchoProxy(ctx context.Context, client *wss.WebSocketClient) error {
	dataCh := make(chan []byte, 8)
	errCh := make(chan error, 2)
	proxy := client.NewProxy(func(_ ksuid.KSUID, data wss.ServerData) {
		dataCh <- data.Data
	}, func(ksuid.KSUID, bool) {}, func(_ ksuid.KSUID, err error) {
		errCh <- err
	})

	listenDone := make(chan error, 1)
	go func() {
		listenDone <- client.ListenIncomeMsg(1 << 23)
	}()

	if err := proxy.Establish(client, nil, wss.ProxyTypeSocks5, "127.0.0.1:55556"); err != nil {
		return err
	}
	if err := waitForPayload(ctx, dataCh, []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return fmt.Errorf("socks establish: %w", err)
	}

	payload := []byte(strings.Repeat("live-http-poll-query-chunk-", 300))
	if err := client.WriteProxyMessage(ctx, proxy.Id, wss.TagData, payload); err != nil {
		return err
	}
	if err := waitForPayload(ctx, dataCh, payload); err != nil {
		return err
	}

	select {
	case err := <-errCh:
		return err
	default:
	}
	select {
	case err := <-listenDone:
		return err
	default:
		return nil
	}
}

func waitForPayload(ctx context.Context, ch <-chan []byte, want []byte) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case got := <-ch:
			if bytes.Equal(got, want) {
				return nil
			}
		}
	}
}

func printResult(res checkResult) {
	data, _ := json.Marshal(res)
	fmt.Println(string(data))
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, strings.TrimRight(format, "\n")+"\n", args...)
	os.Exit(1)
}
