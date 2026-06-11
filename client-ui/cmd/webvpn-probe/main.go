package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rep1ace/wssocks-plugin-smu/client-ui/internal/captcha"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn/passwd"
)

const encryptedHost = "536d756973666f726d616c46696d6d75fa9b923c51c9a48bb382"

type result struct {
	Case        string      `json:"case"`
	Method      string      `json:"method,omitempty"`
	URL         string      `json:"url"`
	Status      int         `json:"status,omitempty"`
	FinalURL    string      `json:"final_url,omitempty"`
	ContentType string      `json:"content_type,omitempty"`
	DurationMS  int64       `json:"duration_ms"`
	BodyLen     int         `json:"body_len,omitempty"`
	BodyPrefix  string      `json:"body_prefix,omitempty"`
	Error       string      `json:"error,omitempty"`
	Headers     http.Header `json:"headers,omitempty"`
}

func main() {
	username := os.Getenv("SMU_VPN_USERNAME")
	password := os.Getenv("SMU_VPN_PASSWORD")
	if username == "" || password == "" {
		fatalf("SMU_VPN_USERNAME and SMU_VPN_PASSWORD are required")
	}

	al := passwd.AutoLogin{
		Host: passwd.SMUVpnHost,
		CaptchaHandler: func(imgData []byte) (string, error) {
			return captcha.Predict(imgData)
		},
		PhoneVerificationHandler: func(challenge passwd.PhoneVerificationChallenge) (string, error) {
			code := os.Getenv("SMU_VPN_SMS_CODE")
			if code == "" {
				return "", fmt.Errorf("SMS code requested for %s; set SMU_VPN_SMS_CODE and rerun", challenge.Phone)
			}
			return code, nil
		},
	}

	cookies, err := al.VpnLogin(username, password)
	if err != nil {
		fatalf("vpn login: %v", err)
	}
	fmt.Fprintf(os.Stderr, "vpn login ok, cookies=%d\n", len(cookies))

	jar, err := cookiejar.New(nil)
	if err != nil {
		fatalf("cookie jar: %v", err)
	}
	rootURL, _ := url.Parse("https://webvpn.smu.edu.cn/")
	jar.SetCookies(rootURL, cookies)

	followClient := &http.Client{Jar: jar, Timeout: 20 * time.Second}
	noRedirectClient := &http.Client{
		Jar:     jar,
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, tc := range probeCases() {
		runHTTPCase(noRedirectClient, "noredirect-"+tc.name, tc.method, tc.url, tc.body, tc.headers)
		runHTTPCase(followClient, "follow-"+tc.name, tc.method, tc.url, tc.body, tc.headers)
	}

	for _, raw := range []struct {
		scheme string
		url    string
	}{
		{"http", "https://webvpn.smu.edu.cn/http-55555/" + encryptedHost + "/probe?case=raw-upgrade-http"},
		{"ws", "https://webvpn.smu.edu.cn/ws-55555/" + encryptedHost + "/probe?case=raw-upgrade-ws"},
		{"https", "https://webvpn.smu.edu.cn/https-55555/" + encryptedHost + "/probe?case=raw-upgrade-https"},
		{"wss", "https://webvpn.smu.edu.cn/wss-55555/" + encryptedHost + "/probe?case=raw-upgrade-wss"},
	} {
		if schemeEnabled(raw.scheme) {
			runRawUpgrade(raw.url, cookies)
		}
	}
}

type probeCase struct {
	name    string
	method  string
	url     string
	body    []byte
	headers http.Header
}

func probeCases() []probeCase {
	httpBase := "https://webvpn.smu.edu.cn/http-55555/" + encryptedHost + "/probe"
	wsBase := "https://webvpn.smu.edu.cn/ws-55555/" + encryptedHost + "/probe"
	httpsBase := "https://webvpn.smu.edu.cn/https-55555/" + encryptedHost + "/probe"
	wssBase := "https://webvpn.smu.edu.cn/wss-55555/" + encryptedHost + "/probe"
	largeQuery := strings.Repeat("A", 3000)
	hugeQuery := strings.Repeat("B", 9000)
	smallBody := []byte("small-post-body")
	largeBody := []byte(strings.Repeat("P", 4096))
	jsonBody := []byte(`{"kind":"json-post","message":"hello through webvpn"}`)
	jsonHeader := http.Header{"Content-Type": {"application/json"}}
	textHeader := http.Header{"Content-Type": {"text/plain"}}

	var cases []probeCase
	for _, base := range []struct {
		name string
		url  string
	}{
		{"http", httpBase},
		{"ws", wsBase},
		{"https", httpsBase},
		{"wss", wssBase},
	} {
		if !schemeEnabled(base.name) {
			continue
		}
		cases = append(cases,
			probeCase{name: base.name + "-get-basic", method: http.MethodGet, url: base.url + "?case=" + base.name + "-get-basic"},
			probeCase{name: base.name + "-get-query-3k", method: http.MethodGet, url: base.url + "?case=" + base.name + "-get-query-3k&data=" + largeQuery},
			probeCase{name: base.name + "-get-query-9k", method: http.MethodGet, url: base.url + "?case=" + base.name + "-get-query-9k&data=" + hugeQuery},
			probeCase{name: base.name + "-fallback-open-shape", method: http.MethodGet, url: base.url + "/?wssocks_action=open&wssocks_session=probe-session&wssocks_transport=http-poll"},
			probeCase{name: base.name + "-fallback-send-shape", method: http.MethodGet, url: base.url + "/?wssocks_action=send&wssocks_session=probe-session&wssocks_transport=http-poll&wssocks_message=m&wssocks_part=0&wssocks_parts=1&wssocks_type=1&wssocks_data=eyJwaW5nIjp0cnVlfQ"},
			probeCase{name: base.name + "-post-empty", method: http.MethodPost, url: base.url + "?case=" + base.name + "-post-empty", headers: textHeader},
			probeCase{name: base.name + "-post-small", method: http.MethodPost, url: base.url + "?case=" + base.name + "-post-small", body: smallBody, headers: textHeader},
			probeCase{name: base.name + "-post-json", method: http.MethodPost, url: base.url + "?case=" + base.name + "-post-json", body: jsonBody, headers: jsonHeader},
			probeCase{name: base.name + "-post-4k", method: http.MethodPost, url: base.url + "?case=" + base.name + "-post-4k", body: largeBody, headers: textHeader},
		)
	}
	return cases
}

func schemeEnabled(name string) bool {
	filter := strings.TrimSpace(os.Getenv("WEBVPN_PROBE_SCHEMES"))
	if filter == "" {
		return true
	}
	for _, item := range strings.Split(filter, ",") {
		if strings.TrimSpace(item) == name {
			return true
		}
	}
	return false
}

func runHTTPCase(client *http.Client, name, method, rawURL string, body []byte, headers http.Header) {
	start := time.Now()
	req, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
	if err != nil {
		printResult(result{Case: name, Method: method, URL: rawURL, Error: err.Error()})
		return
	}
	req.Header.Set("User-Agent", "webvpn-probe/1.0")
	req.Header.Set("X-Probe-Case", name)
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		printResult(result{Case: name, Method: method, URL: rawURL, DurationMS: duration.Milliseconds(), Error: err.Error()})
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	printResult(result{
		Case:        name,
		Method:      method,
		URL:         rawURL,
		Status:      resp.StatusCode,
		FinalURL:    finalURL,
		ContentType: resp.Header.Get("Content-Type"),
		DurationMS:  duration.Milliseconds(),
		BodyLen:     len(respBody),
		BodyPrefix:  string(respBody),
		Headers:     selectedHeaders(resp.Header),
	})
}

func runRawUpgrade(rawURL string, cookies []*http.Cookie) {
	start := time.Now()
	status, headers, body, err := rawUpgrade(rawURL, cookies)
	duration := time.Since(start)
	res := result{
		Case:       "raw-upgrade",
		Method:     "GET",
		URL:        rawURL,
		DurationMS: duration.Milliseconds(),
		Headers:    selectedHeaders(headers),
		BodyPrefix: body,
	}
	if err != nil {
		res.Error = err.Error()
	} else {
		res.Status = status
	}
	printResult(res)
}

func rawUpgrade(rawURL string, cookies []*http.Cookie) (int, http.Header, string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0, nil, "", err
	}
	host := parsed.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second}, "tcp", host, &tls.Config{ServerName: parsed.Hostname()})
	if err != nil {
		return 0, nil, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return 0, nil, "", err
	}
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	var b strings.Builder
	b.WriteString("GET " + parsed.RequestURI() + " HTTP/1.1\r\n")
	b.WriteString("Host: " + parsed.Host + "\r\n")
	b.WriteString("User-Agent: webvpn-probe/1.0\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Origin: https://webvpn.smu.edu.cn\r\n")
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	b.WriteString("Sec-WebSocket-Key: " + wsKey + "\r\n")
	b.WriteString("X-Probe-Case: raw-upgrade\r\n")
	if len(cookies) > 0 {
		var values []string
		for _, cookie := range cookies {
			if cookie != nil && cookie.Name != "" {
				values = append(values, cookie.Name+"="+cookie.Value)
			}
		}
		b.WriteString("Cookie: " + strings.Join(values, "; ") + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return 0, nil, "", err
	}
	resp, err := http.ReadResponse(bufioNewReader(conn), nil)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return resp.StatusCode, resp.Header, string(respBody), nil
}

func bufioNewReader(r io.Reader) *bufio.Reader {
	return bufio.NewReader(r)
}

func selectedHeaders(headers http.Header) http.Header {
	out := http.Header{}
	for _, key := range []string{
		"Content-Type", "Content-Length", "Location", "Server", "Connection", "Upgrade",
		"X-Probe-Server", "X-WSSocks-Transport", "X-WSSocks-Message-Type",
	} {
		if values, ok := headers[key]; ok {
			out[key] = values
		}
	}
	return out
}

func printResult(res result) {
	data, _ := json.Marshal(res)
	fmt.Println(string(data))
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
