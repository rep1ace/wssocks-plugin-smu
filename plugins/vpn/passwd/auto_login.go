package passwd

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unicode"

	log "github.com/sirupsen/logrus"
)

const SMUVpnHost = "webvpn.smu.edu.cn"
const CaptchaUrl = "https://webvpn.smu.edu.cn/https/536d756973666f726d616c46696d6d75bec2cf24168ae597f8d50e40b9f6/imageServlet.do"
const LoginUrl = "https://webvpn.smu.edu.cn/https/536d756973666f726d616c46696d6d75bec2cf24168ae597f8d50e40b9f6/login/login.do"
const RedirectUrl = "https://webvpn.smu.edu.cn/https/536d756973666f726d616c46696d6d75bccede7c1589becaf0c4550bbeed97492a/login"
const WebVPNCASLoginUrl = "https://webvpn.smu.edu.cn/login"
const PhoneVerificationCodeUrl = "https://webvpn.smu.edu.cn/https/536d756973666f726d616c46696d6d75bec2cf24168ae597f8d50e40b9f6/user/getVerificationCode.do"
const PhoneValidateNumberUrl = "https://webvpn.smu.edu.cn/https/536d756973666f726d616c46696d6d75bec2cf24168ae597f8d50e40b9f6/user/getValidateNumber.do"

// Constants used by vpn.go
const USTBVpnHost = SMUVpnHost // Alias for compatibility
const USTBVpnHttpScheme = "http"
const USTBVpnHttpsScheme = "https"
const USTBVpnWSScheme = "ws"
const USTBVpnWSSScheme = "wss"

var ErrAuthFailed = errors.New("vpn authentication failed")

// Keep existing interface for compatibility, though methods might change behavior or be unused
type AutoLoginInterface interface {
	TestAddr() string
	LoginAddr() string
	LogoutAddr() string
}

type CaptchaHandler func(imgData []byte) (string, error)

type PhoneVerificationChallenge struct {
	Phone   string
	Message string
}

type PhoneVerificationHandler func(challenge PhoneVerificationChallenge) (string, error)

type AutoLogin struct {
	Host                     string
	Account                  string
	ForceLogout              bool
	SSLEnabled               bool // the vpn server supports https
	SkipTLSVerify            bool // skip tsl verify when setting https connectioon
	CaptchaHandler           CaptchaHandler
	PhoneVerificationHandler PhoneVerificationHandler
}

type loginResponse struct {
	Status            bool   `json:"status"`
	Message           string `json:"message"`
	Ticket            string `json:"ticket"`
	HomePage          string `json:"homePage"`
	Force             bool   `json:"force"`
	DoubleFactor      bool   `json:"doubleFactor"`
	TypePhone         bool   `json:"typePhone"`
	TypeWx            bool   `json:"typeWx"`
	Phone             string `json:"phone"`
	PswTermOfValidity bool   `json:"pswTermOfValidity"`
	UpdatePswTitle    string `json:"updatePswTitle"`
}

// Helper to open file
func openFile(url string) error {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	return err
}

// create http request client with SSLEnabled and skipTLSVerify as config
func (al *AutoLogin) NewHttpClient(checkRedirect func(req *http.Request, via []*http.Request) error) *http.Client {
	hc := http.Client{}
	if al.SkipTLSVerify {
		hc.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	if checkRedirect != nil {
		hc.CheckRedirect = checkRedirect
	}
	return &hc
}

// VpnLogin login vpn automatically and get cookie
func (al *AutoLogin) VpnLogin(uname, passwd string) ([]*http.Cookie, error) {
	al.SSLEnabled = true // SMU VPN uses HTTPS
	al.Account = strings.TrimSpace(uname)

	hc := al.NewHttpClient(nil)
	if jar, err := cookiejar.New(nil); err != nil {
		return nil, err
	} else {
		hc.Jar = jar
	}

	captcha, err := al.getCaptcha(hc)
	if err != nil {
		return nil, err
	}

	loginResult, err := al.sendLogin(uname, passwd, captcha, hc)
	if err != nil {
		return nil, err
	}
	logPrimaryLoginResult("primary-login", loginResult)
	if loginResult.DoubleFactor {
		loginResult, err = al.completePhoneVerification(loginResult, hc)
		if err != nil {
			return nil, err
		}
		logPrimaryLoginResult("phone-verification-login", loginResult)
	}

	if loginResult.Ticket != "" {
		if err := al.redirectLogin(hc, loginResult.Ticket); err != nil {
			return nil, err
		}
	} else if err := al.redirectServiceLogin(hc); err != nil {
		return nil, err
	}
	if err := al.ensureWebVPNLoginComplete(hc); err != nil {
		return nil, err
	}

	u, _ := url.Parse("https://" + SMUVpnHost)
	logCookieJarState("final-cookie-jar", hc, u)
	return hc.Jar.Cookies(u), nil
}

func (al *AutoLogin) getCaptcha(client *http.Client) (string, error) {
	headers := http.Header{
		"Accept":             {"image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"},
		"Accept-Language":    {"en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7"},
		"Connection":         {"keep-alive"},
		"Host":               {SMUVpnHost},
		"Referer":            {"https://webvpn.smu.edu.cn/https/536d756973666f726d616c46696d6d75bec2cf24168ae597f8d50e40b9f6/login.jsp?service=https%3A%2F%2Fwebvpn.smu.edu.cn%2Flogin%3Fcas_login%3Dtrue"},
		"Sec-Fetch-Dest":     {"image"},
		"Sec-Fetch-Mode":     {"no-cors"},
		"Sec-Fetch-Site":     {"same-origin"},
		"User-Agent":         {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"},
		"sec-ch-ua":          {`"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"`},
		"sec-ch-ua-mobile":   {"?0"},
		"sec-ch-ua-platform": {`"Windows"`},
	}

	req, err := http.NewRequest("GET", CaptchaUrl, nil)
	if err != nil {
		return "", err
	}
	req.Header = headers
	q := req.URL.Query()
	q.Add("vpn-1", "")
	req.URL.RawQuery = "vpn-1" // Force query string to match python script exactly if needed, though Add should work. Python uses params='vpn-1' which might be key only.
	// Requests params='vpn-1' results in ?vpn-1.

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read response body
	imgData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// If handler is provided, use it
	if al.CaptchaHandler != nil {
		return al.CaptchaHandler(imgData)
	}

	// Fallback to file-based approach
	// Save image to temp file
	file, err := os.CreateTemp("", "captcha-*.jpg")
	if err != nil {
		return "", err
	}
	// We don't remove the file immediately so user can see it.
	// defer os.Remove(file.Name())

	if _, err := file.Write(imgData); err != nil {
		file.Close()
		return "", err
	}
	file.Close()

	fmt.Printf("Captcha image saved to %s. Opening...\n", file.Name())
	if err := openFile(file.Name()); err != nil {
		fmt.Printf("Failed to open image automatically: %v. Please open it manually.\n", err)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("请输入验证码: ")
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

func (al *AutoLogin) sendLogin(account, password, captcha string, client *http.Client) (*loginResponse, error) {
	passwordMd5 := md5.Sum([]byte(password))
	passwordMd5Str := hex.EncodeToString(passwordMd5[:])

	data := url.Values{
		"loginName":       {account},
		"password":        {passwordMd5Str},
		"randcodekey":     {captcha},
		"locationBrowser": {"谷歌浏览器[Chrome]"},
		"appid":           {"3516472"},
		"redirect":        {"https://webvpn.smu.edu.cn/login?cas_login=true"},
		"strength":        {"3"},
	}
	if al.ForceLogout {
		data.Set("forceLogin", "1")
	}

	headers := http.Header{
		"Accept":                {"*/*"},
		"Accept-Language":       {"zh-CN,zh;q=0.9"},
		"Connection":            {"keep-alive"},
		"Content-Type":          {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Host":                  {SMUVpnHost},
		"Origin":                {"https://" + SMUVpnHost},
		"Referer":               {"https://webvpn.smu.edu.cn/https/536d756973666f726d616c46696d6d75bec2cf24168ae597f8d50e40b9f6/login.jsp?service=https%3A%2F%2Fwebvpn.smu.edu.cn%2Flogin%3Fcas_login%3Dtrue"},
		"Sec-Fetch-Dest":        {"empty"},
		"Sec-Fetch-Mode":        {"cors"},
		"Sec-Fetch-Site":        {"same-origin"},
		"User-Agent":            {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"},
		"X-KL-kis-Ajax-Request": {"Ajax_Request"},
		"X-Requested-With":      {"XMLHttpRequest"},
		"sec-ch-ua":             {`"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"`},
		"sec-ch-ua-mobile":      {"?0"},
		"sec-ch-ua-platform":    {`"Windows"`},
	}

	req, err := http.NewRequest("POST", LoginUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = headers
	req.URL.RawQuery = "vpn-12-o2-uis.smu.edu.cn"

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	result, parseErr := parseLoginResponse(resp.StatusCode, bodyBytes)
	log.WithFields(log.Fields{
		"status_code":       resp.StatusCode,
		"content_type":      resp.Header.Get("Content-Type"),
		"set_cookie_names":  responseCookieNames(resp),
		"parse_error":       parseErr != nil,
		"body_json":         json.Valid(bodyBytes),
		"body_size":         len(bodyBytes),
		"has_double_factor": result != nil && result.DoubleFactor,
		"has_ticket":        result != nil && result.Ticket != "",
		"has_phone":         result != nil && strings.TrimSpace(result.Phone) != "",
		"type_phone":        result != nil && result.TypePhone,
	}).Info("webvpn primary login response")
	return result, parseErr
}

func logPrimaryLoginResult(step string, result *loginResponse) {
	if result == nil {
		return
	}
	log.WithFields(log.Fields{
		"step":                 step,
		"status":               result.Status,
		"double_factor":        result.DoubleFactor,
		"type_phone":           result.TypePhone,
		"type_wx":              result.TypeWx,
		"has_phone":            strings.TrimSpace(result.Phone) != "",
		"phone_masked":         normalizeMaskedPhone(result.Phone) != "",
		"has_ticket":           result.Ticket != "",
		"has_home_page":        result.HomePage != "",
		"force":                result.Force,
		"psw_term_of_validity": result.PswTermOfValidity,
		"message":              trimLogValue(result.Message, 160),
	}).Info("webvpn primary login parsed")
}

func parseLoginResponse(statusCode int, bodyBytes []byte) (*loginResponse, error) {
	return parseLoginResponseWithOptions(statusCode, bodyBytes, false)
}

func parseLoginResponseWithOptions(statusCode int, bodyBytes []byte, allowMissingTicket bool) (*loginResponse, error) {
	bodyString := string(bodyBytes)
	var result loginResponse
	if err := json.Unmarshal(bodyBytes, &result); err != nil {
		if statusCode == http.StatusOK && strings.Contains(bodyString, "成功") {
			return nil, errors.New("ticket not found in response")
		}
		return nil, fmt.Errorf("%w: 登录失败，原因：%s", ErrAuthFailed, bodyString)
	}

	if statusCode == http.StatusOK && result.Status {
		if result.DoubleFactor {
			return &result, nil
		}
		if result.Ticket != "" {
			fmt.Println("登录成功")
			return &result, nil
		}
		if allowMissingTicket {
			return &result, nil
		}
		if result.PswTermOfValidity {
			return nil, fmt.Errorf("%w: %s", ErrAuthFailed, nonEmpty(result.UpdatePswTitle, "账号密码已过期，需要先在网页端修改密码"))
		}
		if result.Message != "" {
			return nil, fmt.Errorf("%w: 登录成功但未返回 webvpn ticket，原因：%s", ErrAuthFailed, result.Message)
		}
		return nil, errors.New("ticket not found in response")
	}

	reason := result.Message
	if reason == "" {
		reason = bodyString
	}
	return nil, fmt.Errorf("%w: 登录失败，原因：%s", ErrAuthFailed, reason)
}

func (al *AutoLogin) completePhoneVerification(result *loginResponse, client *http.Client) (*loginResponse, error) {
	if result == nil {
		return nil, errors.New("missing phone verification challenge")
	}
	if !result.TypePhone {
		return nil, fmt.Errorf("%w: 当前账号需要二次认证，但登录页未提供手机验证码方式", ErrAuthFailed)
	}

	phone := strings.TrimSpace(result.Phone)
	if phone == "" {
		return nil, fmt.Errorf("%w: 当前账号需要手机验证，但登录响应未返回手机号", ErrAuthFailed)
	}

	if err := al.sendPhoneVerificationCode(client, phone); err != nil {
		return nil, err
	}

	code, err := al.getPhoneVerificationCode(PhoneVerificationChallenge{
		Phone:   phone,
		Message: result.Message,
	})
	if err != nil {
		return nil, err
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, errors.New("phone verification code is empty")
	}

	verified, err := al.submitPhoneVerification(client, phone, code)
	if err != nil {
		return nil, err
	}
	if verified.DoubleFactor {
		return nil, fmt.Errorf("%w: 手机验证码提交后仍需要二次认证", ErrAuthFailed)
	}
	fmt.Println("手机验证成功")
	return verified, nil
}

func (al *AutoLogin) sendPhoneVerificationCode(client *http.Client, phone string) error {
	attempts := []struct {
		url  string
		data url.Values
	}{
		{
			url: PhoneVerificationCodeUrl,
			data: url.Values{
				"phone": {phone},
				"time":  {fmt.Sprint(time.Now().UnixMilli())},
			},
		},
		{
			url: PhoneValidateNumberUrl,
			data: url.Values{
				"phone": {phone},
			},
		},
	}

	var lastErr error
	for _, attempt := range attempts {
		body, err := al.postForm(client, attempt.url, attempt.data)
		if err != nil {
			lastErr = err
			continue
		}
		if ok, reason := phoneVerificationSendOK(body); ok {
			fmt.Println("手机验证码已发送")
			return nil
		} else {
			lastErr = fmt.Errorf("%w: 发送手机验证码失败，原因：%s", ErrAuthFailed, reason)
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("%w: 发送手机验证码失败", ErrAuthFailed)
}

func (al *AutoLogin) getPhoneVerificationCode(challenge PhoneVerificationChallenge) (string, error) {
	if al.PhoneVerificationHandler != nil {
		return al.PhoneVerificationHandler(challenge)
	}

	reader := bufio.NewReader(os.Stdin)
	if challenge.Phone != "" {
		fmt.Printf("手机验证码已发送到 %s\n", challenge.Phone)
	}
	fmt.Print("请输入手机验证码: ")
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

func (al *AutoLogin) submitPhoneVerification(client *http.Client, phone, code string) (*loginResponse, error) {
	data := url.Values{
		"phone":           {phone},
		"authNumber":      {code},
		"locationBrowser": {"谷歌浏览器[Chrome]"},
		"redirect":        {"https://webvpn.smu.edu.cn/login?cas_login=true"},
	}

	bodyBytes, err := al.postForm(client, LoginUrl, data)
	if err != nil {
		return nil, err
	}
	return parseLoginResponseWithOptions(http.StatusOK, bodyBytes, true)
}

func (al *AutoLogin) postForm(client *http.Client, rawURL string, data url.Values) ([]byte, error) {
	headers := http.Header{
		"Accept":                {"*/*"},
		"Accept-Language":       {"zh-CN,zh;q=0.9"},
		"Connection":            {"keep-alive"},
		"Content-Type":          {"application/x-www-form-urlencoded; charset=UTF-8"},
		"Host":                  {SMUVpnHost},
		"Origin":                {"https://" + SMUVpnHost},
		"Referer":               {"https://webvpn.smu.edu.cn/https/536d756973666f726d616c46696d6d75bec2cf24168ae597f8d50e40b9f6/login.jsp?service=https%3A%2F%2Fwebvpn.smu.edu.cn%2Flogin%3Fcas_login%3Dtrue"},
		"Sec-Fetch-Dest":        {"empty"},
		"Sec-Fetch-Mode":        {"cors"},
		"Sec-Fetch-Site":        {"same-origin"},
		"User-Agent":            {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"},
		"X-KL-kis-Ajax-Request": {"Ajax_Request"},
		"X-Requested-With":      {"XMLHttpRequest"},
		"sec-ch-ua":             {`"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"`},
		"sec-ch-ua-mobile":      {"?0"},
		"sec-ch-ua-platform":    {`"Windows"`},
	}

	req, err := http.NewRequest("POST", rawURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = headers
	req.URL.RawQuery = "vpn-12-o2-uis.smu.edu.cn"

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: 请求失败，状态码：%d，响应：%s", ErrAuthFailed, resp.StatusCode, string(bodyBytes))
	}
	return bodyBytes, nil
}

func phoneVerificationSendOK(body []byte) (bool, string) {
	bodyString := strings.TrimSpace(string(body))
	if bodyString == "" {
		return true, ""
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		if strings.Contains(bodyString, "alibaba_aliqin_fc_sms_num_send_response") &&
			strings.Contains(bodyString, "err_code") &&
			strings.Contains(bodyString, "0") {
			return true, ""
		}
		return false, bodyString
	}

	if response, ok := payload["alibaba_aliqin_fc_sms_num_send_response"].(map[string]interface{}); ok {
		if result, ok := response["result"].(map[string]interface{}); ok {
			if fmt.Sprint(result["err_code"]) == "0" {
				return true, ""
			}
		}
	}
	if payload["status"] == true || payload["success"] == true || strings.Contains(bodyString, "成功") {
		return true, ""
	}
	if response, ok := payload["error_response"].(map[string]interface{}); ok {
		return false, fmt.Sprint(response)
	}
	return false, bodyString
}

func nonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func trimLogValue(value string, maxLen int) string {
	value = strings.TrimSpace(value)
	if maxLen <= 0 || len(value) <= maxLen {
		return value
	}
	return value[:maxLen] + "..."
}

func responseCookieNames(resp *http.Response) []string {
	if resp == nil {
		return nil
	}
	cookies := resp.Cookies()
	names := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil || cookie.Name == "" {
			continue
		}
		names = append(names, cookie.Name)
	}
	return names
}

func logCookieJarState(step string, client *http.Client, target *url.URL) {
	if client == nil || client.Jar == nil || target == nil {
		return
	}
	cookies := client.Jar.Cookies(target)
	names := make([]string, 0, len(cookies))
	for _, cookie := range cookies {
		if cookie == nil || cookie.Name == "" {
			continue
		}
		names = append(names, cookie.Name)
	}
	log.WithFields(log.Fields{
		"step":         step,
		"cookie_names": names,
		"cookie_count": len(names),
	}).Info("webvpn cookie jar")
}

func logWebVPNPageSummary(step string, body []byte) {
	bodyString := string(body)
	log.WithFields(log.Fields{
		"step":                 step,
		"title":                safeLogPreview(extractHTMLTitle(bodyString), 80),
		"text_head":            htmlTextPreview(bodyString, 180),
		"has_login_form":       strings.Contains(bodyString, `id="form"`) || strings.Contains(bodyString, `id='form'`),
		"has_second_layer":     strings.Contains(bodyString, "second_login_layer"),
		"has_websocket_marker": strings.Contains(strings.ToLower(bodyString), "websocket") || strings.Contains(bodyString, "wss-"),
	}).Info("webvpn page summary")
}

func extractHTMLTitle(body string) string {
	lower := strings.ToLower(body)
	titleStart := strings.Index(lower, "<title")
	if titleStart < 0 {
		return ""
	}
	contentStart := strings.Index(lower[titleStart:], ">")
	if contentStart < 0 {
		return ""
	}
	contentStart += titleStart + 1
	contentEnd := strings.Index(lower[contentStart:], "</title>")
	if contentEnd < 0 {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(body[contentStart : contentStart+contentEnd]))
}

func htmlTextPreview(body string, maxRunes int) string {
	body = removeHTMLTagBlocks(body, "script")
	body = removeHTMLTagBlocks(body, "style")
	var out strings.Builder
	inTag := false
	lastSpace := true
	for _, r := range body {
		switch r {
		case '<':
			inTag = true
			if !lastSpace {
				out.WriteByte(' ')
				lastSpace = true
			}
		case '>':
			inTag = false
		default:
			if inTag {
				continue
			}
			if unicode.IsSpace(r) {
				if !lastSpace {
					out.WriteByte(' ')
					lastSpace = true
				}
				continue
			}
			out.WriteRune(r)
			lastSpace = false
		}
	}
	return safeLogPreview(html.UnescapeString(out.String()), maxRunes)
}

func removeHTMLTagBlocks(body, tag string) string {
	lower := strings.ToLower(body)
	openPrefix := "<" + strings.ToLower(tag)
	closeTag := "</" + strings.ToLower(tag) + ">"
	var out strings.Builder
	for {
		start := strings.Index(lower, openPrefix)
		if start < 0 {
			out.WriteString(body)
			return out.String()
		}
		out.WriteString(body[:start])
		closeRel := strings.Index(lower[start:], closeTag)
		if closeRel < 0 {
			return out.String()
		}
		end := start + closeRel + len(closeTag)
		body = body[end:]
		lower = lower[end:]
	}
}

func safeLogPreview(value string, maxRunes int) string {
	value = maskDigitRuns(strings.TrimSpace(value))
	if maxRunes <= 0 {
		return value
	}
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes]) + "..."
}

func maskDigitRuns(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); {
		if value[i] < '0' || value[i] > '9' {
			out.WriteByte(value[i])
			i++
			continue
		}
		start := i
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			i++
		}
		run := value[start:i]
		if len(run) >= 6 {
			out.WriteString(run[:2])
			out.WriteString("***")
			out.WriteString(run[len(run)-2:])
			continue
		}
		out.WriteString(run)
	}
	return out.String()
}

func (al *AutoLogin) redirectLogin(client *http.Client, ticket string) error {
	params := url.Values{
		"cas_login": {"true"},
		"ticket":    {ticket},
	}

	headers := http.Header{
		"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"Accept-Language":           {"zh-CN,zh;q=0.9"},
		"Connection":                {"keep-alive"},
		"Host":                      {SMUVpnHost},
		"Referer":                   {"https://webvpn.smu.edu.cn/https/536d756973666f726d616c46696d6d75bec2cf24168ae597f8d50e40b9f6/login.jsp?service=https%3A%2F%2Fwebvpn.smu.edu.cn%2Flogin%3Fcas_login%3Dtrue"},
		"Upgrade-Insecure-Requests": {"1"},
		"User-Agent":                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"},
	}

	req, err := http.NewRequest("GET", WebVPNCASLoginUrl, nil)
	if err != nil {
		return err
	}
	req.Header = headers
	req.URL.RawQuery = params.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	log.WithFields(log.Fields{
		"step":             "redirect-login",
		"status_code":      resp.StatusCode,
		"content_type":     resp.Header.Get("Content-Type"),
		"set_cookie_names": responseCookieNames(resp),
		"final_url":        webVPNLogURL(finalURL),
		"body_size":        len(bodyBytes),
	}).Info("webvpn page response")
	logWebVPNPageSummary("redirect-login", bodyBytes)
	if err := al.completeWebVPNSecondLoginIfNeeded(client, bodyBytes, finalURL); err != nil {
		return err
	}
	logWebVPNLoginState("redirect-login", bodyBytes, finalURL)
	if resp.Request != nil && resp.Request.URL != nil {
		logCookieJarState("redirect-login", client, resp.Request.URL)
	}
	if isWebVPNLoginPage(bodyBytes, finalURL) {
		return fmt.Errorf("%w: CAS 登录后仍被重定向到 WebVPN 登录页，最终地址：%s", ErrAuthFailed, finalURL)
	}
	return nil
}

func (al *AutoLogin) redirectServiceLogin(client *http.Client) error {
	req, err := http.NewRequest("GET", "https://"+SMUVpnHost+"/login?cas_login=true", nil)
	if err != nil {
		return err
	}
	req.Header = http.Header{
		"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		"Accept-Language":           {"zh-CN,zh;q=0.9"},
		"Connection":                {"keep-alive"},
		"Host":                      {SMUVpnHost},
		"Upgrade-Insecure-Requests": {"1"},
		"User-Agent":                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	log.WithFields(log.Fields{
		"step":             "redirect-service-login",
		"status_code":      resp.StatusCode,
		"content_type":     resp.Header.Get("Content-Type"),
		"set_cookie_names": responseCookieNames(resp),
		"final_url":        webVPNLogURL(finalURL),
		"body_size":        len(bodyBytes),
	}).Info("webvpn page response")
	logWebVPNPageSummary("redirect-service-login", bodyBytes)
	if err := al.completeWebVPNSecondLoginIfNeeded(client, bodyBytes, finalURL); err != nil {
		return err
	}
	logWebVPNLoginState("redirect-service-login", bodyBytes, finalURL)
	if resp.Request != nil && resp.Request.URL != nil {
		logCookieJarState("redirect-service-login", client, resp.Request.URL)
	}
	if strings.Contains(strings.ToLower(finalURL), "login.jsp") ||
		strings.Contains(string(bodyBytes), "id=\"loginName\"") ||
		isWebVPNLoginPage(bodyBytes, finalURL) {
		return fmt.Errorf("%w: 手机验证后仍被重定向到登录页，最终地址：%s", ErrAuthFailed, finalURL)
	}
	return nil
}

func (al *AutoLogin) ensureWebVPNLoginComplete(client *http.Client) error {
	if _, err := al.ensureWebVPNSecondLoginComplete(client); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+SMUVpnHost+"/", nil)
	if err != nil {
		return err
	}
	req.Header = webVPNPageHeaders("https://" + SMUVpnHost + "/login?cas_login=true")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	log.WithFields(log.Fields{
		"step":             "login-complete-check",
		"status_code":      resp.StatusCode,
		"content_type":     resp.Header.Get("Content-Type"),
		"set_cookie_names": responseCookieNames(resp),
		"final_url":        webVPNLogURL(finalURL),
		"body_size":        len(bodyBytes),
	}).Info("webvpn page response")
	logWebVPNPageSummary("login-complete-check", bodyBytes)
	if err := al.completeWebVPNSecondLoginIfNeeded(client, bodyBytes, finalURL); err != nil {
		return err
	}
	logWebVPNLoginState("login-complete-check", bodyBytes, finalURL)
	if resp.Request != nil && resp.Request.URL != nil {
		logCookieJarState("login-complete-check", client, resp.Request.URL)
	}
	if isWebVPNLoginPage(bodyBytes, finalURL) {
		return fmt.Errorf("%w: WebVPN 登录后仍未完成认证，最终地址：%s", ErrAuthFailed, finalURL)
	}
	return nil
}

func (al *AutoLogin) ensureWebVPNSecondLoginComplete(client *http.Client) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, WebVPNSecondLoginUrl, nil)
	if err != nil {
		return false, err
	}
	req.Header = webVPNPageHeaders("https://" + SMUVpnHost + "/login?cas_login=true")

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return false, err
	}
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	log.WithFields(log.Fields{
		"step":             "second-login-probe",
		"status_code":      resp.StatusCode,
		"content_type":     resp.Header.Get("Content-Type"),
		"set_cookie_names": responseCookieNames(resp),
		"final_url":        webVPNLogURL(finalURL),
		"body_size":        len(bodyBytes),
	}).Info("webvpn page response")
	logWebVPNPageSummary("second-login-probe", bodyBytes)
	logWebVPNLoginState("second-login-probe", bodyBytes, finalURL)
	if resp.Request != nil && resp.Request.URL != nil {
		logCookieJarState("second-login-probe", client, resp.Request.URL)
	}
	if !needsWebVPNSecondLogin(bodyBytes, finalURL) {
		return false, nil
	}
	return true, al.completeWebVPNSecondLoginIfNeeded(client, bodyBytes, finalURL)
}
