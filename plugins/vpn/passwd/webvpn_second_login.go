package passwd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"image"
	"image/png"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const WebVPNSecondLoginUrl = "https://webvpn.smu.edu.cn/login?second_login=true"
const WebVPNSMSImageUrl = "https://webvpn.smu.edu.cn/smscode/image"
const WebVPNSMSVerifyUrl = "https://webvpn.smu.edu.cn/smscode/verify"
const WebVPNSendSMSUrl = "https://webvpn.smu.edu.cn/send-sms/"
const WebVPNDoSecondLoginUrl = "https://webvpn.smu.edu.cn/do-second-login"

const webVPNSliderMaxAttempts = 3

type webVPNSecondLoginChallenge struct {
	Username    string
	Phone       string
	MaskedPhone string
}

type webVPNSliderImageResponse struct {
	H int    `json:"h"`
	P string `json:"p"`
	S string `json:"s"`
}

type webVPNActionResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	URL     string `json:"url"`
	Data    string `json:"data"`
	Error   string `json:"error"`
}

func (al *AutoLogin) completeWebVPNSecondLoginIfNeeded(client *http.Client, body []byte, finalURL string) error {
	if !needsWebVPNSecondLogin(body, finalURL) {
		return nil
	}

	challenge := parseWebVPNSecondLoginChallenge(body)
	log.WithFields(log.Fields{
		"final_url":            webVPNLogURL(finalURL),
		"has_phone":            challenge.Phone != "",
		"has_masked_phone":     challenge.MaskedPhone != "",
		"has_username":         challenge.Username != "",
		"has_account_fallback": strings.TrimSpace(al.Account) != "",
	}).Info("webvpn second login required")

	identifier := nonEmpty(challenge.Phone, challenge.Username)
	if identifier == "" {
		identifier = strings.TrimSpace(al.Account)
	}
	displayPhone := nonEmpty(challenge.Phone, challenge.MaskedPhone)
	if displayPhone == "" {
		displayPhone = identifier
	}
	if identifier == "" {
		return fmt.Errorf("%w: WebVPN 需要手机二次认证，但登录页没有返回手机号或账号，最终地址：%s", ErrAuthFailed, finalURL)
	}

	if err := al.passWebVPNSliderCaptcha(client); err != nil {
		return err
	}
	if err := al.sendWebVPNSMSCode(client, identifier); err != nil {
		return err
	}

	code, err := al.getPhoneVerificationCode(PhoneVerificationChallenge{
		Phone:   displayPhone,
		Message: "WebVPN 双重登录认证",
	})
	if err != nil {
		return err
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return fmt.Errorf("%w: WebVPN 手机验证码为空", ErrAuthFailed)
	}

	if err := al.submitWebVPNSecondLogin(client, challenge.Username, code); err != nil {
		return err
	}
	fmt.Println("WebVPN 手机验证成功")
	return nil
}

func (al *AutoLogin) CompleteWebVPNSecondLoginIfNeeded(client *http.Client, body []byte, finalURL string) error {
	return al.completeWebVPNSecondLoginIfNeeded(client, body, finalURL)
}

func (al *AutoLogin) EnsureWebVPNSecondLoginComplete(client *http.Client) (bool, error) {
	return al.ensureWebVPNSecondLoginComplete(client)
}

func needsWebVPNSecondLogin(body []byte, finalURL string) bool {
	bodyString := string(body)
	if !strings.Contains(bodyString, "second_login_layer") && !strings.Contains(bodyString, "do-second-login") {
		return false
	}

	challenge := parseWebVPNSecondLoginChallenge(body)
	return challenge.Username != "" || challenge.Phone != "" || challenge.MaskedPhone != ""
}

func isWebVPNLoginPage(body []byte, finalURL string) bool {
	if needsWebVPNSecondLogin(body, finalURL) {
		return false
	}

	if parsed, err := url.Parse(finalURL); err == nil && parsed.Path == "/login" {
		return true
	}

	bodyString := string(body)
	return strings.Contains(bodyString, "CAS统一身份认证登录") ||
		strings.Contains(bodyString, "资源访问控制系统") && strings.Contains(bodyString, "/login?cas_login=true")
}

func parseWebVPNSecondLoginChallenge(body []byte) webVPNSecondLoginChallenge {
	bodyString := string(body)
	needTwoStep := extractJSString(bodyString, "needTwoStep")
	phoneCandidates := []string{
		extractInputValueByID(bodyString, "twostep-phone"),
		extractJSSetValue(bodyString, `input\[name=["']?disable_phone["']?\]`),
		extractJSSetValue(bodyString, `#twostep-phone`),
		extractJSString(bodyString, "phone"),
		needTwoStep,
	}

	var challenge webVPNSecondLoginChallenge
	for _, candidate := range phoneCandidates {
		if phone := normalizePhone(candidate); phone != "" {
			challenge.Phone = phone
			break
		}
		if masked := normalizeMaskedPhone(candidate); masked != "" && challenge.MaskedPhone == "" {
			challenge.MaskedPhone = masked
		}
	}

	if challenge.Phone == "" {
		challenge.Phone = firstRegexpSubmatch(webVPNSecondLoginLayerFragment(bodyString), `(1[3-9]\d{9})`)
	}
	if challenge.MaskedPhone == "" {
		challenge.MaskedPhone = firstRegexpSubmatch(webVPNSecondLoginLayerFragment(bodyString), `(1\d{2}\*{4}\d{4})`)
	}

	challenge.Username = nonEmpty(
		extractInputValueByID(bodyString, "twostep-username"),
		extractJSSetValue(bodyString, `#twostep-username`),
	)
	if challenge.Username == "" {
		challenge.Username = needTwoStep
	}
	return challenge
}

func webVPNSecondLoginLayerFragment(body string) string {
	start := strings.Index(body, `id="second_login_layer"`)
	if start < 0 {
		start = strings.Index(body, `id='second_login_layer'`)
	}
	if start < 0 {
		return ""
	}
	end := strings.Index(body[start:], `id="second_login_layer_totp"`)
	if end < 0 {
		end = strings.Index(body[start:], `id='second_login_layer_totp'`)
	}
	if end < 0 {
		return body[start:]
	}
	return body[start : start+end]
}

func logWebVPNLoginState(step string, body []byte, finalURL string) {
	bodyString := string(body)
	challenge := parseWebVPNSecondLoginChallenge(body)
	log.WithFields(log.Fields{
		"step":                step,
		"final_url":           webVPNLogURL(finalURL),
		"has_second_layer":    strings.Contains(bodyString, "second_login_layer"),
		"has_do_second_login": strings.Contains(bodyString, "do-second-login"),
		"has_need_two_step":   extractJSString(bodyString, "needTwoStep") != "",
		"has_phone":           challenge.Phone != "",
		"has_masked_phone":    challenge.MaskedPhone != "",
		"has_username":        challenge.Username != "",
	}).Info("webvpn login check")
}

func webVPNLogURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host + parsed.Path
}

func extractInputValueByID(body, id string) string {
	pattern := fmt.Sprintf(`(?is)<input\b[^>]*\bid=["']%s["'][^>]*>`, regexp.QuoteMeta(id))
	input := regexp.MustCompile(pattern).FindString(body)
	if input == "" {
		return ""
	}
	value := firstRegexpSubmatch(input, `(?is)\bvalue=["']([^"']*)["']`)
	return strings.TrimSpace(html.UnescapeString(value))
}

func extractJSSetValue(body, selectorPattern string) string {
	patterns := []string{
		fmt.Sprintf(`(?is)\$\(["']%s["']\)\.val\(["']([^"']*)["']\)`, selectorPattern),
		fmt.Sprintf(`(?is)\$\(["']%s["']\)\.attr\(["']value["']\s*,\s*["']([^"']*)["']\)`, selectorPattern),
	}
	for _, pattern := range patterns {
		if value := firstRegexpSubmatch(body, pattern); value != "" {
			return strings.TrimSpace(html.UnescapeString(value))
		}
	}
	return ""
}

func extractJSString(body, name string) string {
	patterns := []string{
		fmt.Sprintf(`(?is)var\s+%s\s*=\s*["']([^"']*)["']`, regexp.QuoteMeta(name)),
		fmt.Sprintf(`(?is)%s\s*:\s*["']([^"']*)["']`, regexp.QuoteMeta(name)),
		fmt.Sprintf(`(?is)["']%s["']\s*:\s*["']([^"']*)["']`, regexp.QuoteMeta(name)),
	}
	for _, pattern := range patterns {
		if value := firstRegexpSubmatch(body, pattern); value != "" {
			return strings.TrimSpace(html.UnescapeString(value))
		}
	}
	return ""
}

func firstRegexpSubmatch(body, pattern string) string {
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(body)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSpace(match[1])
}

func normalizePhone(value string) string {
	value = strings.TrimSpace(value)
	if matched, _ := regexp.MatchString(`^1[3-9]\d{9}$`, value); matched {
		return value
	}
	return ""
}

func normalizeMaskedPhone(value string) string {
	value = strings.TrimSpace(value)
	if matched, _ := regexp.MatchString(`^1\d{2}\*{4}\d{4}$`, value); matched {
		return value
	}
	return ""
}

func (al *AutoLogin) passWebVPNSliderCaptcha(client *http.Client) error {
	var lastErr error
	for attempt := 1; attempt <= webVPNSliderMaxAttempts; attempt++ {
		captcha, err := al.fetchWebVPNSliderImage(client)
		if err != nil {
			lastErr = err
			continue
		}

		offset, err := solveWebVPNSliderOffset(captcha)
		if err != nil {
			lastErr = err
			continue
		}

		if err := al.verifyWebVPNSliderCaptcha(client, offset); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("%w: WebVPN 滑块验证失败", ErrAuthFailed)
}

func (al *AutoLogin) fetchWebVPNSliderImage(client *http.Client) (*webVPNSliderImageResponse, error) {
	req, err := http.NewRequest(http.MethodGet, WebVPNSMSImageUrl, nil)
	if err != nil {
		return nil, err
	}
	req.Header = webVPNAjaxHeaders(WebVPNSecondLoginUrl)
	q := req.URL.Query()
	q.Set("_", strconv.FormatInt(time.Now().UnixMilli(), 10))
	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: 获取 WebVPN 滑块失败，状态码：%d，响应：%s", ErrAuthFailed, resp.StatusCode, string(body))
	}

	var payload webVPNSliderImageResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("%w: 解析 WebVPN 滑块失败，响应：%s", ErrAuthFailed, string(body))
	}
	if payload.P == "" || payload.S == "" {
		return nil, fmt.Errorf("%w: WebVPN 滑块响应缺少图片", ErrAuthFailed)
	}
	return &payload, nil
}

func solveWebVPNSliderOffset(payload *webVPNSliderImageResponse) (int, error) {
	bg, err := decodeCaptchaDataURL(payload.P)
	if err != nil {
		return 0, fmt.Errorf("%w: 解析 WebVPN 滑块背景失败: %v", ErrAuthFailed, err)
	}
	piece, err := decodeCaptchaDataURL(payload.S)
	if err != nil {
		return 0, fmt.Errorf("%w: 解析 WebVPN 滑块拼图失败: %v", ErrAuthFailed, err)
	}

	offset, confidence := locateSliderGap(bg, piece, payload.H)
	if offset < 0 {
		return 0, fmt.Errorf("%w: 无法定位 WebVPN 滑块缺口", ErrAuthFailed)
	}
	if confidence <= 0 {
		return 0, fmt.Errorf("%w: WebVPN 滑块缺口匹配置信度过低", ErrAuthFailed)
	}
	return offset, nil
}

func decodeCaptchaDataURL(value string) (image.Image, error) {
	_, encoded, ok := strings.Cut(value, ",")
	if !ok {
		encoded = value
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return png.Decode(bytes.NewReader(data))
}

func locateSliderGap(bg image.Image, piece image.Image, yOffset int) (int, float64) {
	bgBounds := bg.Bounds()
	pieceBounds := piece.Bounds()
	bgWidth := bgBounds.Dx()
	bgHeight := bgBounds.Dy()
	pieceWidth := pieceBounds.Dx()
	pieceHeight := pieceBounds.Dy()
	if bgWidth <= 0 || bgHeight <= 0 || pieceWidth <= 0 || pieceHeight <= 0 {
		return -1, 0
	}

	yOffset = clampInt(yOffset, 0, maxInt(bgHeight-pieceHeight, 0))
	bgGradient := imageGradient(bg)
	boundary := pieceBoundaryMask(piece)
	if len(boundary) == 0 {
		boundary = pieceEdgeMask(piece)
	}
	if len(boundary) == 0 {
		return -1, 0
	}

	bestX := -1
	bestScore := math.Inf(-1)
	secondScore := math.Inf(-1)
	maxX := bgWidth - pieceWidth
	for x := 0; x <= maxX; x++ {
		score := 0.0
		count := 0
		for _, point := range boundary {
			bx := x + point.X
			by := yOffset + point.Y
			if bx < 0 || bx >= bgWidth || by < 0 || by >= bgHeight {
				continue
			}
			score += bgGradient[by][bx]
			count++
		}
		if count == 0 {
			continue
		}
		score /= float64(count)
		if score > bestScore {
			secondScore = bestScore
			bestScore = score
			bestX = x
		} else if score > secondScore {
			secondScore = score
		}
	}
	if bestX < 0 {
		return -1, 0
	}
	return bestX, bestScore - secondScore
}

func imageGradient(img image.Image) [][]float64 {
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	gray := make([][]float64, height)
	for y := 0; y < height; y++ {
		gray[y] = make([]float64, width)
		for x := 0; x < width; x++ {
			r, g, b, _ := img.At(bounds.Min.X+x, bounds.Min.Y+y).RGBA()
			gray[y][x] = 0.299*float64(r>>8) + 0.587*float64(g>>8) + 0.114*float64(b>>8)
		}
	}

	gradient := make([][]float64, height)
	for y := 0; y < height; y++ {
		gradient[y] = make([]float64, width)
	}
	for y := 1; y < height-1; y++ {
		for x := 1; x < width-1; x++ {
			gx := -gray[y-1][x-1] - 2*gray[y][x-1] - gray[y+1][x-1] +
				gray[y-1][x+1] + 2*gray[y][x+1] + gray[y+1][x+1]
			gy := -gray[y-1][x-1] - 2*gray[y-1][x] - gray[y-1][x+1] +
				gray[y+1][x-1] + 2*gray[y+1][x] + gray[y+1][x+1]
			gradient[y][x] = math.Hypot(gx, gy)
		}
	}
	return gradient
}

func pieceBoundaryMask(piece image.Image) []image.Point {
	bounds := piece.Bounds()
	points := make([]image.Point, 0, bounds.Dx()*bounds.Dy()/4)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			if alphaAt(piece, x, y) <= 24 {
				continue
			}
			if x == bounds.Min.X || x == bounds.Max.X-1 || y == bounds.Min.Y || y == bounds.Max.Y-1 ||
				alphaAt(piece, x-1, y) <= 24 || alphaAt(piece, x+1, y) <= 24 ||
				alphaAt(piece, x, y-1) <= 24 || alphaAt(piece, x, y+1) <= 24 {
				points = append(points, image.Pt(x-bounds.Min.X, y-bounds.Min.Y))
			}
		}
	}
	return points
}

func pieceEdgeMask(piece image.Image) []image.Point {
	gradient := imageGradient(piece)
	bounds := piece.Bounds()
	points := make([]image.Point, 0, bounds.Dx()*bounds.Dy()/6)
	for y := 1; y < bounds.Dy()-1; y++ {
		for x := 1; x < bounds.Dx()-1; x++ {
			if alphaAt(piece, bounds.Min.X+x, bounds.Min.Y+y) > 24 && gradient[y][x] > 45 {
				points = append(points, image.Pt(x, y))
			}
		}
	}
	return points
}

func alphaAt(img image.Image, x, y int) uint32 {
	_, _, _, a := img.At(x, y).RGBA()
	return a >> 8
}

func (al *AutoLogin) verifyWebVPNSliderCaptcha(client *http.Client, offset int) error {
	body, err := postWebVPNForm(client, WebVPNSMSVerifyUrl, sliderTrackValues(offset), WebVPNSecondLoginUrl)
	if err != nil {
		return err
	}
	var result webVPNActionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("%w: 解析 WebVPN 滑块验证响应失败，响应：%s", ErrAuthFailed, string(body))
	}
	if !result.Success {
		return fmt.Errorf("%w: WebVPN 滑块验证失败，原因：%s", ErrAuthFailed, nonEmpty(result.Message, string(body)))
	}
	return nil
}

func sliderTrackValues(offset int) url.Values {
	offset = maxInt(offset, 0)
	startX := 120
	startY := 360
	duration := 900 + offset*3
	values := url.Values{
		"w": {strconv.Itoa(offset)},
		"t": {strconv.Itoa(duration)},
	}

	steps := 5
	for i := 0; i <= steps; i++ {
		progress := float64(i) / float64(steps)
		eased := 1 - math.Pow(1-progress, 2)
		x := startX + int(math.Round(float64(offset)*eased))
		y := startY + int(math.Round(math.Sin(progress*math.Pi)*2))
		values.Set(fmt.Sprintf("locations[%d][x]", i), strconv.Itoa(x))
		values.Set(fmt.Sprintf("locations[%d][y]", i), strconv.Itoa(y))
	}
	return values
}

func (al *AutoLogin) sendWebVPNSMSCode(client *http.Client, phone string) error {
	body, err := postWebVPNForm(client, WebVPNSendSMSUrl, url.Values{
		"username":  {phone},
		"auth_type": {"cas"},
	}, WebVPNSecondLoginUrl)
	if err != nil {
		return err
	}
	var result webVPNActionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("%w: 解析 WebVPN 短信发送响应失败，响应：%s", ErrAuthFailed, string(body))
	}
	if !result.Success {
		return fmt.Errorf("%w: WebVPN 发送短信验证码失败，原因：%s", ErrAuthFailed, nonEmpty(result.Message, string(body)))
	}
	fmt.Println("WebVPN 手机验证码已发送")
	return nil
}

func (al *AutoLogin) submitWebVPNSecondLogin(client *http.Client, username, code string) error {
	data := url.Values{
		"username": {username},
		"code":     {code},
	}
	body, err := postWebVPNForm(client, WebVPNDoSecondLoginUrl, data, WebVPNSecondLoginUrl)
	if err != nil {
		return err
	}

	var result webVPNActionResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("%w: 解析 WebVPN 二次认证响应失败，响应：%s", ErrAuthFailed, string(body))
	}
	if !result.Success {
		return fmt.Errorf("%w: WebVPN 二次认证失败，原因：%s", ErrAuthFailed, nonEmpty(result.Message, string(body)))
	}

	nextURL := nonEmpty(result.URL, result.Data)
	if nextURL == "" {
		nextURL = "/"
	}
	return al.finishWebVPNSecondLogin(client, nextURL)
}

func (al *AutoLogin) finishWebVPNSecondLogin(client *http.Client, nextURL string) error {
	targetURL, err := resolveWebVPNURL(nextURL)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return err
	}
	req.Header = webVPNPageHeaders(WebVPNSecondLoginUrl)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	finalURL := ""
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	if needsWebVPNSecondLogin(body, finalURL) || isWebVPNLoginPage(body, finalURL) {
		return fmt.Errorf("%w: WebVPN 二次认证后仍停留在登录页，最终地址：%s", ErrAuthFailed, finalURL)
	}
	return nil
}

func postWebVPNForm(client *http.Client, rawURL string, data url.Values, referer string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header = webVPNAjaxHeaders(referer)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%w: WebVPN 请求失败，状态码：%d，响应：%s", ErrAuthFailed, resp.StatusCode, string(body))
	}
	return body, nil
}

func webVPNAjaxHeaders(referer string) http.Header {
	headers := webVPNPageHeaders(referer)
	headers.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	headers.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	headers.Set("Origin", "https://"+SMUVpnHost)
	headers.Set("X-Requested-With", "XMLHttpRequest")
	headers.Set("Sec-Fetch-Dest", "empty")
	headers.Set("Sec-Fetch-Mode", "cors")
	headers.Set("Sec-Fetch-Site", "same-origin")
	return headers
}

func webVPNPageHeaders(referer string) http.Header {
	headers := http.Header{
		"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
		"Accept-Language":           {"zh-CN,zh;q=0.9"},
		"Connection":                {"keep-alive"},
		"Host":                      {SMUVpnHost},
		"Upgrade-Insecure-Requests": {"1"},
		"User-Agent":                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"},
		"sec-ch-ua":                 {`"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"`},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {`"Windows"`},
	}
	if referer != "" {
		headers.Set("Referer", referer)
	}
	return headers
}

func resolveWebVPNURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", err
	}
	if parsed.IsAbs() {
		return parsed.String(), nil
	}
	base, _ := url.Parse("https://" + SMUVpnHost)
	return base.ResolveReference(parsed).String(), nil
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
