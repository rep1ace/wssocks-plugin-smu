package passwd

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const SMUVpnHost = "webvpn.smu.edu.cn"
const CaptchaUrl = "https://webvpn.smu.edu.cn/https/536d756973666f726d616c46696d6d75bec2cf24168ae597f8d50e40b9f6/imageServlet.do"
const LoginUrl = "https://webvpn.smu.edu.cn/https/536d756973666f726d616c46696d6d75bec2cf24168ae597f8d50e40b9f6/login/login.do"
const RedirectUrl = "https://webvpn.smu.edu.cn/https/536d756973666f726d616c46696d6d75bccede7c1589becaf0c4550bbeed97492a/login"

// Constants used by vpn.go
const USTBVpnHost = SMUVpnHost // Alias for compatibility
const USTBVpnHttpScheme = "http"
const USTBVpnHttpsScheme = "https"
const USTBVpnWSScheme = "ws"
const USTBVpnWSSScheme = "wss"

// Keep existing interface for compatibility, though methods might change behavior or be unused
type AutoLoginInterface interface {
	TestAddr() string
	LoginAddr() string
	LogoutAddr() string
}

type CaptchaHandler func(imgData []byte) (string, error)

type AutoLogin struct {
	Host           string
	ForceLogout    bool
	SSLEnabled     bool // the vpn server supports https
	SkipTLSVerify  bool // skip tsl verify when setting https connectioon
	CaptchaHandler CaptchaHandler
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

	ticket, err := al.sendLogin(uname, passwd, captcha, hc)
	if err != nil {
		return nil, err
	}

	if err := al.redirectLogin(hc, ticket); err != nil {
		return nil, err
	}

	u, _ := url.Parse("https://" + SMUVpnHost)
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

func (al *AutoLogin) sendLogin(account, password, captcha string, client *http.Client) (string, error) {
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
		return "", err
	}
	req.Header = headers
	req.URL.RawQuery = "vpn-12-o2-uis.smu.edu.cn"

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	bodyString := string(bodyBytes)

	if resp.StatusCode == 200 && strings.Contains(bodyString, "成功") {
		var respJson map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &respJson); err != nil {
			return "", err
		}
		fmt.Println("登录成功")
		if ticket, ok := respJson["ticket"].(string); ok {
			return ticket, nil
		}
		return "", errors.New("ticket not found in response")
	}
	return "", fmt.Errorf("登录失败，原因：%s", bodyString)
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

	req, err := http.NewRequest("GET", RedirectUrl, nil)
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
	
	// We just need to execute this request to set cookies/session state
	return nil
}
