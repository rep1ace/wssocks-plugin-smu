package passwd

import (
	"errors"
	"log"
	"net/http"
	"net/http/cookiejar"
	"os"
	"regexp"
	"testing"
)

func TestRep(t *testing.T) {
	var text1 = `var logoutOtherToken = 'e97e5e358c2713c2'`
	matched_1, err := regexp.Match(`logoutOtherToken[\s]+=[\s]+'[\w]+`, []byte(text1))
	if !matched_1 {
		t.Error(err)
	}

	var text2 = `var logoutOtherToken = 'e97e5e358c2713c2'  \n`
	matched_2, err := regexp.Match(`logoutOtherToken[\s]+=[\s]+'[\w]+`, []byte(text2))
	if !matched_2 {
		t.Error(err)
	}

	var text3 = `var logoutOtherToken = ''  \n`
	matched_3, err := regexp.Match(`logoutOtherToken[\s]+=[\s]+'[\w]+`, []byte(text3))
	if matched_3 {
		t.Error(err)
	}
}

func TestAutoLogin(t *testing.T) {
	if os.Getenv("SMU_VPN_LIVE_TEST") != "1" {
		t.Skip("set SMU_VPN_LIVE_TEST=1 to run live SMU VPN login test")
	}

	al := AutoLogin{Host: "n.ustb.edu.cn", ForceLogout: true}
	if cookies, err := al.VpnLogin("b20170328", "genshen1234"); err != nil {
		log.Println(err.Error())
	} else {
		log.Println(cookies)
	}
}

func TestParseLoginResponseSuccess(t *testing.T) {
	resp, err := parseLoginResponse(http.StatusOK, []byte(`{"status":true,"message":"登录成功","ticket":"ST-123"}`))
	if err != nil {
		t.Fatalf("parse login response: %v", err)
	}
	if resp.Ticket != "ST-123" {
		t.Fatalf("unexpected ticket: %q", resp.Ticket)
	}
}

func TestParseLoginResponseDoubleFactor(t *testing.T) {
	resp, err := parseLoginResponse(http.StatusOK, []byte(`{"status":true,"doubleFactor":true,"typePhone":true,"phone":"138****1234"}`))
	if err != nil {
		t.Fatalf("parse login response: %v", err)
	}
	if !resp.DoubleFactor || !resp.TypePhone || resp.Phone != "138****1234" {
		t.Fatalf("unexpected double factor response: %#v", resp)
	}
}

func TestParseLoginResponseFailure(t *testing.T) {
	_, err := parseLoginResponse(http.StatusOK, []byte(`{"status":false,"message":"验证码错误"}`))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
}

func TestPhoneVerificationSendOK(t *testing.T) {
	ok, reason := phoneVerificationSendOK([]byte(`{"alibaba_aliqin_fc_sms_num_send_response":{"result":{"err_code":"0"}}}`))
	if !ok {
		t.Fatalf("expected sms response ok, reason: %s", reason)
	}
}

func TestNeedsWebVPNSecondLogin(t *testing.T) {
	if needsWebVPNSecondLogin(nil, "https://webvpn.smu.edu.cn/login?second_login=true") {
		t.Fatal("second_login URL alone should not require WebVPN second login")
	}

	body := []byte(`<div id="second_login_layer"></div><script>var needTwoStep = '20240001'</script>`)
	if !needsWebVPNSecondLogin(body, "https://webvpn.smu.edu.cn/login") {
		t.Fatal("expected non-empty needTwoStep page to require WebVPN second login")
	}

	normalLogin := []byte(`<div id="second_login_layer"></div><a href="/login?cas_login=true">CAS统一身份认证登录</a>`)
	if needsWebVPNSecondLogin(normalLogin, "https://webvpn.smu.edu.cn/login") {
		t.Fatal("ordinary WebVPN login page should not be treated as completed second-login challenge")
	}

	publicSecondLogin := []byte(`<div id="second_login_layer"></div><script>var needTwoStep = ''</script>`)
	if needsWebVPNSecondLogin(publicSecondLogin, "https://webvpn.smu.edu.cn/login?second_login=true") {
		t.Fatal("public second_login page without account state should not send SMS")
	}
}

func TestParseWebVPNSecondLoginChallenge(t *testing.T) {
	body := []byte(`
		<input type="hidden" id="twostep-username" value="20240001">
		<input type="hidden" id="twostep-phone" value="13800138000">
		<script>
			$('input[name="disable_phone"]').val("13900139000");
		</script>
	`)

	challenge := parseWebVPNSecondLoginChallenge(body)
	if challenge.Username != "20240001" {
		t.Fatalf("unexpected username: %q", challenge.Username)
	}
	if challenge.Phone != "13800138000" {
		t.Fatalf("expected hidden input phone to win, got %q", challenge.Phone)
	}
}

func TestParseWebVPNSecondLoginChallengeFromScript(t *testing.T) {
	body := []byte(`
		<script>
			var needTwoStep = '20240002'
			$('#twostep-phone').val('13800138001')
			$('#two_step_phone').text('138****8001')
		</script>
	`)

	challenge := parseWebVPNSecondLoginChallenge(body)
	if challenge.Username != "20240002" {
		t.Fatalf("unexpected username: %q", challenge.Username)
	}
	if challenge.Phone != "13800138001" {
		t.Fatalf("unexpected phone: %q", challenge.Phone)
	}
}

func TestParseWebVPNSecondLoginChallengePhoneFromNeedTwoStep(t *testing.T) {
	challenge := parseWebVPNSecondLoginChallenge([]byte(`<script>var needTwoStep = '13800138002'</script>`))
	if challenge.Phone != "13800138002" {
		t.Fatalf("unexpected phone: %q", challenge.Phone)
	}
	if challenge.Username != "13800138002" {
		t.Fatalf("unexpected username: %q", challenge.Username)
	}
}

func TestWebVPNSecondLoginFallsBackToAccountIdentifier(t *testing.T) {
	al := AutoLogin{Account: "20240003"}
	challenge := parseWebVPNSecondLoginChallenge([]byte(`<div id="second_login_layer"></div>`))
	identifier := nonEmpty(challenge.Phone, challenge.Username)
	if identifier == "" {
		identifier = al.Account
	}
	if identifier != "20240003" {
		t.Fatalf("unexpected fallback identifier: %q", identifier)
	}
}

func TestSliderTrackValues(t *testing.T) {
	values := sliderTrackValues(123)
	if values.Get("w") != "123" {
		t.Fatalf("unexpected slider width: %q", values.Get("w"))
	}
	if values.Get("locations[0][x]") == "" || values.Get("locations[5][y]") == "" {
		t.Fatalf("expected jQuery-style nested location keys, got %#v", values)
	}
}

func TestWebVPNSliderCaptchaLive(t *testing.T) {
	if os.Getenv("SMU_VPN_SLIDER_LIVE_TEST") != "1" {
		t.Skip("set SMU_VPN_SLIDER_LIVE_TEST=1 to run live WebVPN slider test")
	}

	al := AutoLogin{}
	client := al.NewHttpClient(nil)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	client.Jar = jar

	captcha, err := al.fetchWebVPNSliderImage(client)
	if err != nil {
		t.Fatalf("fetch slider image: %v", err)
	}
	offset, err := solveWebVPNSliderOffset(captcha)
	if err != nil {
		t.Fatalf("solve slider image: %v", err)
	}
	t.Logf("slider offset: %d, y: %d", offset, captcha.H)
	if err := al.verifyWebVPNSliderCaptcha(client, offset); err != nil {
		t.Fatalf("verify slider captcha: %v", err)
	}
}
