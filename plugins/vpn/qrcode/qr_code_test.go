package qrcode

import (
	"net/http"
	"testing"
)

func TestQRCodeHtmlUrl(t *testing.T) {
	t.Skip("requires live VPN endpoint")
	client := &http.Client{}
	var cookies []*http.Cookie
	_, _ = ParseQRCodeHtmlUrl(client, &cookies)
}

func TestQRCodeImgUrl(t *testing.T) {
	t.Skip("requires live VPN endpoint")
}
