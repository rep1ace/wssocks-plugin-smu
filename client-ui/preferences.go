package main

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/widget"
	"github.com/genshen/wssocks-plugin-ustb/plugins/vpn"
)

const (
	PrefHasPreference  = "has_preference"
	PrefLocalAddr      = "local_addr"
	PrefRemoteAddr     = "remote_addr"
	PrefHttpEnable     = "http_enable"
	PrefHttpLocalAddr  = "http_local_addr"
	PrefSkipTSLVerify  = "skip_TSL_verify"
	PrefVpnEnable      = "vpn_enable"
	PrefVpnAuthMethod  = "auth_method"
	PrefVpnForceLogout = "vpn_force_logout"
	PrefVpnHostEncrypt = "vpn_host_encrypt"
	PrefVpnHostInput   = "vpn_host"
	PrefVpnUsername    = "vpn_username"
	PrefVpnPassword    = "vpn_password"
	PrefSaveVpnPwd     = "save_vpn_password"
	PrefAuthToken      = "auth_token"
	PrefSaveToken      = "save_token"
)

func saveBasicPreference(pref fyne.Preferences, uiLocalAddr, uiRemoteAddr,
	uiHttpLocalAddr, uiAuthToken *widget.Entry, uiHttpEnable *widget.Check,
	uiSkipTSLVerify, uiSaveToken *widget.Check) {
	pref.SetBool(PrefHasPreference, true)
	pref.SetString(PrefLocalAddr, uiLocalAddr.Text)
	pref.SetString(PrefRemoteAddr, uiRemoteAddr.Text)

	pref.SetBool(PrefSaveToken, uiSaveToken.Checked)
	if uiSaveToken.Checked {
		pref.SetString(PrefAuthToken, encrypt(uiAuthToken.Text))
	} else {
		pref.SetString(PrefAuthToken, "")
	}

	pref.SetBool(PrefHttpEnable, uiHttpEnable.Checked)
	pref.SetString(PrefHttpLocalAddr, uiHttpLocalAddr.Text)
	pref.SetBool(PrefSkipTSLVerify, uiSkipTSLVerify.Checked)
}

func saveVPNMainPreference(pref fyne.Preferences,
	uiVpnEnable *widget.Check) {
	pref.SetBool(PrefVpnEnable, uiVpnEnable.Checked)
}

func saveVPNPreference(pref fyne.Preferences, uiVpnForceLogout, uiVpnHostEncrypt, uiSaveVpnPwd *widget.Check,
	uiVpnHostInput, uiVpnUsername, uiVpnPassword *widget.Entry) {
	if !pref.Bool(PrefHasPreference) {
		return
	}

	pref.SetBool(PrefVpnForceLogout, uiVpnForceLogout.Checked)
	pref.SetBool(PrefVpnHostEncrypt, uiVpnHostEncrypt.Checked)
	pref.SetBool(PrefSaveVpnPwd, uiSaveVpnPwd.Checked)
	pref.SetString(PrefVpnHostInput, uiVpnHostInput.Text)
	pref.SetString(PrefVpnUsername, uiVpnUsername.Text)
	if uiSaveVpnPwd.Checked && uiVpnPassword.Text != "" {
		pref.SetString(PrefVpnPassword, encrypt(uiVpnPassword.Text))
	} else {
		pref.SetString(PrefVpnPassword, "")
	}
	pref.SetInt(PrefVpnAuthMethod, vpn.VpnAuthMethodPasswd)
}

func loadBasicPreference(pref fyne.Preferences, uiLocalAddr, uiRemoteAddr,
	uiHttpLocalAddr, uiAuthToken *widget.Entry, uiHttpEnable *widget.Check,
	uiSkipTSLVerify, uiSaveToken *widget.Check) {
	if !pref.Bool(PrefHasPreference) {

		uiHttpLocalAddr.Disable()
		return
	}

	// local address
	if localAddr := pref.String(PrefLocalAddr); strings.TrimSpace(localAddr) != "" {
		uiLocalAddr.SetText(strings.TrimSpace(localAddr))
	}
	// remote address
	if remoteAddr := pref.String(PrefRemoteAddr); strings.TrimSpace(remoteAddr) != "" {
		uiRemoteAddr.SetText(strings.TrimSpace(remoteAddr))
	}
	// http enable (default false)
	if pref.Bool(PrefHttpEnable) {
		uiHttpEnable.SetChecked(true)
	}
	// http local address
	if httpAddr := pref.String(PrefHttpLocalAddr); strings.TrimSpace(httpAddr) != "" {
		uiHttpLocalAddr.SetText(strings.TrimSpace(httpAddr))
	}
	// skip TSL verify
	// skip TSL verify
	if pref.Bool(PrefSkipTSLVerify) {
		uiSkipTSLVerify.SetChecked(true)
	}

	// auth token
	if saveToken := pref.Bool(PrefSaveToken); saveToken {
		uiSaveToken.SetChecked(true)
		if token := pref.String(PrefAuthToken); token != "" {
			uiAuthToken.SetText(decrypt(token))
		}
	} else {
		uiSaveToken.SetChecked(false)
	}

	if !uiHttpEnable.Checked {
		uiHttpLocalAddr.Disable()
	}
}

func loadVPNMainPreference(pref fyne.Preferences, uiVpnEnable *widget.Check) {
	if !pref.Bool(PrefHasPreference) {
		return
	}
	// vpn enable
	if enable := pref.Bool(PrefVpnEnable); !enable {
		uiVpnEnable.SetChecked(enable) // toggle default value
	} // else, default value(true) or preference is true, dont touch it.

}

func loadVpnPreference(pref fyne.Preferences, uiVpnForceLogout, uiVpnHostEncrypt, uiSaveVpnPwd *widget.Check,
	uiVpnHostInput, uiVpnUsername, uiVpnPassword *widget.Entry) {
	if !pref.Bool(PrefHasPreference) {
		return
	}
	// vpn force logout
	if enable := pref.Bool(PrefVpnForceLogout); !enable {
		uiVpnForceLogout.SetChecked(enable)
	}
	// vpn force logout
	if enable := pref.Bool(PrefVpnHostEncrypt); !enable {
		uiVpnHostEncrypt.SetChecked(enable)
	}

	// vpn host, username, password
	if host := pref.String(PrefVpnHostInput); strings.TrimSpace(host) != "" {
		uiVpnHostInput.SetText(strings.TrimSpace(host))
	}
	if username := pref.String(PrefVpnUsername); strings.TrimSpace(username) != "" {
		uiVpnUsername.SetText(strings.TrimSpace(username))
	}
	if savePwd := pref.Bool(PrefSaveVpnPwd); savePwd {
		uiSaveVpnPwd.SetChecked(true)
		if password := pref.String(PrefVpnPassword); password != "" {
			uiVpnPassword.SetText(decrypt(password))
		}
	} else {
		uiSaveVpnPwd.SetChecked(false)
	}
}
