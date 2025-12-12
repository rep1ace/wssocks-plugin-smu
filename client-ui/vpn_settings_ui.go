package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/genshen/wssocks-plugin-ustb/plugins/vpn"
	"github.com/genshen/wssocks-plugin-ustb/plugins/vpn/passwd"
)

type VpnSettingsUI struct {
	uiVpnEnable      *widget.Check
	uiVpnForceLogout *widget.Check
	uiVpnHostEncrypt *widget.Check
	uiVpnHostInput   *widget.Entry
	uiVpnUsername    *widget.Entry
	uiVpnPassword    *widget.Entry
}

func (v *VpnSettingsUI) Init(pref fyne.Preferences) {
	v.uiVpnEnable = newCheckbox("enable smu vpn", true, nil)
	v.uiVpnForceLogout = newCheckbox("", true, nil)
	v.uiVpnHostEncrypt = newCheckbox("", true, nil)
	v.uiVpnHostInput = &widget.Entry{PlaceHolder: "vpn hostname", Text: "n.ustb.edu.cn"}
	v.uiVpnUsername = &widget.Entry{PlaceHolder: "vpn username", Text: ""}
	v.uiVpnPassword = &widget.Entry{PlaceHolder: "vpn password", Text: "", Password: true}

	// load Preference
	loadVPNMainPreference(pref, v.uiVpnEnable)
	// pass nil as auth method radio group, as we removed it.
	loadVpnPreference(pref, v.uiVpnForceLogout, v.uiVpnHostEncrypt, v.uiVpnHostInput, v.uiVpnUsername, v.uiVpnPassword)
}

func (v *VpnSettingsUI) Save(pref fyne.Preferences) {
	saveVPNMainPreference(pref, v.uiVpnEnable)
	saveVPNPreference(pref, v.uiVpnForceLogout, v.uiVpnHostEncrypt, v.uiVpnHostInput, v.uiVpnUsername, v.uiVpnPassword)
}

func (v *VpnSettingsUI) GetContainer() *fyne.Container {
	return container.NewVBox(
		&widget.Form{Items: []*widget.FormItem{
			{Text: "enable", Widget: v.uiVpnEnable},
			{Text: "force logout", Widget: v.uiVpnForceLogout},
			{Text: "host encrypt", Widget: v.uiVpnHostEncrypt},
			{Text: "vpn host", Widget: v.uiVpnHostInput},
			{Text: "username", Widget: v.uiVpnUsername},
			{Text: "password", Widget: v.uiVpnPassword},
		}},
	)
}

func (v *VpnSettingsUI) LoadSettingsValues(values *vpn.UstbVpn) {
	values.Enable = v.uiVpnEnable.Checked
	values.ForceLogout = v.uiVpnForceLogout.Checked
	values.HostEncrypt = v.uiVpnHostEncrypt.Checked
	values.TargetVpn = v.uiVpnHostInput.Text
	values.AuthMethod = vpn.VpnAuthMethodPasswd
	values.PasswdAuth = passwd.UstbVpnPasswdAuth{
		Username: v.uiVpnUsername.Text,
		Password: v.uiVpnPassword.Text,
	}
}
