package main

import (
	_ "embed"
	"fmt"
	"net/url"
	"runtime"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	resource "github.com/genshen/wssocks-plugin-ustb/client-ui/resources"
	"github.com/genshen/wssocks-plugin-ustb/extra"
	"github.com/genshen/wssocks-plugin-ustb/plugins/vpn"
	pluginversion "github.com/genshen/wssocks-plugin-ustb/wssocks-ustb/version"
	"github.com/genshen/wssocks/client"
	"github.com/genshen/wssocks/version"
)

const (
	AppName           = "wssocks Client"
	AppId             = "wssocks-ustb.genshen.github.com"
	CoreGithubRepoUrl = "https://github.com/genshen/wssocks"
	GithubRepoUrl     = "https://github.com/genshen/wssocks-plugin-ustb"
	DocumentUrl       = "https://genshen.github.io/wssocks-plugin-ustb/"
)

//go:embed app-512.png
var appIconData []byte

const (
	btnStopped = iota
	btnStarting
	btnRunning
	btnStopping
)

const (
	ProxyCommandGit = iota
	ProxyCommandHttp
	ProxyCommandSsh
)

const (
	TextVpnAuthMethodPasswd = "Password"
	TextVpnAuthMethodQrCode = "QR Code"
)

func newEntryWithText(text string) *widget.Entry {
	entry := widget.NewEntry()
	entry.SetText(text)
	return entry
}

func newCheckbox(text string, checked bool, onChanged func(bool)) *widget.Check {
	checkbox := widget.NewCheck(text, onChanged)
	checkbox.SetChecked(checked)
	return checkbox
}

func main() {
	wssApp := app.NewWithID(AppId)
	wssApp.Settings().SetTheme(&myTheme{})
	wssApp.SetIcon(fyne.NewStaticResource("icon", appIconData))

	w := wssApp.NewWindow(AppName)
	//w.SetFixedSize(true)
	//w.Resize(fyne.NewSize(100, 100))

	// basic input
	uiLocalAddr := &widget.Entry{PlaceHolder: "socks5 listen address", Text: "127.0.0.1:1080"}
	uiRemoteAddr := &widget.Entry{PlaceHolder: "wssocks server address"}
	uiAuthToken := &widget.Entry{PlaceHolder: "the token for proxy authentication"}
	uiHttpEnable := newCheckbox("", false, nil)
	uiHttpLocalAddr := &widget.Entry{PlaceHolder: "http listen address", Text: "127.0.0.1:1086"}
	uiSkipTSLVerify := newCheckbox("", false, nil)

	loadBasicPreference(wssApp.Preferences(), uiLocalAddr, uiRemoteAddr, uiHttpLocalAddr, uiHttpEnable, uiSkipTSLVerify)

	uiHttpEnable.OnChanged = func(checked bool) {
		if checked {
			uiHttpLocalAddr.Enable()
		} else {
			uiHttpLocalAddr.Disable()
		}
	}

	// create vpn ui and necessary callbacks.
	vpnUi, onLoadValue, onVpnClose := loadVpnUI(&wssApp)

	btnStart := widget.NewButtonWithIcon("Start", theme.MailSendIcon(), nil)
	btnStart.Importance = widget.HighImportance

	btnStatus := btnStopped
	var handles extra.TaskHandles
	var ignoreWaitErr = true
	btnStart.OnTapped = func() {
		if btnStatus == btnRunning { // running can stop
			btnStatus = btnStopping
			ignoreWaitErr = true
			btnStart.SetText("Stopping")
			handles.NotifyCloseWrapper()
			btnStart.SetText("Start")
			btnStatus = btnStopped
		} else if btnStatus == btnStopped { // stopped can run
			options := extra.Options{
				Options: client.Options{
					LocalSocks5Addr: uiLocalAddr.Text,
					HttpEnabled:     uiHttpEnable.Checked,
					LocalHttpAddr:   uiHttpLocalAddr.Text,
					SkipTLSVerify:   uiSkipTSLVerify.Checked,
				},
				UstbVpn:    onLoadValue(),
				RemoteAddr: uiRemoteAddr.Text,
				AuthToken:  uiAuthToken.Text,
			}
			btnStatus = btnStarting
			btnStart.SetText("Loading")

			// Run connection in a goroutine to avoid blocking UI (especially for captcha)
			go func() {
				if err := handles.StartWssocks(options); err != nil {
					// log error
					fyne.Do(func() {
						dialog.ShowError(err, w)
						btnStart.SetText("Start")
						btnStatus = btnStopped
					})
					return
				}
				fyne.Do(func() {
					btnStart.SetText("Stop")
					btnStatus = btnRunning
				})

				// Wait for connection to close
				// the `ignoreWaitErr` the same as swiftui.
				ignoreWaitErr = false
				// wait error and stop the client
				if err := handles.Wait(); err != nil && !ignoreWaitErr {
					fyne.Do(func() {
						dialog.ShowError(err, w)
					})
				}
				fyne.Do(func() {
					btnStart.SetText("Start")
					btnStatus = btnStopped
				})
				ignoreWaitErr = true
			}()
		}
	}

	docUrl, err := url.Parse(DocumentUrl)
	if err != nil {
		return
	}

	repoUrl, err := url.Parse(GithubRepoUrl)
	if err != nil {
		return
	}

	coreRepoUrl, err := url.Parse(CoreGithubRepoUrl)
	if err != nil {
		return
	}

	basicUi := &widget.Form{Items: []*widget.FormItem{
		{Text: "socks5 address", Widget: uiLocalAddr},
		{Text: "remote address", Widget: uiRemoteAddr},
		{Text: "auth token", Widget: uiAuthToken},
		{Text: "http(s) proxy", Widget: uiHttpEnable},
		{Text: "http(s) address", Widget: uiHttpLocalAddr},
		{Text: "skip TSL verify", Widget: uiSkipTSLVerify},
	}}

	selectCopyProxyCommand := container.NewBorder(nil, nil, nil, nil,
		NewWSelectWithCopyProxyCommand([]string{"git", "http/https", "ssh/sftp/scp"},
			func(sel *widget.Select, value string) {
				if value != "" {
					sel.ClearSelected()
					switch value {
					case "git":
						copyToClipboard(ProxyCommandGit, uiLocalAddr.Text, uiHttpLocalAddr.Text, w)
					case "http/https":
						copyToClipboard(ProxyCommandHttp, uiLocalAddr.Text, uiHttpLocalAddr.Text, w)
					case "ssh/sftp/scp":
						copyToClipboard(ProxyCommandSsh, uiLocalAddr.Text, uiHttpLocalAddr.Text, w)
					}
				}
			},
		),
	)

	w.SetContent(container.NewVBox(
		container.NewAppTabs(
			container.NewTabItem("Basic", widget.NewCard("", "wssocks settings", basicUi)),
			container.NewTabItem("SMU VPN", container.NewVBox(
				widget.NewCard("", "SMU VPN settings", vpnUi)),
			),
		),
		btnStart,
		selectCopyProxyCommand,
		&widget.Separator{},
		container.NewGridWithColumns(2,
			container.NewHBox(
				NewHyperlinkIcon(resource.GithubIcon(), coreRepoUrl),
				widget.NewHyperlink("wssocks core: ", coreRepoUrl),
			),
			widget.NewLabel("v"+version.VERSION),
		),
		container.NewGridWithColumns(2,
			container.NewHBox(
				NewHyperlinkIcon(resource.GithubIcon(), repoUrl),
				widget.NewHyperlink("USTB vpn plugin: ", repoUrl),
			),
			container.NewGridWithColumns(2,
				widget.NewLabel("v"+pluginversion.VERSION),
				container.NewHBox(
					layout.NewSpacer(),
					widget.NewToolbar(
						widget.NewToolbarAction(theme.HelpIcon(), func() {
							if err := fyne.CurrentApp().OpenURL(docUrl); err != nil {
								dialog.ShowError(fmt.Errorf("open link %s failed", docUrl), w)
							}
						}),
					),
				),
			),
		),
	))

	w.SetOnClosed(func() {
		// todo close all and stop if network lost
		if btnStatus == btnRunning { // running can stop
			btnStatus = btnStopping
			btnStart.SetText("Stopping")
			handles.NotifyCloseWrapper()
		}
		saveBasicPreference(wssApp.Preferences(), uiLocalAddr, uiRemoteAddr, uiHttpLocalAddr, uiHttpEnable, uiSkipTSLVerify)
		onVpnClose()
	})
	//w.SetOnClosed() todo
	w.ShowAndRun()
}

// loadVpnUI creates ui for ustb vpn, including auth method selection and the input box.
// it returns callback function: onAppClose for saving preference,
// loadUiValue for loading value from the input box.
func loadVpnUI(wssApp *fyne.App) (*fyne.Container, func() vpn.UstbVpn, func()) {
	// the vpn UI and vpn settings UI
	vpnSettings := VpnSettingsUI{}
	vpnSettings.Init((*wssApp).Preferences())
	vpnUi := vpnSettings.GetContainer()

	loadUiValues := func() vpn.UstbVpn {
		vals := vpn.UstbVpn{
			QrCodeAuth: newQrCodeAuth(wssApp),
			CaptchaHandler: func(imgData []byte) (string, error) {
				// Create a channel to receive the result
				resultChan := make(chan string)
				errChan := make(chan error)

				// Run UI operations on the main thread
				// The threading issue specifically: callbacks from core are not on UI thread.
				// We must use fyne.Do to ensure UI operations are safe.

				fyne.Do(func() {
					// Create image from data
					res := fyne.NewStaticResource("captcha.jpg", imgData)
					img := canvas.NewImageFromResource(res)
					img.FillMode = canvas.ImageFillContain
					img.SetMinSize(fyne.NewSize(400, 160)) // Set a reasonable min size

					entry := widget.NewEntry()
					entry.PlaceHolder = "Enter Captcha"

					content := container.NewVBox(
						img,
						entry,
					)

					d := dialog.NewCustomConfirm("Enter Captcha", "OK", "Cancel", content, func(ok bool) {
						if ok {
							resultChan <- entry.Text
						} else {
							errChan <- fmt.Errorf("captcha input cancelled")
						}
					}, (*wssApp).Driver().AllWindows()[0]) // Assuming the main window is the first one or active one.

					d.Show()
				})

				select {
				case res := <-resultChan:
					return res, nil
				case err := <-errChan:
					return "", err
				}
			},
		}
		vpnSettings.LoadSettingsValues(&vals)
		return vals
	}
	onVpnClose := func() {
		vpnSettings.Save((*wssApp).Preferences())
	}
	return vpnUi, loadUiValues, onVpnClose
}

// NewWSelectWithCopyProxyCommand is copied from widget.NewSelect.
func NewWSelectWithCopyProxyCommand(options []string, changed func(sel *widget.Select, val string)) *widget.Select {
	s := &widget.Select{
		Options:     options,
		PlaceHolder: "(copy proxy command)",
	}
	s.OnChanged = func(val string) {
		changed(s, val)
	}
	s.ExtendBaseWidget(s)
	return s
}

func copyToClipboard(category int, socksAddr string, httpAddr string, win fyne.Window) {
	var text = ""
	var nc = "nc -x" // darwin or linux
	if runtime.GOOS == "windows" {
		nc = "connect -S"
	}
	switch category {
	case ProxyCommandGit:
		text = fmt.Sprintf("export GIT_SSH_COMMAND=\"ssh -o ProxyCommand='%s %s %%h %%p' \"", nc, socksAddr)
		break
	case ProxyCommandHttp:
		text = fmt.Sprintf("export https_proxy=http://%s http_proxy=http://%s", socksAddr, httpAddr)
		break
	case ProxyCommandSsh:
		text = fmt.Sprintf("ssh -o ProxyCommand='%s %s %%h %%p'", nc, socksAddr)
		break
	}
	win.Clipboard().SetContent(text)
}
