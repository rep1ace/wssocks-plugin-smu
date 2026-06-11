package main

import (
	_ "embed"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/rep1ace/wssocks-plugin-smu/client-ui/internal/captcha"
	resource "github.com/rep1ace/wssocks-plugin-smu/client-ui/resources"
	"github.com/rep1ace/wssocks-plugin-smu/extra"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn"
	"github.com/rep1ace/wssocks-plugin-smu/plugins/vpn/passwd"
	pluginversion "github.com/rep1ace/wssocks-plugin-smu/wssocks-ustb/version"
	"github.com/rep1ace/wssocks/client"
	"github.com/rep1ace/wssocks/version"
	log "github.com/sirupsen/logrus"
)

const (
	AppName           = "WSSocks SMU Client"
	AppId             = "wssocks-smu-client-ui.rep1ace.github.com"
	CoreGithubRepoUrl = "https://github.com/rep1ace/wssocks"
	GithubRepoUrl     = "https://github.com/rep1ace/wssocks-plugin-smu"
	DocumentUrl       = "https://github.com/rep1ace/wssocks-plugin-smu/tree/master/docs"
	MutexName         = "Global\\wssocks-plugin-smu-client-ui"
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

var localLockListener net.Listener

func acquireLocalLock() bool {
	var err error
	localLockListener, err = net.Listen("tcp", "127.0.0.1:37539")
	if err != nil {
		return false
	}
	return true
}

func main() {
	if !acquireLocalLock() {
		// show a simple error dialog or just exit
		// Since we can't easily show a dialog without an app instance, we'll try to create a temp one
		// or just exit. A temp app instance for just a dialog is fine.
		app := app.New()
		w := app.NewWindow("Error")
		w.SetContent(widget.NewLabel("Another instance is already running."))
		w.SetFixedSize(true)
		w.Resize(fyne.NewSize(300, 100))
		w.CenterOnScreen()
		// Show the window and close it after a short delay or let user close it?
		// Usually showing an error and waiting for user close is better.
		w.Show()
		// We use a timer to auto-close to avoid hanging if the user doesn't see it (optional, but requested behavior was just "detect")
		// But usually "exit nicely" implies notifying the user.
		// Let's just run it.
		// app.Run() would block.
		// Let's just exit for now as per minimal requirement, or better:
		// Just return, effectively exiting. The user might miss it if silent.
		// But creating a full Fyne app just to say "error" might be slow/overkill?
		// Actually, standard behavior is silent exit or focus focus existing.
		// Focusing existing is hard cross-platform.
		// Let's just logging and exit for CLI, or maybe a quick dialog.
		// Given the simplicity, let's just return for now to ensure it works.
		// If I want to be nice:
		// fmt.Println("Another instance is running.")
		return
	}
	// Defer close not strictly necessary as OS cleans up on exit, but good practice.
	if localLockListener != nil {
		defer localLockListener.Close()
	}

	wssApp := app.NewWithID(AppId)
	wssApp.Settings().SetTheme(&myTheme{})
	wssApp.SetIcon(fyne.NewStaticResource("icon", appIconData))

	w := wssApp.NewWindow(AppName)
	//w.SetFixedSize(true)
	//w.Resize(fyne.NewSize(100, 100))

	// basic input
	uiLocalAddr := &widget.Entry{PlaceHolder: "socks5 listen address", Text: "127.0.0.1:1080"}
	uiRemoteAddr := &widget.Entry{PlaceHolder: "WSSocks server address"}
	uiAuthToken := &widget.Entry{PlaceHolder: "the token for proxy authentication", Password: true}
	uiHttpEnable := newCheckbox("", false, nil)
	uiHttpLocalAddr := &widget.Entry{PlaceHolder: "http listen address", Text: "127.0.0.1:1086"}
	uiSkipTSLVerify := newCheckbox("", false, nil)
	uiSaveToken := newCheckbox("save token", false, nil)

	loadBasicPreference(wssApp.Preferences(), uiLocalAddr, uiRemoteAddr, uiHttpLocalAddr, uiAuthToken, uiHttpEnable, uiSkipTSLVerify, uiSaveToken)

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
	statusLabel := widget.NewLabel("State: stopped")
	statusLabel.Wrapping = fyne.TextWrapWord

	btnStatus := btnStopped
	var handles extra.TaskHandles
	var ignoreWaitErr = true
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			state, reason := handles.CurrentState()
			text := "State: " + strings.ReplaceAll(state, "_", " ")
			if text == "State: " {
				text = "State: stopped"
			}
			if reason != "" {
				text += " - " + reason
			}
			fyne.Do(func() {
				statusLabel.SetText(text)
			})
		}
	}()
	btnStart.OnTapped = func() {
		if btnStatus == btnRunning { // running can stop
			btnStatus = btnStopping
			ignoreWaitErr = true
			btnStart.SetText("Stopping")
			handles.NotifyCloseWrapper()
			btnStart.SetText("Start")
			btnStatus = btnStopped
		} else if btnStatus == btnStopped { // stopped can run
			if vpnUiValue := onLoadValue(); vpnUiValue.Enable && vpnUiValue.PasswdAuth.Password == "" {
				dialog.ShowInformation("Error", "Please input vpn password", w)
				return
			}
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
		{Text: "", Widget: uiSaveToken},
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
			container.NewTabItem("Basic", widget.NewCard("", "WSSocks settings", basicUi)),
			container.NewTabItem("SMU VPN", container.NewVBox(
				widget.NewCard("", "SMU VPN settings", vpnUi)),
			),
		),
		btnStart,
		statusLabel,
		selectCopyProxyCommand,
		&widget.Separator{},
		container.NewGridWithColumns(2,
			container.NewHBox(
				NewHyperlinkIcon(resource.GithubIcon(), coreRepoUrl),
				widget.NewHyperlink("WSSocks core: ", coreRepoUrl),
			),
			widget.NewLabel("v"+version.VERSION),
		),
		container.NewGridWithColumns(2,
			container.NewHBox(
				NewHyperlinkIcon(resource.GithubIcon(), repoUrl),
				widget.NewHyperlink("SMU VPN plugin: ", repoUrl),
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

	savePreferences := func() {
		if btnStatus == btnRunning { // running can stop
		}
		saveBasicPreference(wssApp.Preferences(), uiLocalAddr, uiRemoteAddr, uiHttpLocalAddr, uiAuthToken, uiHttpEnable, uiSkipTSLVerify, uiSaveToken)
		onVpnClose()
	}

	if desk, ok := wssApp.(desktop.App); ok {
		m := fyne.NewMenu(AppName,
			fyne.NewMenuItem("Show Window", func() {
				w.Show()
			}),
			fyne.NewMenuItem("Copy Proxy Command", nil),
			fyne.NewMenuItem("Exit", func() {
				// Stop if running
				if btnStatus == btnRunning {
					btnStatus = btnStopping
					btnStart.SetText("Stopping")
					handles.NotifyCloseWrapper()
				}
				savePreferences()
				wssApp.Quit()
			}),
		)
		m.Items[1].ChildMenu = fyne.NewMenu("",
			fyne.NewMenuItem("Git", func() {
				copyToClipboard(ProxyCommandGit, uiLocalAddr.Text, uiHttpLocalAddr.Text, w)
			}),
			fyne.NewMenuItem("HTTP/HTTPS", func() {
				copyToClipboard(ProxyCommandHttp, uiLocalAddr.Text, uiHttpLocalAddr.Text, w)
			}),
			fyne.NewMenuItem("SSH/SFTP/SCP", func() {
				copyToClipboard(ProxyCommandSsh, uiLocalAddr.Text, uiHttpLocalAddr.Text, w)
			}),
		)
		desk.SetSystemTrayMenu(m)
		desk.SetSystemTrayWindow(w)
	}

	w.SetCloseIntercept(func() {
		savePreferences()
		w.Hide()
	})

	w.SetOnClosed(func() {
		// todo close all and stop if network lost
		if btnStatus == btnRunning { // running can stop
			btnStatus = btnStopping
			btnStart.SetText("Stopping")
			handles.NotifyCloseWrapper()
		}
		savePreferences()
	})
	//w.SetOnClosed() todo
	w.ShowAndRun()
}

// loadVpnUI creates ui for SMU vpn, including auth method selection and the input box.
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
				result, err := captcha.Predict(imgData)
				if err == nil {
					return result, nil
				}
				log.WithError(err).Warn("automatic CAPTCHA recognition failed, falling back to manual input")
				return promptCaptchaInput(wssApp, imgData)
			},
			PhoneVerificationHandler: func(challenge passwd.PhoneVerificationChallenge) (string, error) {
				return promptPhoneVerificationInput(wssApp, challenge)
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

func promptCaptchaInput(wssApp *fyne.App, imgData []byte) (string, error) {
	resultChan := make(chan string, 1)
	errChan := make(chan error, 1)

	fyne.Do(func() {
		res := fyne.NewStaticResource("captcha.jpg", imgData)
		img := canvas.NewImageFromResource(res)
		img.FillMode = canvas.ImageFillContain
		img.SetMinSize(fyne.NewSize(400, 160))

		entry := widget.NewEntry()
		entry.PlaceHolder = "Enter Captcha"

		content := container.NewVBox(img, entry)

		windows := (*wssApp).Driver().AllWindows()
		if len(windows) == 0 {
			errChan <- fmt.Errorf("no window available for captcha input")
			return
		}

		var d dialog.Dialog
		d = dialog.NewCustomConfirm("Enter Captcha", "OK", "Cancel", content, func(ok bool) {
			if ok {
				resultChan <- entry.Text
			} else {
				errChan <- fmt.Errorf("captcha input cancelled")
			}
		}, windows[0])

		entry.OnSubmitted = func(_ string) {
			resultChan <- entry.Text
			d.Hide()
		}

		d.Show()
		windows[0].Canvas().Focus(entry)
	})

	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errChan:
		return "", err
	}
}

func promptPhoneVerificationInput(wssApp *fyne.App, challenge passwd.PhoneVerificationChallenge) (string, error) {
	resultChan := make(chan string, 1)
	errChan := make(chan error, 1)

	fyne.Do(func() {
		phoneText := challenge.Phone
		if phoneText == "" {
			phoneText = "bound phone"
		}

		entry := widget.NewEntry()
		entry.PlaceHolder = "SMS Code"

		content := container.NewVBox(
			widget.NewLabel(fmt.Sprintf("Code sent to %s", phoneText)),
			entry,
		)

		windows := (*wssApp).Driver().AllWindows()
		if len(windows) == 0 {
			errChan <- fmt.Errorf("no window available for phone verification input")
			return
		}

		var d dialog.Dialog
		d = dialog.NewCustomConfirm("Phone Verification", "OK", "Cancel", content, func(ok bool) {
			if ok {
				resultChan <- entry.Text
			} else {
				errChan <- fmt.Errorf("phone verification input cancelled")
			}
		}, windows[0])

		entry.OnSubmitted = func(_ string) {
			resultChan <- entry.Text
			d.Hide()
		}

		d.Show()
		windows[0].Canvas().Focus(entry)
	})

	select {
	case result := <-resultChan:
		return result, nil
	case err := <-errChan:
		return "", err
	}
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
	var ncCmdType = "ncat"
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
		if runtime.GOOS == "windows" && ncCmdType == "ncat" {
			text = fmt.Sprintf("ssh -o ProxyCommand='ncat --proxy %s --proxy-type socks5 %%h %%p'", socksAddr)
		} else {
			text = fmt.Sprintf("ssh -o ProxyCommand='%s %s %%h %%p'", nc, socksAddr)
		}
		break
	}
	win.Clipboard().SetContent(text)
}
