
PACKAGE_PATH := github.com/rep1ace/wssocks-plugin-smu/client-ui
APP_NAME     := wssocks-smu-client
APP_ID       := wssocks-smu-client-ui.rep1ace.github.com
VERSION      := 0.7.0
BUILD_NUM    := 5
ICON         := app-512.png

CC_WIN       := x86_64-w64-mingw32-gcc
CC_MAC       := clang
FYNE         := fyne

GOFLAGS      := -trimpath
LDFLAGS_WIN  := -H=windowsgui
PKG_FLAGS    := -icon $(ICON) -appID $(APP_ID) -appVersion $(VERSION) -appBuild $(BUILD_NUM) -release


.PHONY: all clean package package-windows package-mac

all: package


# macOS AMD64 Binary
bin-mac-amd64:
	CC=$(CC_MAC) CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build $(GOFLAGS) -o wssocks-smu-ui-macOS-amd64 $(PACKAGE_PATH)

# macOS ARM64 Binary
bin-mac-arm64:
	CC=$(CC_MAC) CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -o wssocks-smu-ui-macOS-arm64 $(PACKAGE_PATH)

# macOS Universal Binary
bin-mac-universal: bin-mac-amd64 bin-mac-arm64
	lipo wssocks-smu-ui-macOS-amd64 wssocks-smu-ui-macOS-arm64 -create -output wssocks-smu-ui-macOS-universal

# Windows AMD64 Binary
bin-win-amd64:
	CC=$(CC_WIN) CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS_WIN)" -o wssocks-smu-ui-windows-amd64.exe $(PACKAGE_PATH)

bin-linux-amd64:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o wssocks-smu-ui-linux-amd64 $(PACKAGE_PATH)


package: package-mac package-windows package-linux


package-windows: bin-win-amd64
	$(FYNE) package -os windows $(PKG_FLAGS) -executable wssocks-smu-ui-windows-amd64.exe -name $(APP_NAME).exe
	mv $(APP_NAME).exe client-ui-windows-amd64.exe
	@echo "✅ Windows package created: client-ui-windows-amd64.exe"


package-mac: bin-mac-universal
	$(FYNE) package -os darwin $(PKG_FLAGS) -executable wssocks-smu-ui-macOS-universal -name $(APP_NAME)
	rm -rf client-ui-macOS-universal.app
	mv $(APP_NAME).app client-ui-macOS-universal.app
	@echo "✅ macOS package created: client-ui-macOS-universal.app"

package-linux: bin-linux-amd64
	@echo "✅ Linux binary ready: wssocks-smu-ui-linux-amd64"


clean:
	rm -rf wssocks-smu-ui-* client-ui-* *.app *.exe fyne.syso