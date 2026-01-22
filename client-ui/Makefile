# makefile for crossing building on macOS
# supported os: windows, macOS

# make sure fyne is installed before packaging (see: https://developer.fyne.io/started/packaging).

PHONY: clean all package package-windows

PACKAGE=github.com/rep1ace/wssocks-plugin-smu/client-ui
FLAGS=--trimpath
appID=wssocks-smu-client-ui.rep1ace.github.com
appName="wssocks-smu client"
APP_VERSION=0.7.0
PACKAGE_FLAG=-icon app-512.png -appID ${appID} --appVersion ${APP_VERSION} -release -appBuild 5

all: wssocks-smu-ui-macOS-amd64 wssocks-smu-ui-macOS-arm64 wssocks-smu-ui-windows-amd64.exe # wssocks-smu-ui-linux-amd64

wssocks-smu-ui-macOS-amd64:
	CC=clang CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build ${FLAGS} -o wssocks-smu-ui-macOS-amd64 ${PACKAGE}

wssocks-smu-ui-macOS-arm64:
	CC=clang CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build ${FLAGS} -o wssocks-smu-ui-macOS-arm64 ${PACKAGE}

wssocks-smu-ui-windows-amd64.exe:
	CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build ${FLAGS} -ldflags "-H=windowsgui" -o wssocks-smu-ui-windows-amd64.exe ${PACKAGE}

wssocks-smu-ui-macOS-universal: wssocks-smu-ui-macOS-amd64 wssocks-smu-ui-macOS-arm64
	lipo wssocks-smu-ui-macOS-amd64 wssocks-smu-ui-macOS-arm64 -create -output wssocks-smu-ui-macOS-universal

# wssocks-smu-ui-linux-amd64:
# 	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o wssocks-smu-ui-linux-amd64 ${PACKAGE}

# packaging
package: client-ui-macOS-universal.app client-ui-windows-amd64.exe # client-ui-linux-amd64

client-ui-macOS-universal.app: wssocks-smu-ui-macOS-universal
	CC=clang CGO_ENABLED=1 GOOS=darwin fyne package -os darwin ${PACKAGE_FLAG} -executable wssocks-smu-ui-macOS-universal -name ${appName}
	rm -rf client-ui-macOS-universal.app; mv ${appName}.app client-ui-macOS-universal.app

client-ui-windows-amd64.exe: wssocks-smu-ui-windows-amd64.exe
	CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 GOOS=windows GOARCH=amd64 fyne package -os windows ${PACKAGE_FLAG} -executable wssocks-smu-ui-windows-amd64.exe -name ${appName}.exe
	mv ${appName}.exe client-ui-windows-amd64.exe

# export CGO_CFLAGS='-D _POSIX'

# client-ui-linux-amd64:

clean:
	rm -rf wssocks-smu-ui-macOS-amd64 wssocks-smu-ui-macOS-arm64 wssocks-smu-ui-macOS-universal wssocks-smu-ui-windows-amd64.exe client-ui-macOS-universal.app client-ui-windows-amd64.exe
	rm -rf wssocks-smu-client fyne.syso

package-windows:
	CC=x86_64-w64-mingw32-gcc CGO_ENABLED=1 fyne package --target windows --icon app-512.png --name "wssocks-smu-client" --app-id wssocks-smu-client-ui.rep1ace.github.com --release