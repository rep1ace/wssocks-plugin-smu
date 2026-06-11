//go:build windows

package captcha

import "embed"

var (
	//go:embed assets/model/captcha_model.onnx assets/model/captcha_model.onnx.data assets/ort/windows-amd64/onnxruntime.dll
	embeddedAssets embed.FS
)
