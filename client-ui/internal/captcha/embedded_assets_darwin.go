//go:build darwin

package captcha

import "embed"

var (
	//go:embed assets/model/captcha_model.onnx assets/model/captcha_model.onnx.data assets/ort/darwin-amd64/libonnxruntime.1.22.0.dylib assets/ort/darwin-arm64/libonnxruntime.1.22.0.dylib
	embeddedAssets embed.FS
)
