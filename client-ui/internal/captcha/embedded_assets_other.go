//go:build !darwin && !windows

package captcha

import "embed"

var (
	//go:embed assets/model/captcha_model.onnx assets/model/captcha_model.onnx.data
	embeddedAssets embed.FS
)
