package captcha

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPredictSample(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skip("automatic CAPTCHA recognition is only packaged for Windows and macOS")
	}

	data, err := os.ReadFile(filepath.Join("testdata", "0001_5489.png"))
	if err != nil {
		t.Fatalf("read sample image: %v", err)
	}

	result, err := Predict(data)
	if err != nil {
		t.Fatalf("predict sample captcha: %v", err)
	}
	if result != "5489" {
		t.Fatalf("unexpected prediction: got %q want %q", result, "5489")
	}
}
