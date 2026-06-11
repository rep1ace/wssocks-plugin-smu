package captcha

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	xdraw "golang.org/x/image/draw"

	ort "github.com/yalue/onnxruntime_go"
)

const (
	modelFileName      = "captcha_model.onnx"
	modelDataFileName  = "captcha_model.onnx.data"
	modelInputName     = "image"
	modelOutputName    = "digits"
	modelWidth         = 80
	modelHeight        = 20
	modelChannels      = 3
	modelOutputDigits  = 4
	modelDigitClasses  = 10
	modelAssetVersion  = "smu-captcha-model-onnx-v1"
	ortLibraryVersion  = "1.22.0"
	cacheDirName       = "wssocks-plugin-smu"
	cacheCaptchaSubdir = "captcha-runtime"
)

var (
	defaultRecognizerOnce sync.Once
	defaultRecognizer     *Recognizer
	defaultRecognizerErr  error

	envInitOnce sync.Once
	envInitErr  error
)

type Recognizer struct {
	mu           sync.Mutex
	session      *ort.AdvancedSession
	inputTensor  *ort.Tensor[float32]
	outputTensor *ort.Tensor[float32]
}

type runtimeAssets struct {
	modelPath   string
	libraryPath string
}

func NewRecognizer() (*Recognizer, error) {
	assets, err := prepareRuntimeAssets()
	if err != nil {
		return nil, err
	}
	if err := initializeEnvironment(assets.libraryPath); err != nil {
		return nil, err
	}

	inputTensor, err := ort.NewEmptyTensor[float32](ort.NewShape(1, modelChannels, modelHeight, modelWidth))
	if err != nil {
		return nil, fmt.Errorf("create input tensor: %w", err)
	}

	outputTensor, err := ort.NewEmptyTensor[float32](ort.NewShape(1, modelOutputDigits, modelDigitClasses))
	if err != nil {
		inputTensor.Destroy()
		return nil, fmt.Errorf("create output tensor: %w", err)
	}

	session, err := ort.NewAdvancedSession(
		assets.modelPath,
		[]string{modelInputName},
		[]string{modelOutputName},
		[]ort.Value{inputTensor},
		[]ort.Value{outputTensor},
		nil,
	)
	if err != nil {
		outputTensor.Destroy()
		inputTensor.Destroy()
		return nil, fmt.Errorf("create ONNX session: %w", err)
	}

	return &Recognizer{
		session:      session,
		inputTensor:  inputTensor,
		outputTensor: outputTensor,
	}, nil
}

func Predict(imageBytes []byte) (string, error) {
	defaultRecognizerOnce.Do(func() {
		defaultRecognizer, defaultRecognizerErr = NewRecognizer()
	})
	if defaultRecognizerErr != nil {
		return "", defaultRecognizerErr
	}
	return defaultRecognizer.Predict(imageBytes)
}

func (r *Recognizer) Predict(imageBytes []byte) (string, error) {
	img, err := decodeImage(imageBytes)
	if err != nil {
		return "", err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	fillInputTensor(r.inputTensor.GetData(), img)
	if err := r.session.Run(); err != nil {
		return "", fmt.Errorf("run ONNX session: %w", err)
	}

	return decodeOutput(r.outputTensor.GetData())
}

func (r *Recognizer) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.session != nil {
		r.session.Destroy()
		r.session = nil
	}
	if r.inputTensor != nil {
		r.inputTensor.Destroy()
		r.inputTensor = nil
	}
	if r.outputTensor != nil {
		r.outputTensor.Destroy()
		r.outputTensor = nil
	}
	return nil
}

func initializeEnvironment(libraryPath string) error {
	envInitOnce.Do(func() {
		ort.SetSharedLibraryPath(libraryPath)
		envInitErr = ort.InitializeEnvironment()
	})
	if envInitErr != nil {
		return fmt.Errorf("initialize ONNX Runtime environment: %w", envInitErr)
	}
	return nil
}

func prepareRuntimeAssets() (runtimeAssets, error) {
	cacheRoot, err := os.UserCacheDir()
	if err != nil || cacheRoot == "" {
		cacheRoot = os.TempDir()
	}
	targetDir := filepath.Join(
		cacheRoot,
		cacheDirName,
		cacheCaptchaSubdir,
		modelAssetVersion,
		runtime.GOOS+"-"+runtime.GOARCH,
	)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return runtimeAssets{}, fmt.Errorf("create runtime cache dir: %w", err)
	}

	modelPath := filepath.Join(targetDir, modelFileName)
	modelDataPath := filepath.Join(targetDir, modelDataFileName)
	libraryPath := filepath.Join(targetDir, platformLibraryName())

	if err := writeEmbeddedFile("assets/model/"+modelFileName, modelPath, 0o644); err != nil {
		return runtimeAssets{}, err
	}
	if err := writeEmbeddedFile("assets/model/"+modelDataFileName, modelDataPath, 0o644); err != nil {
		return runtimeAssets{}, err
	}

	libraryAssetPath, err := platformLibraryAssetPath()
	if err != nil {
		return runtimeAssets{}, err
	}
	if err := writeEmbeddedFile(libraryAssetPath, libraryPath, 0o755); err != nil {
		return runtimeAssets{}, err
	}

	return runtimeAssets{
		modelPath:   modelPath,
		libraryPath: libraryPath,
	}, nil
}

func writeEmbeddedFile(assetPath, destination string, mode os.FileMode) error {
	data, err := embeddedAssets.ReadFile(assetPath)
	if err != nil {
		return fmt.Errorf("read embedded asset %s: %w", assetPath, err)
	}
	if err := os.WriteFile(destination, data, mode); err != nil {
		return fmt.Errorf("write runtime asset %s: %w", destination, err)
	}
	return nil
}

func platformLibraryAssetPath() (string, error) {
	switch {
	case runtime.GOOS == "windows" && runtime.GOARCH == "amd64":
		return "assets/ort/windows-amd64/onnxruntime.dll", nil
	case runtime.GOOS == "darwin" && runtime.GOARCH == "amd64":
		return "assets/ort/darwin-amd64/libonnxruntime.1.22.0.dylib", nil
	case runtime.GOOS == "darwin" && runtime.GOARCH == "arm64":
		return "assets/ort/darwin-arm64/libonnxruntime.1.22.0.dylib", nil
	default:
		return "", fmt.Errorf("automatic CAPTCHA recognition is unsupported on %s/%s", runtime.GOOS, runtime.GOARCH)
	}
}

func platformLibraryName() string {
	if runtime.GOOS == "windows" {
		return "onnxruntime.dll"
	}
	return "libonnxruntime." + ortLibraryVersion + ".dylib"
}

func decodeImage(imageBytes []byte) (image.Image, error) {
	if len(imageBytes) == 0 {
		return nil, errors.New("empty CAPTCHA image")
	}
	img, _, err := image.Decode(bytes.NewReader(imageBytes))
	if err != nil {
		return nil, fmt.Errorf("decode CAPTCHA image: %w", err)
	}
	return img, nil
}

func fillInputTensor(input []float32, src image.Image) {
	dst := image.NewRGBA(image.Rect(0, 0, modelWidth, modelHeight))
	xdraw.ApproxBiLinear.Scale(dst, dst.Bounds(), src, src.Bounds(), xdraw.Over, nil)

	channelStride := modelWidth * modelHeight
	for y := 0; y < modelHeight; y++ {
		for x := 0; x < modelWidth; x++ {
			rgba := color.RGBAModel.Convert(dst.At(x, y)).(color.RGBA)
			pixelIndex := y*modelWidth + x
			input[pixelIndex] = float32(rgba.R) / 255.0
			input[channelStride+pixelIndex] = float32(rgba.G) / 255.0
			input[2*channelStride+pixelIndex] = float32(rgba.B) / 255.0
		}
	}
}

func decodeOutput(output []float32) (string, error) {
	if len(output) != modelOutputDigits*modelDigitClasses {
		return "", fmt.Errorf("unexpected output size: got %d", len(output))
	}

	result := make([]byte, modelOutputDigits)
	for digitIndex := 0; digitIndex < modelOutputDigits; digitIndex++ {
		start := digitIndex * modelDigitClasses
		bestClass := 0
		bestValue := output[start]
		for classIndex := 1; classIndex < modelDigitClasses; classIndex++ {
			value := output[start+classIndex]
			if value > bestValue {
				bestValue = value
				bestClass = classIndex
			}
		}
		result[digitIndex] = byte('0' + bestClass)
	}
	return string(result), nil
}
