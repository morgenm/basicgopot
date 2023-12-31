package vt

import (
	"crypto/sha256"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	goerrors "errors"

	"github.com/morgenm/basicgopot/pkg/config"
	"github.com/morgenm/basicgopot/pkg/errors"
)

// TestCheckHashVirusTotalKnownHash tests CheckHashVirusTotal using a file hash already on VT.
func TestCheckHashVirusTotalKnownHash(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}

	// Define simple file already present on VT
	hash := "55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4"

	reader, err := CheckHashVirusTotal(cfg.VirusTotalApiKey, hash)
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalKnownHash = %v, %v, want io.ReadCloser, nil`, reader, err)
	}
}

// TestCheckHashVirusTotalKnownHashBadKey tests CheckHashVirusTotal using a file hash already on VT and an invalid key.
func TestCheckHashVirusTotalKnownHashBadKey(t *testing.T) {
	cfg := config.Config{
		UseVirusTotal:    true,
		UploadVirusTotal: false,
		VirusTotalApiKey: "badkey",
	}

	// Define simple file already present on VT
	hash := "55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4"

	reader, err := CheckHashVirusTotal(cfg.VirusTotalApiKey, hash)
	expectedErr := &errors.VirusTotalAPIKeyError{}
	if !goerrors.As(err, &expectedErr) || reader != nil {
		t.Fatalf(`TestCheckHashVirusTotalKnownHashBadKey = %v, %v, want nil, %v`, reader, err, expectedErr)
	}
}

// TestCheckHashVirusTotalHashTooLong tests CheckHashVirusTotal using a bad file hash that is too long.
func TestCheckHashVirusTotalHashTooLong(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}

	// Define simple file already present on VT
	hash := "55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180ba12345"

	reader, err := CheckHashVirusTotal(cfg.VirusTotalApiKey, hash)
	expectedErr := &errors.InvalidHashError{}
	if !goerrors.As(err, &expectedErr) || reader != nil {
		t.Fatalf(`TestCheckHashVirusTotalHashTooLong = %v, %v, want io.ReadCloser, nil`, reader, err)
	}
}

// TestCheckHashVirusTotalHashBad tests CheckHashVirusTotal using a hash with invalid chars.
func TestCheckHashVirusTotalHashBad(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}

	// Define simple file already present on VT
	hash := "lol8718109829bf5wab09d8af615b9f107a266e19f7a311039d1035f180b22d4"

	reader, err := CheckHashVirusTotal(cfg.VirusTotalApiKey, hash)
	expectedErr := &errors.InvalidHashError{}
	if !goerrors.As(err, &expectedErr) || reader != nil {
		t.Fatalf(`TestCheckHashVirusTotalHashBad = %v, %v, want io.ReadCloser, nil`, reader, err)
	}
}

// Test CheckHashVirusTotal with a randomly generated file, not on VT.
func TestCheckHashVirusTotalRandomFile(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}

	// Generate random bytes to act as our file
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const fileSize = 1024 * 512 // Will generate half a MB of random data
	data := make([]byte, fileSize)
	for i := 0; i < fileSize; i++ {
		data[i] = byte(r.Intn(255 + 1))
	}

	// Get the hash to pass to VT
	hasher := sha256.New()
	_, err = hasher.Write(data)
	if err != nil {
		t.Fatalf(`checkVirusTotal test with random file failed when generating random file with error %v`, err)
	}
	hash := fmt.Sprintf("%x", hasher.Sum(nil))

	reader, err := CheckHashVirusTotal(cfg.VirusTotalApiKey, hash)
	errHashNotFound := &errors.VirusTotalHashNotFound{}
	if err != nil && !goerrors.As(err, &errHashNotFound) {
		t.Fatalf(`TestCheckHashVirusTotalRandomFile = %v, %v, want nil, %v`, reader, err, errHashNotFound)
	}
}

// Test UploadFileVirusTotal with a randomly generated file, not on VT.
func TestUploadFileVirusTotalRandomFile(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}

	// Generate random bytes to act as our file
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const fileSize = 1024 * 512 // Will generate half a MB of random data
	data := make([]byte, fileSize)
	for i := 0; i < fileSize; i++ {
		data[i] = byte(r.Intn(255 + 1))
	}

	_, err = UploadFileVirusTotal(cfg.VirusTotalApiKey, "random.test", data)
	if err != nil {
		t.Fatalf(`TestUploadFileVirusTotalRandomFile = nil, %v, want io.ReadCloser, nil`, err)
	}
}

// Test UploadFileVirusTotal with a randomly generated file, not on VT, that is too large to upload.
func TestUploadFileVirusTotalRandomFileTooBig(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}

	// Generate random bytes to act as our file
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const fileSize = 1024 * 1024 * 33 // Generate 33 MBs
	data := make([]byte, fileSize)
	for i := 0; i < fileSize; i++ {
		data[i] = byte(r.Intn(255 + 1))
	}

	_, err = UploadFileVirusTotal(cfg.VirusTotalApiKey, "random.test", data)
	if err == nil {
		t.Fatalf(`TestUploadFileVirusTotalRandomFileTooBig = nil, nil, want nil, %v`, &errors.FileTooBig{})
	}
}

// Fuzz UploadFileVirusTotal.
func FuzzUploadFileVirusTotal(f *testing.F) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		f.Fatalf(`checkVirusTotal with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}

	f.Add("KEY", []byte{1, 2, 3, 4, 5, 6, 7})
	f.Fuzz(func(t *testing.T, fileName string, data []byte) {
		fileSize := len(data) / (1024 * 1024)
		reader, err := UploadFileVirusTotal(cfg.VirusTotalApiKey, fileName, data)
		errFileTooBig := &errors.FileTooBig{}
		if (!goerrors.As(err, &errFileTooBig) || reader != nil) && fileSize > 32 {
			t.Fatalf(`TestCheckVirusTotalFuzz = %v, %v, want nil, FileTooBig`, reader, err)
		} else if reader == nil || err != nil {
			t.Fatalf(`TestCheckVirusTotalFuzz = %v, %v, want reader, nil`, reader, err)
		}
	})
}
