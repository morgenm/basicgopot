package server

import (
	"bytes"
	"crypto/sha256"
	goerrors "errors"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/morgenm/basicgopot/pkg/config"
	"github.com/morgenm/basicgopot/pkg/errors"
)

func TestWriteVTResult(t *testing.T) {
	buf := []byte("hello test")
	reader := bytes.NewReader(buf)
	var writer bytes.Buffer

	if err := writeVTResult(reader, &writer); err != nil {
		t.Fatalf(`TestWriteVTResult = %v, want nil`, err)
	}

	if !bytes.Equal(buf, writer.Bytes()) {
		t.Fatalf(`TestWriteVTResult in and out buffers don't match! %v %v`, buf, writer.Bytes())
	}
}

func TestCheckVirusTotalHashTooLong(t *testing.T) {
	expectedErr := &errors.InvalidHashError{}
	hash := string(make([]byte, 100))
	err := checkVirusTotal(nil, nil, nil, "", "", hash, "", []byte{})
	if err == nil {
		t.Fatalf(`TestCheckVirusTotalHashTooLong = nil want %v`, expectedErr)
	}

	if err != nil && !goerrors.As(err, &expectedErr) {
		t.Fatalf(`TestCheckVirusTotalHashTooLong = %v, want %v`, err, expectedErr)
	}
}

func TestCheckVirusTotalBadKey(t *testing.T) {
	expectedErr := &errors.VirusTotalAPIKeyError{}
	cfg := config.Config{}
	hash := "55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4"
	err := checkVirusTotal(&cfg, nil, nil, "", "", hash, "", []byte{})
	if err == nil {
		t.Fatalf(`TestCheckVirusTotalBadKey = nil want %v`, expectedErr)
	}

	if err != nil && !goerrors.As(err, &expectedErr) {
		t.Fatalf(`TestCheckVirusTotalBadKey = %v, want %v`, err, expectedErr)
	}
}

func TestCheckVirusTotalKnownHash(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`TestCheckVirusTotalKnownHash with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}
	cfg.UseVirusTotal = true

	hash := "55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4" // Define simple file already present on VT
	ul := UploadLog{}
	ul.AddFile("uploadpath", "original", "now", "scan", hash, "Scan")
	var writer bytes.Buffer

	err = checkVirusTotal(cfg, &ul, &writer, "scan", "uploadpath", hash, "", []byte{})
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalKnownHash = %v, want nil`, err)
	}
}

func TestCheckVirusTotalRandomFile(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`TestCheckVirusTotalRandomFile with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}

	cfg.UploadVirusTotal = true
	cfg.UseVirusTotal = true

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

	ul := UploadLog{}
	ul.AddFile("uploadpath", "original", "now", "scan", hash, "Scan")
	var writer bytes.Buffer

	err = checkVirusTotal(cfg, &ul, &writer, "scan", "uploadpath", hash, "", data)
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalRandomFile = %v, want nil`, err)
	}
}
