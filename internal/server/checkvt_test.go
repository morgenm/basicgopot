package server

import (
	"bytes"
	"crypto/sha256"
	goerrors "errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/morgenm/basicgopot/pkg/config"
	"github.com/morgenm/basicgopot/pkg/errors"
	"github.com/morgenm/basicgopot/pkg/logging"
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
	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalHashTooLong, failed to create the log!: %v`, err)
	}

	expectedErr := &errors.InvalidHashError{}
	hash := string(make([]byte, 100))
	err = checkVirusTotal(nil, log, nil, nil, "", "", hash, "", []byte{})
	if err == nil {
		t.Fatalf(`TestCheckVirusTotalHashTooLong = nil want %v`, expectedErr)
	}

	if err != nil && !goerrors.As(err, &expectedErr) {
		t.Fatalf(`TestCheckVirusTotalHashTooLong = %v, want %v`, err, expectedErr)
	}
}

func TestCheckVirusTotalBadKey(t *testing.T) {
	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalBadKey, failed to create the log!: %v`, err)
	}

	expectedErr := &errors.VirusTotalAPIKeyError{}
	cfg := config.Config{}
	hash := "55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4"
	err = checkVirusTotal(&cfg, log, nil, nil, "", "", hash, "", []byte{})
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

	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalKnownHash, failed to create the log!: %v`, err)
	}

	hash := "55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4" // Define simple file already present on VT
	ul := UploadLog{}
	if err = ul.AddFile("uploadpath", "original", "now", "scan", hash, "Scan"); err != nil {
		t.Fatalf(`TestCheckVirusTotalKnownHash adding file to uploas log returned %v`, err)
	}
	var writer bytes.Buffer

	err = checkVirusTotal(cfg, log, &ul, &writer, "scan", "uploadpath", hash, "", []byte{})
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalKnownHash = %v, want nil`, err)
	}

	if s := writer.String(); s != "" {
		if !strings.Contains(s, "last_submission_date") {
			t.Fatalf(`TestCheckVirusTotalKnownHash invalid output buffer!`)
		}
	} else {
		t.Fatalf(`TestCheckVirusTotalRandomFile nil output!`)
	}
}

// TestCheckVirusTotalKnownHashNoOutput tests checkVirusTotal with a file hash already present on
// vt and doesn't log output.
func TestCheckVirusTotalKnownHashNoOutput(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`TestCheckVirusTotalKnownHashNoOutput with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}
	cfg.UseVirusTotal = true

	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalKnownHashNoOutput, failed to create the log!: %v`, err)
	}

	hash := "55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4" // Define simple file already present on VT
	ul := UploadLog{}
	if err = ul.AddFile("uploadpath", "original", "now", "scan", hash, "Scan"); err != nil {
		t.Fatalf(`TestCheckVirusTotalKnownHashNoOutput adding file to uploas log returned %v`, err)
	}

	err = checkVirusTotal(cfg, log, &ul, nil, "scan", "uploadpath", hash, "", []byte{})
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalKnownHashNoOutput = %v, want nil`, err)
	}
}

// TestCheckVirusTotalRandomFile tests checkVirusTotal with a file hash not yet present on
// vt by generating a random file.
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

	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalRandomFile, failed to create the log!: %v`, err)
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

	ul := UploadLog{}
	if err = ul.AddFile("uploadpath", "original", "now", "scan", hash, "Scan"); err != nil {
		t.Fatalf(`TestCheckVirusTotalKnownHash adding file to uploas log returned %v`, err)
	}
	var writer bytes.Buffer

	err = checkVirusTotal(cfg, log, &ul, &writer, "scan", "uploadpath", hash, "", data)
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalRandomFile = %v, want nil`, err)
	}

	if s := writer.String(); s != "" {
		if !strings.Contains(s, "file_info") {
			t.Fatalf(`TestCheckVirusTotalRandomFile invalid output buffer!`)
		}
	} else {
		t.Fatalf(`TestCheckVirusTotalRandomFile nil output!`)
	}
}

// TestCheckVirusTotalRandomFile tests checkVirusTotal with a file hash not yet present on
// vt by generating a random file and doesn't output the scan.
func TestCheckVirusTotalRandomFileNoOutput(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`TestCheckVirusTotalRandomFileNoOutput with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}

	cfg.UploadVirusTotal = true
	cfg.UseVirusTotal = true

	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalRandomFileNoOutput, failed to create the log!: %v`, err)
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
		t.Fatalf(`TestCheckVirusTotalRandomFileNoOutput test with random file failed when generating random file with error %v`, err)
	}
	hash := fmt.Sprintf("%x", hasher.Sum(nil))

	ul := UploadLog{}
	if err = ul.AddFile("uploadpath", "original", "now", "scan", hash, "Scan"); err != nil {
		t.Fatalf(`TestCheckVirusTotalRandomFileNoOutput adding file to uploas log returned %v`, err)
	}

	err = checkVirusTotal(cfg, log, &ul, nil, "scan", "uploadpath", hash, "", data)
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalRandomFileNoOutput = %v, want nil`, err)
	}
}

// TestCheckVirusTotalRandomFileNoUpload tests checkVirusTotal with a file hash not yet present on
// vt by generating a random file, but does not actually upload it to vt.
func TestCheckVirusTotalRandomFileNoUpload(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`TestCheckVirusTotalRandomFileNoUpload with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}

	cfg.UploadVirusTotal = false
	cfg.UseVirusTotal = true

	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalRandomFileNoUpload, failed to create the log!: %v`, err)
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
		t.Fatalf(`TestCheckVirusTotalRandomFileNoUpload failed when generating random file with error %v`, err)
	}
	hash := fmt.Sprintf("%x", hasher.Sum(nil))

	ul := UploadLog{}
	if err = ul.AddFile("uploadpath", "original", "now", "scan", hash, "Scan"); err != nil {
		t.Fatalf(`TestCheckVirusTotalRandomFileNoUpload adding file to uploas log returned %v`, err)
	}
	var writer bytes.Buffer

	err = checkVirusTotal(cfg, log, &ul, &writer, "scan", "uploadpath", hash, "", data)
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalRandomFileNoUpload = %v, want nil`, err)
	}

	if s := writer.String(); s != "" {
		t.Fatalf(`TestCheckVirusTotalRandomFileNoUpload expected nil buffer output!`)
	}
}

// TestCheckVirusBadUploadLog tests checkVirusTotal with a file hash not yet present on
// vt by generating a random file, but does not add the file to the upload log beforehand.
func TestCheckVirusRandBadUploadLog(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`TestCheckVirusBadUploadLog with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}

	cfg.UploadVirusTotal = true
	cfg.UseVirusTotal = true

	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestCheckVirusBadUploadLog, failed to create the log!: %v`, err)
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
		t.Fatalf(`TestCheckVirusBadUploadLog failed when generating random file with error %v`, err)
	}
	hash := fmt.Sprintf("%x", hasher.Sum(nil))

	ul := UploadLog{}
	var writer bytes.Buffer

	err = checkVirusTotal(cfg, log, &ul, &writer, "scan", "uploadpath", hash, "", data)
	expectedErr := &errors.UploadNotInLog{}
	if !goerrors.As(err, &expectedErr) {
		t.Fatalf(`TestCheckVirusBadUploadLog = %v, want %v`, err, expectedErr)
	}
}

// TestCheckVirusRandTooBig tests checkVirusTotal with a file hash not yet present on
// vt by generating a random file, but the file is too big for uploading.
func TestCheckVirusRandTooBig(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`TestCheckVirusRandTooBig with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}

	cfg.UploadVirusTotal = true
	cfg.UseVirusTotal = true

	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestCheckVirusRandTooBig, failed to create the log!: %v`, err)
	}

	// Generate random bytes to act as our file
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const fileSize = 1024 * 1024 * 64 // Will generate 64 MB of random data
	data := make([]byte, fileSize)
	for i := 0; i < fileSize; i++ {
		data[i] = byte(r.Intn(255 + 1))
	}

	// Get the hash to pass to VT
	hasher := sha256.New()
	_, err = hasher.Write(data)
	if err != nil {
		t.Fatalf(`TestCheckVirusRandTooBig failed when generating random file with error %v`, err)
	}
	hash := fmt.Sprintf("%x", hasher.Sum(nil))

	ul := UploadLog{}
	if err = ul.AddFile("uploadpath", "original", "now", "scan", hash, "Scan"); err != nil {
		t.Fatalf(`TestCheckVirusRandTooBig adding file to uploas log returned %v`, err)
	}

	// Create temporary file for writing....

	err = checkVirusTotal(cfg, log, &ul, nil, "scan", "uploadpath", hash, "", data)
	expectedErr := &errors.FileTooBig{}
	if !goerrors.As(err, &expectedErr) {
		t.Fatalf(`TestCheckVirusRandTooBig = %v, want %v`, err, expectedErr)
	}
}
