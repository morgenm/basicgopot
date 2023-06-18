package vt

import (
	"crypto/sha256"
	"fmt"
	"log"
	"math/rand"
	"testing"
	"time"

	"github.com/morgenm/basicgopot/internal/config"
	"github.com/morgenm/basicgopot/internal/errors"
)

// Test CheckHashVirusTotal using a file hash already on VT.
func TestCheckVirusTotalKnownHash(t *testing.T) {
	// Quite ugly, but using config.json from top level dir so we
	// have access to the legitimate API key
	cfg, err := config.ReadConfig("../../config/config.json")
	if err != nil {
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!`)
	}

	// Define simple file already present on VT
	hash := "55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4"

	reader, err := CheckHashVirusTotal(cfg.VirusTotalApiKey, hash)
	if err != nil {
		t.Fatalf(`TestCheckVirusTotalKnownHash = nil, %v, want io.ReadCloser, nil`, err)
	} else if reader == nil && err == nil {
		t.Fatalf(`TestCheckVirusTotalKnownHash = nil, nil, want io.ReadCloser, nil`)
	}
}

// Test CheckHashVirusTotal with a randomly generated file, not on VT.
func TestCheckHashVirusTotalRandomFile(t *testing.T) {
	// Quite ugly, but using config.json from top level dir so we
	// have access to the legitimate API key
	cfg, err := config.ReadConfig("../../config/config.json")
	if err != nil {
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!`)
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
	log.Print(hash)

	reader, err := CheckHashVirusTotal(cfg.VirusTotalApiKey, hash)
	if err != nil {
		t.Fatalf(`TestCheckHashVirusTotalRandomFile = nil, %v, want nil, nil`, err)
	} else if reader != nil {
		t.Fatalf(`TestCheckHashVirusTotalRandomFile = %v, nil, want nil, nil`, reader)
	}
}

// Test UploadFileVirusTotal with a randomly generated file, not on VT.
func TestUploadFileVirusTotalRandomFile(t *testing.T) {
	// Quite ugly, but using config.json from top level dir so we
	// have access to the legitimate API key
	cfg, err := config.ReadConfig("../../config/config.json")
	if err != nil {
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!`)
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

	_, err = UploadFileVirusTotal(cfg.VirusTotalApiKey, hash, fileSize/(1024*1024), "random.test", data)
	if err != nil {
		t.Fatalf(`TestUploadFileVirusTotalRandomFile = nil, %v, want io.ReadCloser, nil`, err)
	}
}

// Test UploadFileVirusTotal with a randomly generated file, not on VT, that is too large to upload.
func TestUploadFileVirusTotalRandomFileTooBig(t *testing.T) {
	// Quite ugly, but using config.json from top level dir so we
	// have access to the legitimate API key
	cfg, err := config.ReadConfig("../../config/config.json")
	if err != nil {
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!`)
	}

	// Generate random bytes to act as our file
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const fileSize = 1024 * 1024 * 33 // Generate 33 MBs
	data := make([]byte, fileSize)
	for i := 0; i < fileSize; i++ {
		data[i] = byte(r.Intn(255 + 1))
	}

	// Get the hash to pass to VT
	hasher := sha256.New()
	_, err = hasher.Write(data)
	if err != nil {
		t.Fatalf(`checkVirusTotal test with too big random file failed when generating random file with error %v`, err)
	}
	hash := fmt.Sprintf("%x", hasher.Sum(nil))

	_, err = UploadFileVirusTotal(cfg.VirusTotalApiKey, hash, fileSize/(1024*1024), "random.test", data)
	if err == nil {
		t.Fatalf(`TestUploadFileVirusTotalRandomFileTooBig = nil, nil, want nil, %v`, &errors.FileTooBig{})
	}
}