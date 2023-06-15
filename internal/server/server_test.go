package server

import (
	"crypto/sha256"
	goerrors "errors"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/morgenm/basicgopot/internal/config"
	"github.com/morgenm/basicgopot/internal/errors"
)

// Test checkVirusTotal using a filehash already on VT
func TestCheckVirusTotalKnownHash(t *testing.T) {
	// Quite ugly, but using config.json from top level dir so we
	// have access to the legitimate API key
	cfg, err := config.ReadConfig("../../config.json")
	if err != nil {
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!`)
	}

	cfg.ScanOutputDir = "" // Don't output scans

	// Define simple file already present on VT
	sArr := []byte("test file")
	hash := "55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4"

	err = checkVirusTotal(cfg, hash, 0.01, "out.test", sArr)
	if err != nil {
		t.Fatalf(`checkVirusTotal with known hash = %v, want nil`, err)
	}
}

// Test checkVirusTotal with a randomly generated file, not on VT
func TestCheckVirusTotalRandomFile(t *testing.T) {
	// Quite ugly, but using config.json from top level dir so we
	// have access to the legitimate API key
	cfg, err := config.ReadConfig("../../config.json")
	if err != nil {
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!`)
	}

	cfg.ScanOutputDir = "" // Don't output scans

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

	err = checkVirusTotal(cfg, hash, fileSize/(1024*1024), "out.test", data)
	if err != nil {
		t.Fatalf(`checkVirusTotal with random file = %v, want nil`, err)
	}
}

// Test checkVirusTotal with a randomly generated file, not on VT, that is too large to upload
func TestCheckVirusTotalRandomFileTooBig(t *testing.T) {
	// Quite ugly, but using config.json from top level dir so we
	// have access to the legitimate API key
	cfg, err := config.ReadConfig("../../config.json")
	if err != nil {
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!`)
	}

	cfg.ScanOutputDir = "" // Don't output scans

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

	err = checkVirusTotal(cfg, hash, fileSize/(1024*1024), "out.test", data)
	expected := &errors.FileTooBig{}
	if !goerrors.As(err, &expected) {
		t.Fatalf(`checkVirusTotal with random file = %v, want %v`, err, &errors.FileTooBig{})
	}
}
