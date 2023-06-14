package server

import (
	"testing"
	"github.com/morgenm/basicgopot/internal/config"
)

// Test checkVirusTotal using a filehash already on VT	
func TestCheckVirusTotalKnownHash(t *testing.T) {
	// Quite ugly, but using config.json from top level dir so we
	// have access to the legitimate API key
	cfg, err := config.ReadConfig("../../config.json")
	if err != nil {
		t.Fatalf(`checkVirusTotal with known hash, failed to read config file!`)
	}
	cfg.ScanOutputDir = ""

	// Define simple file already present on VT
	sArr := []byte("test file")
	hash := "55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4"

	err = checkVirusTotal(cfg, hash, 0.01, "out.test", sArr)
	if err != nil {
		t.Fatalf(`checkVirusTotal with known hash = %v, want nil`, err)
	}
}

