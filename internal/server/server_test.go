package server

import (
	"testing"
	"github.com/morgenm/basicgopot/internal/config"
	"github.com/morgenm/basicgopot/internal/errors"
	goerrors "errors"
)

func TestCheckVirusTotalEmptyHash(t *testing.T) {
	cfg := config.Config {
		8080,
		10,
		true,
		true,
		"test",
	}

	s := "test file"
	sArr := []byte(s)

	err := checkVirusTotal(&cfg, "", 0.01, "out.test", sArr)
	if err == nil {
		t.Fatalf(`checkVirusTotal with empty hash = nil, want error`)
	} else if e := new(errors.InvalidHashError); !goerrors.As(err, &e) {
		t.Fatalf(`checkVirusTotal with empty hash = %v, want %v`, err, e)
	}
}