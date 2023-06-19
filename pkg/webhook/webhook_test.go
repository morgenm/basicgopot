package webhook

import (
	"bytes"
	"testing"

	"github.com/morgenm/basicgopot/pkg/config"
)

// Test NewWebHook using an empty WebHookConfig and empty map.
func TestNewWebHookEmpty(t *testing.T) {
	c := config.WebHookConfig{}
	w := NewWebHook(c, make(map[string][]byte))
	if w == nil {
		t.Fatalf("TestNewWebHookEmpty = %v, expected WebHook", w)
	}
}

// Test NewWebHook using some valid data.
func TestNewWebHook(t *testing.T) {
	c := config.WebHookConfig{
		URL:     "google.com/",
		Method:  "POST",
		Headers: "Authorization: Bearer",
		Data:    "TEST $FILE $FILE TEST",
	}

	webHookStrings := make(map[string][]byte)
	webHookStrings["$FILE"] = []byte{1, 2, 3, 4}

	w := NewWebHook(c, webHookStrings)
	if w == nil {
		t.Fatalf("TestNewWebHookEmpty = %v, expected WebHook", w)
	}

	expectedData := []byte{}
	expectedData = append(expectedData, []byte("TEST ")...)
	expectedData = append(expectedData, webHookStrings["$FILE"]...)
	expectedData = append(expectedData, " "...)
	expectedData = append(expectedData, webHookStrings["$FILE"]...)
	expectedData = append(expectedData, " TEST"...)
	if !bytes.Equal(w.DataBytes, expectedData) {
		t.Fatalf("TestNewWebHookEmpty DataBytes do not match!")
	}
}
