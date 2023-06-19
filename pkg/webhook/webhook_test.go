package webhook

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
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
		URL:    "google.com/",
		Method: "POST",
		Headers: map[string]string{
			"Authorization": "Bearer",
		},
		Data: "TEST $FILE $FILE TEST",
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

// Test Execute for POST request by spawning a webserver and receiving data.
func TestExecutePOST(t *testing.T) {
	c := config.WebHookConfig{
		Method: "POST",
		Headers: map[string]string{
			"Authorization": "Bearer",
		},
		Data: "TEST $FILE $FILE TEST",
	}

	webHookStrings := make(map[string][]byte)
	webHookStrings["$FILE"] = []byte{1, 2, 3, 4}
	webHook := NewWebHook(c, webHookStrings)

	// Create test server for receiving and validating WebHook POST request.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate the headers
		hasAuth := false
		for _, header := range r.Header["Authorization"] {
			if header == "Bearer" {
				hasAuth = true
			}
		}
		if !hasAuth {
			t.Fatalf(`TestExecutePOST: missing Authorization header`)
		}

		// Validate that the request has the file.
		formFile, _, err := r.FormFile("file")
		if err != nil {
			t.Fatalf(`TestExecutePOST: error on getting form %v`, err)
		}

		fileContent, err := io.ReadAll(formFile)
		if err != nil {
			t.Fatalf(`TestExecutePOST: error on reading file from form %v`, err)
		}

		// Validate that the file was correctly uploaded.
		expectedFileContent := []byte("TEST ")
		expectedFileContent = append(expectedFileContent, webHookStrings["$FILE"]...)
		expectedFileContent = append(expectedFileContent, " "...)
		expectedFileContent = append(expectedFileContent, webHookStrings["$FILE"]...)
		expectedFileContent = append(expectedFileContent, " TEST"...)
		if !bytes.Equal(fileContent, expectedFileContent) {
			t.Fatalf(`TestExecutePOST: the uploaded file does not match the expected value!`)
		}

		// Create a mock response
		response := []byte(`{"resp": "Test response"}`)

		// Set the response headers
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Write the response body
		_, err = w.Write(response)
		if err != nil {
			t.Fatal(err)
		}
	}))
	defer ts.Close()

	webHook.URL = ts.URL

	// See if the response in the WebHook matches what we sent.
	reader, err := webHook.Execute()
	if err != nil {
		t.Fatalf("TestExecutePOST = %v, %v. Expected io.ReadCloser, nil", reader, err)
	}

	resp, err := io.ReadAll(*reader)
	if err != nil {
		t.Fatalf("TestExecutePOST failed reading response in WebHook!")
	}

	expectedResponse := []byte(`{"resp": "Test response"}`)
	if !bytes.Equal(expectedResponse, resp) {
		t.Fatalf("TestExecutePOST responses do not match!")
	}
}
