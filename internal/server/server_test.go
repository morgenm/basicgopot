package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/morgenm/basicgopot/pkg/config"
)

// TestCreateScanWriter tests that a scan writer can be created and written to in a test dir.
func TestCreateScanWriter(t *testing.T) {
	tmpDirScans := t.TempDir()
	cfg := config.Config{
		ScanOutputDir: tmpDirScans,
	}

	writer, filepath, err := createScanWriter(&cfg)
	if err != nil {
		t.Fatalf(`TestCreateScanWriter = %v, want nil`, err)
	}

	// Check if file was created.
	if _, err := os.Stat(filepath); errors.Is(err, os.ErrNotExist) {
		t.Fatalf(`TestCreateScanWriter did not create scan file!`)
	}

	// Check if write works.
	if b, err := writer.Write([]byte{1, 2, 3}); err == nil {
		if b != 3 {
			t.Fatalf(`TestCreateScanWriter tried to write %d bytes, but ended up writing %d`, 3, b)
		}
	} else {
		t.Fatalf(`TestCreateScanWriter failed writing with %v!`, err)
	}
}

// TestCreateScanWriterBad tests creating a scan with an invalid path.
func TestCreateScanWriterBad(t *testing.T) {
	cfg := config.Config{
		ScanOutputDir: "::::bad:path////",
	}

	_, _, err := createScanWriter(&cfg)
	if err == nil {
		t.Fatalf(`TestCreateScanWriter = nil, want error`)
	}
}

func TestServerUploadNoSaveNoVTNoWH(t *testing.T) {
	cfg := config.Config{}
	ul := UploadLog{}
	h := FileUploadHandler{
		cfg:       &cfg,
		uploadLog: &ul,
	}

	// Generate random bytes to act as our file
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const fileSize = 1024 * 512 // Will generate half a MB of random data
	data := make([]byte, fileSize)
	for i := 0; i < fileSize; i++ {
		data[i] = byte(r.Intn(255 + 1))
	}

	// Create form file for upload
	buf := new(bytes.Buffer)
	reader := bytes.NewReader(data) // Create bytes reader for data
	writer := multipart.NewWriter(buf)
	formFile, err := writer.CreateFormFile("fileupload", "filename")
	if err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoVTNoWH failed with %v`, err)
	}

	if _, err = io.Copy(formFile, reader); err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoVTNoWH failed with %v`, err)
	}
	if err = writer.Close(); err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoVTNoWH failed with %v`, err)
	}

	// Make POST request
	req, err := http.NewRequest("POST", "/upload", buf)
	if err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoVTNoWH failed with %v`, err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.ServeHTTP)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("TestServerUploadNoSaveNoVTNoWH Unexpected status code. Expected: %d, Got: %d", http.StatusSeeOther, rr.Code)
	}
}

func TestServerUploadNoSaveNoWH(t *testing.T) {
	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`TestServerUploadNoSaveNoWH with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}
	cfg.UseVirusTotal = true
	cfg.UploadVirusTotal = true
	cfg.WebHookDir = ""
	cfg.ScanOutputDir = ""
	cfg.UploadLog = ""
	cfg.UploadsDir = ""
	cfg.UploadWebHooks = make(map[string]config.WebHookConfig) // Empty webhooks

	ul := UploadLog{}
	h := FileUploadHandler{
		cfg:       cfg,
		uploadLog: &ul,
	}

	// Generate random bytes to act as our file
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const fileSize = 1024 * 512 // Will generate half a MB of random data
	data := make([]byte, fileSize)
	for i := 0; i < fileSize; i++ {
		data[i] = byte(r.Intn(255 + 1))
	}

	// Create form file for upload
	buf := new(bytes.Buffer)
	reader := bytes.NewReader(data) // Create bytes reader for data
	writer := multipart.NewWriter(buf)
	formFile, err := writer.CreateFormFile("fileupload", "filename")
	if err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoWH failed with %v`, err)
	}

	if _, err = io.Copy(formFile, reader); err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoWH failed with %v`, err)
	}
	if err = writer.Close(); err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoWH failed with %v`, err)
	}

	// Make POST request
	req, err := http.NewRequest("POST", "/upload", buf)
	if err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoWH failed with %v`, err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.ServeHTTP)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("TestServerUploadNoSaveNoWH Unexpected status code. Expected: %d, Got: %d", http.StatusSeeOther, rr.Code)
	}
}

func TestServerUploadNoWH(t *testing.T) {
	// Create temp dir for uploads
	tmpDirUploads := t.TempDir()

	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`TestServerUploadNoWH with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}
	cfg.UseVirusTotal = true
	cfg.UploadVirusTotal = true
	cfg.WebHookDir = ""
	cfg.ScanOutputDir = ""
	cfg.UploadLog = ""
	cfg.UploadsDir = tmpDirUploads
	cfg.UploadWebHooks = make(map[string]config.WebHookConfig) // Empty webhooks

	ul := UploadLog{}
	h := FileUploadHandler{
		cfg:       cfg,
		uploadLog: &ul,
	}

	// Generate random bytes to act as our file
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const fileSize = 1024 * 512 // Will generate half a MB of random data
	data := make([]byte, fileSize)
	for i := 0; i < fileSize; i++ {
		data[i] = byte(r.Intn(255 + 1))
	}

	// Create form file for upload
	buf := new(bytes.Buffer)
	reader := bytes.NewReader(data) // Create bytes reader for data
	writer := multipart.NewWriter(buf)
	formFile, err := writer.CreateFormFile("fileupload", "filename")
	if err != nil {
		t.Fatalf(`TestServerUploadNoWH failed with %v`, err)
	}

	if _, err = io.Copy(formFile, reader); err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoWH failed with %v`, err)
	}
	if err = writer.Close(); err != nil {
		t.Fatalf(`TestServerUploadNoWH failed with %v`, err)
	}

	// Make POST request
	req, err := http.NewRequest("POST", "/upload", buf)
	if err != nil {
		t.Fatalf(`TestServerUploadNoWH failed with %v`, err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.ServeHTTP)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("TestServerUploadNoWH Unexpected status code. Expected: %d, Got: %d", http.StatusSeeOther, rr.Code)
	}

	// Ensure upload file was saved correctly
	var uploadPath string
	for u := range ul.uploads {
		uploadPath = u
		break
	}
	if len(uploadPath) == 0 {
		t.Fatalf("TestServerUploadNoWH no uploads found in UploadLog!")
	}
	f, err := os.Open(uploadPath)
	if err != nil {
		t.Fatalf(`TestServerUploadNoWH could not open the saved upload at %s!`, uploadPath)
	}
	defer f.Close()

	uploadRead := make([]byte, fileSize)
	_, err = f.Read(uploadRead)
	if err != nil {
		t.Fatalf("TestServerUploadNoWH could not read the saved upload!")
	}

	if !bytes.Equal(uploadRead, data) {
		t.Fatalf("TestServerUploadNoWH saved file doesn't match!")
	}
}

func TestCreateAndRunHTTPServer(t *testing.T) {
	cfg := &config.Config{}

	configPath := os.Getenv("BASICGOPOT_CONFIG_FILE")

	if configPath == "" {
		// Quite ugly, but using config.json from top level dir so we
		// have access to the legitimate API key
		configPath = "../../config/config.json"
	}

	cfg, err := config.ReadConfigFromFile(configPath)
	if err != nil {
		pwd, _ := os.Getwd()
		t.Fatalf(`TestServerUploadNoSaveNoWH with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}

	cfg.UseVirusTotal = true
	cfg.UploadVirusTotal = true
	cfg.WebHookDir = ""
	cfg.ScanOutputDir = ""
	cfg.UploadLog = ""
	cfg.UploadsDir = ""
	cfg.UploadWebHooks = make(map[string]config.WebHookConfig)
	testWebHook := config.WebHookConfig{}
	cfg.UploadWebHooks["TestWebHook"] = testWebHook

	// Create HTTP server.
	httpServer, err := CreateHTTPServer(cfg)
	if err != nil {
		t.Fatalf("TestCreateAndRunHTTPServer CreateHTTPServer = %v!", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)

	// Run HTTP server.
	go func() {
		defer wg.Done()
		httpServer.RunServer(cfg)
	}()

	// Test connection to server.
	client := &http.Client{}
	url := "http://localhost:" + fmt.Sprint(cfg.ServerPort) + "/upload"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("TestCreateAndRunHTTPServer error creating GET request to server = %v!", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("TestCreateAndRunHTTPServer error in GET request to server = %v!", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("TestCreateAndRunHTTPServer GET request status code = %d, not 200!", resp.StatusCode)
	}

	// Shutdown and wait for HTTP server.
	httpServer.StopServer()
	wg.Wait()
}
