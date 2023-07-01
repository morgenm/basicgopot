package server

import (
	"bytes"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/morgenm/basicgopot/pkg/config"
)

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
