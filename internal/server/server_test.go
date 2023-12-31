package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/morgenm/basicgopot/pkg/config"
	"github.com/morgenm/basicgopot/pkg/logging"
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

// TestGetPageDataBad tests getting page data for a page that doesn't exist.
func TestGetPageDataBad(t *testing.T) {
	pageData, err := GetPageData("::::bad:path////", "Default str")
	if err != nil {
		t.Fatalf(`TestGetPageDataBad = %v, want nil`, err)
	}

	if !bytes.Equal([]byte("Default str"), pageData) {
		t.Fatalf(`TestGetPageDataBad returned unexpected data = %s, want Default str`, pageData)
	}
}

// TestGetPageData tests getting page data for a page that does exist.
func TestGetPageData(t *testing.T) {
	// Create page data file.
	tmpDir := t.TempDir()
	pageStr := "404 page data"
	pageDataPath := filepath.Join(tmpDir, "data.html")
	f, err := os.Create(pageDataPath)
	if err != nil {
		t.Fatalf(`TestGetPageData create file = %v, want nil`, err)
	}

	if _, err = f.WriteString(pageStr); err != nil {
		t.Fatalf(`TestGetPageData write file = %v, want nil`, err)
	}

	if err = f.Close(); err != nil {
		t.Fatalf(`TestGetPageData close file = %v, want nil`, err)
	}

	pageData, err := GetPageData(pageDataPath, "Default str")
	if err != nil {
		t.Fatalf(`TestGetPageData = %v, want nil`, err)
	}

	if !bytes.Equal([]byte(pageStr), pageData) {
		t.Fatalf(`TestGetPageDataBad returned unexpected data = %s, want %s`, pageData, pageStr)
	}
}

// TestServerUploadNoSaveNoVTNoWH tests uploading a random file without saving, without submitting to VT, and
// without any WebHooks.
func TestServerUploadNoSaveNoVTNoWH(t *testing.T) {
	cfg := config.Config{
		UploadLimitMB: 512,
	}
	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoWH failed to create the log!: %v`, err)
	}

	ul := UploadLog{}
	h := FileUploadHandler{
		cfg:       &cfg,
		uploadLog: &ul,
		log:       log,
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

	if rr.Code != http.StatusOK {
		t.Fatalf("TestServerUploadNoSaveNoVTNoWH Unexpected status code. Expected: %d, Got: %d", http.StatusOK, rr.Code)
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
	cfg.UploadLimitMB = 512
	cfg.UseVirusTotal = true
	cfg.UploadVirusTotal = true
	cfg.WebHookDir = ""
	cfg.ScanOutputDir = ""
	cfg.UploadLog = ""
	cfg.UploadsDir = ""
	cfg.UploadWebHooks = make(map[string]config.WebHookConfig) // Empty webhooks

	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoWH with known hash, failed to create the log!: %v`, err)
	}

	ul := UploadLog{}
	h := FileUploadHandler{
		cfg:       cfg,
		uploadLog: &ul,
		log:       log,
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

	if rr.Code != http.StatusOK {
		t.Fatalf("TestServerUploadNoSaveNoWH Unexpected status code. Expected: %d, Got: %d", http.StatusOK, rr.Code)
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
	cfg.UploadLimitMB = 512
	cfg.UseVirusTotal = true
	cfg.UploadVirusTotal = true
	cfg.WebHookDir = ""
	cfg.ScanOutputDir = ""
	cfg.UploadLog = ""
	cfg.UploadsDir = tmpDirUploads
	cfg.UploadWebHooks = make(map[string]config.WebHookConfig) // Empty webhooks

	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoWH with known hash, failed to create the log!: %v`, err)
	}

	ul := UploadLog{}
	h := FileUploadHandler{
		cfg:       cfg,
		uploadLog: &ul,
		log:       log,
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

	if rr.Code != http.StatusOK {
		t.Fatalf("TestServerUploadNoWH Unexpected status code. Expected: %d, Got: %d", http.StatusOK, rr.Code)
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

// TestServerUploadTooBigNoWH tests file upload functionality by uploading a file
// that is higher than the configured max file size.
func TestServerUploadTooBigNoWH(t *testing.T) {
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
	cfg.UploadLimitMB = 1
	cfg.UseVirusTotal = true
	cfg.UploadVirusTotal = true
	cfg.WebHookDir = ""
	cfg.ScanOutputDir = ""
	cfg.UploadLog = ""
	cfg.UploadsDir = tmpDirUploads
	cfg.UploadWebHooks = make(map[string]config.WebHookConfig) // Empty webhooks

	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoWH with known hash, failed to create the log!: %v`, err)
	}

	ul := UploadLog{}
	h := FileUploadHandler{
		cfg:       cfg,
		uploadLog: &ul,
		log:       log,
	}

	// Generate random bytes to act as our file
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const fileSize = 2 << 20 // Will generate 2 MB of random data, which is more than the upload limit.
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

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("TestServerUploadNoWH Unexpected status code. Expected: %d, Got: %d", http.StatusBadRequest, rr.Code)
	}
}

// TestServerUploadNoWHBadScanDir tests file uploading with an invalid scan directory. We still expect
// everything to work correctly expect scan output.
func TestServerUploadNoWHBadScanDir(t *testing.T) {
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
		t.Fatalf(`TestServerUploadNoWHBadScanDir with known hash, failed to read config file!: %v at pwd of %v`, err, pwd)
	}
	cfg.UploadLimitMB = 512
	cfg.UseVirusTotal = true
	cfg.UploadVirusTotal = true
	cfg.WebHookDir = ""
	cfg.ScanOutputDir = "::::bad:path////"
	cfg.UploadLog = ""
	cfg.UploadsDir = tmpDirUploads
	cfg.UploadWebHooks = make(map[string]config.WebHookConfig) // Empty webhooks

	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoWH with known hash, failed to create the log!: %v`, err)
	}

	ul := UploadLog{}
	h := FileUploadHandler{
		cfg:       cfg,
		uploadLog: &ul,
		log:       log,
	}

	// Generate random bytes to act as our file
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const fileSize = 1024 * 500 // Will generate half a MB of random data
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
		t.Fatalf(`TestServerUploadNoWHBadScanDir failed with %v`, err)
	}

	if _, err = io.Copy(formFile, reader); err != nil {
		t.Fatalf(`TestServerUploadNoWHBadScanDir failed with %v`, err)
	}
	if err = writer.Close(); err != nil {
		t.Fatalf(`TestServerUploadNoWHBadScanDir failed with %v`, err)
	}

	// Make POST request
	req, err := http.NewRequest("POST", "/upload", buf)
	if err != nil {
		t.Fatalf(`TestServerUploadNoWHBadScanDir failed with %v`, err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.ServeHTTP)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("TestServerUploadNoWHBadScanDir Unexpected status code. Expected: %d, Got: %d", http.StatusOK, rr.Code)
	}

	// Ensure upload file was saved correctly
	var uploadPath string
	for u := range ul.uploads {
		uploadPath = u
		break
	}
	if len(uploadPath) == 0 {
		t.Fatalf("TestServerUploadNoWHBadScanDir no uploads found in UploadLog!")
	}
	f, err := os.Open(uploadPath)
	if err != nil {
		t.Fatalf(`TestServerUploadNoWHBadScanDir could not open the saved upload at %s!`, uploadPath)
	}
	defer f.Close()

	uploadRead := make([]byte, fileSize)
	_, err = f.Read(uploadRead)
	if err != nil {
		t.Fatalf("TestServerUploadNoWHBadScanDir could not read the saved upload!")
	}

	if !bytes.Equal(uploadRead, data) {
		t.Fatalf("TestServerUploadNoWHBadScanDir saved file doesn't match!")
	}
}

// TestCreateAndRunHTTPServer creates an HTTP server, runs it, and does a simple GET request to check if it is up.
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

	// Create log
	logger, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestServerUploadNoSaveNoWH with known hash, failed to create the log!: %v`, err)
	}
	cfg.UploadLimitMB = 512
	cfg.UseVirusTotal = true
	cfg.UploadVirusTotal = true
	cfg.WebHookDir = ""
	cfg.ScanOutputDir = ""
	cfg.UploadLog = ""
	cfg.UploadsDir = ""
	cfg.UploadWebHooks = make(map[string]config.WebHookConfig)
	testWebHook := config.WebHookConfig{}
	cfg.UploadWebHooks["TestWebHook"] = testWebHook

	// Get ephemeral port in a hacky way.
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("TestCreateAndRunHTTPServer net.Listen = %v!", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	cfg.ServerPort = port

	// Create HTTP server.
	httpServer, err := CreateHTTPServer(cfg, logger)
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

	// Test connection to server. Since no web content is being served in this test, GET upload which should return 400.
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
	if resp.StatusCode != 405 {
		t.Fatalf("TestCreateAndRunHTTPServer GET request status code = %d, not 405!", resp.StatusCode)
	}

	// Shutdown and wait for HTTP server.
	httpServer.StopServer()
	wg.Wait()
}

// TestWriteWebHookResponseToFile tests writing a sample WebHook response to a file.
func TestWriteWebHookResponseToFile(t *testing.T) {
	cfg := &config.Config{
		WebHookDir: t.TempDir(),
	}

	b := []byte{1, 2, 3, 4, 5}
	reader := bytes.NewBuffer(b)

	webHookFilename := "TestWebHook"

	err := writeWebHookResponseToFile(cfg, reader, webHookFilename)
	if err != nil {
		t.Fatalf("TestWriteWebHookResponseToFile error writing file = %v", err)
	}
}

// TestWriteWebHookResponseToFileBadDir tests writing a sample WebHook response to a non existing directory.
func TestWriteWebHookResponseToFileBadDir(t *testing.T) {
	cfg := &config.Config{
		WebHookDir: "::::bad:path////",
	}

	b := []byte{1, 2, 3, 4, 5}
	reader := bytes.NewBuffer(b)

	webHookFilename := "TestWebHook"

	err := writeWebHookResponseToFile(cfg, reader, webHookFilename)
	if err == nil || !strings.Contains(err.Error(), "no such file or directory") {
		t.Fatalf("TestWriteWebHookResponseToFile error writing file = %v, want no such file or directory", err)
	}
}

// TestServeHTTPFileServerHandler tests the FileServerHandler.
func TestServeHTTPFileServerHandler(t *testing.T) {
	// Create log
	log, err := logging.New("")
	if err != nil {
		t.Fatalf(`TestServeHTTPFileServerHandler failed to create log %v`, err)
	}

	// Create fs for the handler
	fsDir := t.TempDir()
	fsys := os.DirFS(fsDir)
	fileServer := http.FileServer(http.FS(fsys))

	// Create handler
	h := FileServerHandler{
		fsys:       &fsys,
		log:        log,
		fileServer: fileServer,
	}

	// Request index, which will always be a 200.
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatalf(`TestServeHTTPFileServerHandler failed to create request with %v`, err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(h.ServeHTTP)

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("TestServeHTTPFileServerHandler Unexpected status code. Expected: %d, Got: %d", http.StatusOK, rr.Code)
	}

	// Request a page that doesn't exist, which will return 404.
	req, err = http.NewRequest("GET", "/doesnotexist", nil)
	if err != nil {
		t.Fatalf(`TestServeHTTPFileServerHandler failed to create request with %v`, err)
	}
	rr = httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("TestServeHTTPFileServerHandler Unexpected status code. Expected: %d, Got: %d", http.StatusNotFound, rr.Code)
	}

	// Make a bad request.
	req, err = http.NewRequest("GET", "///badrequest", nil)
	if err != nil {
		t.Fatalf(`TestServeHTTPFileServerHandler failed to create request with %v`, err)
	}
	rr = httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("TestServeHTTPFileServerHandler Unexpected status code. Expected: %d, Got: %d", http.StatusBadRequest, rr.Code)
	}
}
