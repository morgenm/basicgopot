package server

import (
	"encoding/json"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/morgenm/basicgopot/pkg/errors"
)

// Test adding file data.
func TestAddFileTest(t *testing.T) {
	u := &UploadLog{
		logPath: "",
	}

	if err := u.AddFile("uploads/test.txt", "localhost", "original.txt", "Whenever", "scans/scan.json", "123", "Results"); err != nil {
		t.Fatalf(`testAddFileTest = %v, want nil`, err)
	}

	// This is what the upload vals should look like since we are passing empty data.
	uploadVals := map[string]interface{}{
		"Time Uploaded":     "Whenever",
		"Original Filename": "original.txt",
		"Uploader IP":       "localhost",
		"Scan File":         "scans/scan.json",
		"File Hash":         "123",
		"Scan Type":         "Results", // Results for file already in VT, Analysis for queued/new upload.
	}

	// Actual values
	var retVals map[string]interface{} = u.uploads["uploads/test.txt"].(map[string]interface{})

	for key, val := range uploadVals {
		if retVals[key] != val {
			t.Fatalf(`testAddFile empty failed, uploads[%v] = %v, want %v`, key, u.uploads[key], val)
		}
	}
}

// Test adding repeat file.
func TestAddRepeatFile(t *testing.T) {
	u := &UploadLog{
		logPath: "",
	}

	if err := u.AddFile("uploads/test.txt", "localhost", "original.txt", "Now", "scans/scan1.json", "321", "Analysis"); err != nil {
		t.Fatalf(`testUpdateFileTest repeat add file failed on first file = %v, want nil`, err)
	}

	if err := u.AddFile("uploads/test.txt", "localhost", "new.txt", "Whenever", "scans/scan.json", "123", "Results"); err == nil {
		t.Fatalf(`testAddFileTest repeat add existing file = nil, want %v`, &errors.UploadAlreadyInLog{})
	}
}

// Test updating.
func TestUpdateFileTest(t *testing.T) {
	u := &UploadLog{
		logPath: "",
	}

	if err := u.AddFile("uploads/test.txt", "localhost", "original.txt", "Now", "scans/scan1.json", "321", "Analysis"); err != nil {
		t.Fatalf(`testUpdateFileTest adding new file = %v, want nil`, err)
	}

	if err := u.UpdateFile("uploads/test.txt", "localhost", "new.txt", "Whenever", "scans/scan.json", "123", "Results"); err != nil {
		t.Fatalf(`testUpdateFileTest updating existing file = %v, want nil`, err)
	}

	// This is what the upload vals should look like since we are passing empty data.
	uploadVals := map[string]interface{}{
		"Time Uploaded":     "Whenever",
		"Original Filename": "new.txt",
		"Scan File":         "scans/scan.json",
		"File Hash":         "123",
		"Scan Type":         "Results", // Results for file already in VT, Analysis for queued/new upload.
	}

	// Actual values
	var retVals map[string]interface{} = u.uploads["uploads/test.txt"].(map[string]interface{})

	for key, val := range uploadVals {
		if retVals[key] != val {
			t.Fatalf(`testAddFile empty failed, uploads[%v] = %v, want %v`, key, uploadVals[key], val)
		}
	}
}

// Test updating scan path and type.
func TestUpdateFileScan(t *testing.T) {
	u := &UploadLog{
		logPath: "",
	}

	if err := u.AddFile("uploads/test.txt", "localhost", "original.txt", "Now", "scans/scan1.json", "321", "Analysis"); err != nil {
		t.Fatalf(`testUpdateFileScan adding new file = %v, want nil`, err)
	}

	if err := u.UpdateFileScan("uploads/test.txt", "scans/scan2.json", "Report"); err != nil {
		t.Fatalf(`testUpdateFileScan updating existing file = %v, want nil`, err)
	}

	// This is what the upload vals should look like since we are passing empty data.
	uploadVals := map[string]interface{}{
		"Time Uploaded":     "Now",
		"Original Filename": "original.txt",
		"Scan File":         "scans/scan2.json",
		"File Hash":         "321",
		"Scan Type":         "Report", // Results for file already in VT, Analysis for queued/new upload.
	}

	// Actual values.
	var retVals map[string]interface{} = u.uploads["uploads/test.txt"].(map[string]interface{})

	for key, val := range uploadVals {
		if retVals[key] != val {
			t.Fatalf(`testUpdateFileScan failed, uploads[%v] = %v, want %v`, key, uploadVals[key], val)
		}
	}
}

// TestSaveFileTest tests saving to file without actually writing.
func TestSaveFileTest(t *testing.T) {
	u := &UploadLog{
		logPath: "",
	}

	if err := u.AddFile("uploads/test.txt", "localhost", "original.txt", "Now", "scans/scan1.json", "321", "Analysis"); err != nil {
		t.Fatalf(`testSaveFileTest add file failed = %v, want nil`, err)
	}

	if err := u.SaveFile(); err != nil {
		t.Fatalf(`testSaveFileTest failed on save file = %v, want nil`, err)
	}
}

// TestSaveFile tests saving to file.
func TestSaveFile(t *testing.T) {
	u := &UploadLog{
		logPath: filepath.Join(t.TempDir(), "log.log"),
	}

	if err := u.AddFile("uploads/test.txt", "localhost", "original.txt", "Now", "scans/scan1.json", "321", "Analysis"); err != nil {
		t.Fatalf(`TestSaveFile add file failed = %v, want nil`, err)
	}

	if err := u.SaveFile(); err != nil {
		t.Fatalf(`TestSaveFile failed on save file = %v, want nil`, err)
	}

	// Read file to ensure saving was successful
	f, err := os.Open(u.logPath)
	if err != nil {
		t.Fatalf(`TestSaveFile failed to open file: %v`, err)
	}
	defer f.Close()

	bytes := make([]byte, 1024)
	numBytes, err := f.Read(bytes)
	if err != nil {
		t.Fatalf("TestSaveFile could not read the saved log file!")
	} else if numBytes == 0 {
		t.Fatalf("TestSaveFile read 0 bytes from saved log file!")
	}

	if !strings.Contains(string(bytes), "uploads/test.txt") {
		t.Fatalf("TestSaveFile invalid log file output!")
	}
}

// FuzzLoadFromBytes fuzzes the input bytes for loading the UploadLog.
func FuzzLoadFromBytes(f *testing.F) {
	// Generate random bytes to act as fuzz seed.
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const dataSeedSize = 1024 * 1024 * 10 // Generate 10 MBs to test loading a good amount of data.
	dataSeed := make([]byte, dataSeedSize)
	for i := 0; i < dataSeedSize; i++ {
		dataSeed[i] = byte(r.Intn(255 + 1))
	}

	f.Add(dataSeed)
	f.Fuzz(func(t *testing.T, data []byte) {
		u := &UploadLog{}

		err := u.loadFromBytes(data)
		if err == nil {
			t.Fatalf(`FuzzReadConfigFromFile = nil, want error`)
		}
	})
}

// TestLoadFromBytesLarge tests loading a valid, but very large upload log.
func TestLoadFromBytesLarge(t *testing.T) {
	u := &UploadLog{}
	uploadSample := map[string]interface{}{
		"Time Uploaded":     "Now",
		"Original Filename": "original.txt",
		"Scan File":         "scans/scan2.json",
		"File Hash":         "321",
		"Scan Type":         "Report", // Results for file already in VT, Analysis for queued/new upload
	}
	uploads := make(map[string]interface{})

	// Add lots of uploads
	const numUploads = 10000 // Number of uploads to add
	for i := 0; i < numUploads; i++ {
		fileName := strconv.Itoa(i)
		uploads[fileName] = uploadSample
	}

	uploadsJson, _ := json.Marshal(uploads)

	if err := u.loadFromBytes(uploadsJson); err != nil {
		t.Fatalf(`TestLoadFromBytesLarge = %v, want nil`, err)
	}
}
