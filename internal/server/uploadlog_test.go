package server

import (
	"testing"
)

// Test adding file data
func TestAddFileTest(t *testing.T) {
	u := &UploadLog{
		logPath: "",
	}

	if err := u.AddFile("uploads/test.txt", "Whenever", "scans/scan.json", "123", "Results"); err != nil {
		t.Fatalf(`testAddFile empty = %v, want nil`, err)
	}

	// This is what the upload vals should look like since we are passing empty data
	uploadVals := map[string]interface{}{
		"Time Uploaded": "Whenever",
		"Scan File":     "scans/scan.json",
		"File Hash":     "123",
		"Scan Type":     "Results", // Results for file already in VT, Analysis for queued/new upload
	}

	// Actual values
	var retVals map[string]interface{} = u.uploads["uploads/test.txt"].(map[string]interface{})

	for key, val := range uploadVals {
		if retVals[key] != val {
			t.Fatalf(`testAddFile empty failed, uploads[%v] = %v, want %v`, key, u.uploads[key], val)
		}
	}
}

// Test adding repeat file

// Test updating
