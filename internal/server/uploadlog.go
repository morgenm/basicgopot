package server

import (
	"sync"

	"github.com/morgenm/basicgopot/internal/errors"
)

type UploadLog struct {
	logPath string // Where to save the log
	mutx    sync.Mutex
	uploads map[string]interface{}
}

// Add file to UploadLog. Returns err if already in log.
func (uploadLog *UploadLog) AddFile(uploadPath string, timeUpload string, scanPath string, hash string, scanType string) error {
	uploadLog.mutx.Lock()
	defer uploadLog.mutx.Unlock()

	if _, ok := uploadLog.uploads[uploadPath]; ok {
		return &errors.UploadAlreadyInLog{}
	}

	// Create map of values for this upload
	uploadVals := map[string]interface{}{
		"Time Uploaded": timeUpload,
		"Scan File":     scanPath,
		"File Hash":     hash,
		"Scan Type":     scanType, // Results for file already in VT, Analysis for queued/new upload
	}

	// Add to uploadLog
	if uploadLog.uploads == nil {
		uploadLog.uploads = make(map[string]interface{})
	}
	uploadLog.uploads[uploadPath] = uploadVals

	return nil
}

// Update existing log entry. Returns err if not already in log.

// Save to file
