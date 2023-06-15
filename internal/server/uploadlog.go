package server

import (
	"encoding/json"
	"os"
	"path/filepath"
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
func (uploadLog *UploadLog) UpdateFile(uploadPath string, timeUpload string, scanPath string, hash string, scanType string) error {
	uploadLog.mutx.Lock()
	defer uploadLog.mutx.Unlock()

	if _, ok := uploadLog.uploads[uploadPath]; !ok {
		return &errors.UploadNotInLog{}
	}

	// Create map of values for this upload
	uploadVals := map[string]interface{}{
		"Time Uploaded": timeUpload,
		"Scan File":     scanPath,
		"File Hash":     hash,
		"Scan Type":     scanType, // Results for file already in VT, Analysis for queued/new upload
	}

	// Add to uploadLog
	uploadLog.uploads = make(map[string]interface{})
	uploadLog.uploads[uploadPath] = uploadVals

	return nil
}

// Save to file
func (uploadLog *UploadLog) SaveFile() error {
	uploadLog.mutx.Lock()
	defer uploadLog.mutx.Unlock()

	// Convert the map to JSON data
	jsonData, err := json.Marshal(uploadLog.uploads)
	if err != nil {
		return err
	}

	// If were aren't saving to any file, don't do anything else
	if uploadLog.logPath == "" {
		return nil
	}

	// Open uploadLog file for writing the JSON data
	logPath := filepath.Clean(filepath.Join(uploadLog.logPath))
	outFile, err := os.Create(logPath)
	if err != nil {
		return err
	}

	_, err = outFile.Write(jsonData)
	if err != nil {
		return err
	}
	if err = outFile.Close(); err != nil {
		return err
	}

	return nil
}
