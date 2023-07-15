package server

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/morgenm/basicgopot/pkg/errors"
)

type UploadLog struct {
	logPath        string // Where to save the log
	mutx           sync.Mutex
	uploads        map[string]interface{}
	quitSavingLoop bool
	saveInterval   int // Save every so many seconds
}

// IsInLog returns true if the given upload path is already in the log, false otherwise.
func (uploadLog *UploadLog) IsInLog(uploadPath string) bool {
	uploadLog.mutx.Lock()
	_, ok := uploadLog.uploads[uploadPath]
	uploadLog.mutx.Unlock()
	return ok
}

// AddFile adds the given file info to UploadLog. Returns err if already in log.
func (uploadLog *UploadLog) AddFile(uploadPath string, uploaderIP string, originalFilename string, timeUpload string, scanPath string, hash string, scanType string) error {
	uploadLog.mutx.Lock()
	defer uploadLog.mutx.Unlock()

	if _, ok := uploadLog.uploads[uploadPath]; ok {
		return &errors.UploadAlreadyInLog{}
	}

	// Create map of values for this upload
	uploadVals := map[string]interface{}{
		"Original Filename": originalFilename,
		"Uploader IP":       uploaderIP,
		"Time Uploaded":     timeUpload,
		"Scan File":         scanPath,
		"File Hash":         hash,
		"Scan Type":         scanType, // Results for file already in VT, Analysis for queued/new upload, or Not Uploaded if not yet uploaded or not going to upload
		"WebHookResults":    make(map[string]string),
	}

	// Add to uploadLog
	if uploadLog.uploads == nil {
		uploadLog.uploads = make(map[string]interface{})
	}
	uploadLog.uploads[uploadPath] = uploadVals

	return nil
}

// Update existing log entry. Returns err if not already in log.
func (uploadLog *UploadLog) UpdateFile(uploadPath string, uploaderIP string, originalFilename string, timeUpload string, scanPath string, hash string, scanType string) error {
	uploadLog.mutx.Lock()
	defer uploadLog.mutx.Unlock()

	if _, ok := uploadLog.uploads[uploadPath]; !ok {
		return &errors.UploadNotInLog{}
	}

	// Create map of values for this upload
	uploadVals := map[string]interface{}{
		"Original Filename": originalFilename,
		"Uploader IP":       uploaderIP,
		"Time Uploaded":     timeUpload,
		"Scan File":         scanPath,
		"File Hash":         hash,
		"Scan Type":         scanType, // Results for file already in VT, Analysis for queued/new upload
		"WebHookResults":    make(map[string]string),
	}

	// Add to uploadLog
	uploadLog.uploads = make(map[string]interface{})
	uploadLog.uploads[uploadPath] = uploadVals

	return nil
}

// Update the scan path and type of an already existing entry.
func (uploadLog *UploadLog) UpdateFileScan(uploadPath string, newScanPath string, newScanType string) error {
	uploadLog.mutx.Lock()
	defer uploadLog.mutx.Unlock()

	if _, ok := uploadLog.uploads[uploadPath]; !ok {
		return &errors.UploadNotInLog{}
	}

	uploadLog.uploads[uploadPath].(map[string]interface{})["Scan File"] = newScanPath
	uploadLog.uploads[uploadPath].(map[string]interface{})["Scan Type"] = newScanType
	return nil
}

// Update the WebHook file paths for an already existing entry.
func (uploadLog *UploadLog) UpdateAddWebHookPath(uploadPath string, webHookName string, webHookPath string) error {
	uploadLog.mutx.Lock()
	defer uploadLog.mutx.Unlock()

	if _, ok := uploadLog.uploads[uploadPath]; !ok {
		return &errors.UploadNotInLog{}
	}

	webHookResults := uploadLog.uploads[uploadPath].(map[string]interface{})["WebHookResults"].(map[string]string)
	webHookResults[webHookName] = webHookPath

	return nil
}

// Save to file.
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
	logPath := filepath.Clean(uploadLog.logPath)
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

// Loop and save file every so many seconds.
func (uploadLog *UploadLog) SaveFileLoop() error {
	isQuit := false

	for !isQuit {
		if err := uploadLog.SaveFile(); err != nil {
			return err
		}

		time.Sleep(time.Duration(uploadLog.saveInterval) * time.Second)

		// Get isQuit
		uploadLog.mutx.Lock()
		isQuit = uploadLog.quitSavingLoop
		uploadLog.mutx.Unlock()
	}

	return nil
}

func (uploadLog *UploadLog) StopSaveFileLoop() {
	uploadLog.mutx.Lock()
	defer uploadLog.mutx.Unlock()
	uploadLog.quitSavingLoop = true
}

// loadFromBytes will load an upload log from given bytes. Returns nil on success, error on failure.
func (uploadLog *UploadLog) loadFromBytes(data []byte) error {
	if err := json.Unmarshal(data, &uploadLog.uploads); err != nil {
		return err
	}
	return nil
}

// Load will load the upload log from the file specified in uploadLog.logPath. Returns nil on success, error on failure.
func (uploadLog *UploadLog) Load() error {
	if uploadLog.logPath == "" { // No log file
		return nil
	}

	f, err := os.Open(filepath.Clean(uploadLog.logPath))
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()

	// Get file size.
	stat, err := f.Stat()
	if err != nil {
		return err
	}

	// Read the uploadLog file
	data := make([]byte, stat.Size())

	if _, err = bufio.NewReader(f).Read(data); err != nil {
		return err
	}

	return uploadLog.loadFromBytes(data)
}
