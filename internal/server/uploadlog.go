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

// Add file to UploadLog. Returns err if already in log.
func (uploadLog *UploadLog) AddFile(uploadPath string, originalFilename string, timeUpload string, scanPath string, hash string, scanType string) error {
	uploadLog.mutx.Lock()
	defer uploadLog.mutx.Unlock()

	if _, ok := uploadLog.uploads[uploadPath]; ok {
		return &errors.UploadAlreadyInLog{}
	}

	// Create map of values for this upload
	uploadVals := map[string]interface{}{
		"Original Filename": originalFilename,
		"Time Uploaded":     timeUpload,
		"Scan File":         scanPath,
		"File Hash":         hash,
		"Scan Type":         scanType, // Results for file already in VT, Analysis for queued/new upload, or Not Uploaded if not yet uploaded or not going to upload
	}

	// Add to uploadLog
	if uploadLog.uploads == nil {
		uploadLog.uploads = make(map[string]interface{})
	}
	uploadLog.uploads[uploadPath] = uploadVals

	return nil
}

// Update existing log entry. Returns err if not already in log.
func (uploadLog *UploadLog) UpdateFile(uploadPath string, originalFilename string, timeUpload string, scanPath string, hash string, scanType string) error {
	uploadLog.mutx.Lock()
	defer uploadLog.mutx.Unlock()

	if _, ok := uploadLog.uploads[uploadPath]; !ok {
		return &errors.UploadNotInLog{}
	}

	// Create map of values for this upload
	uploadVals := map[string]interface{}{
		"Original Filename": originalFilename,
		"Time Uploaded":     timeUpload,
		"Scan File":         scanPath,
		"File Hash":         hash,
		"Scan Type":         scanType, // Results for file already in VT, Analysis for queued/new upload
	}

	// Add to uploadLog
	uploadLog.uploads = make(map[string]interface{})
	uploadLog.uploads[uploadPath] = uploadVals

	return nil
}

// Update the scan path and type of an already existing entry
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

// Loop and save file every so many seconds
func (uploadLog *UploadLog) SaveFileLoop() error {
	for !uploadLog.quitSavingLoop {
		if err := uploadLog.SaveFile(); err != nil {
			return err
		}

		time.Sleep(time.Duration(uploadLog.saveInterval) * time.Second)
	}

	return nil
}

// Load uploadlog from file
func (uploadLog *UploadLog) LoadFromFile() error {
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

	// Read the uploadLog file
	scanner := bufio.NewScanner(f)
	var data []byte

	for scanner.Scan() { // Reading line-by-line
		line := scanner.Bytes()
		data = append(data, line...)
		data = append(data, '\n')
	}
	if err = scanner.Err(); err != nil {
		return err
	}

	// Create the upload map from the file
	if err = json.Unmarshal(data, &uploadLog.uploads); err != nil {
		return err
	}

	return nil
}
