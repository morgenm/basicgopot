package server

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	goerrors "errors"

	"github.com/morgenm/basicgopot/pkg/config"
	"github.com/morgenm/basicgopot/pkg/errors"
	"github.com/morgenm/basicgopot/pkg/vt"
)

// writeVTResultToFile will write the given ReadCloser to a scan file. The scan file path is based on the
// passed config. Returns nil on success, error on failure.
func writeVTResultToFile(cfg *config.Config, reader io.ReadCloser) error {
	// Read the result
	body, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	// Write JSON to file
	scanFilename := time.Now().Format(time.UnixDate) + ".json"
	scanFilepath := filepath.Clean(filepath.Join(cfg.ScanOutputDir, scanFilename))
	outFile, err := os.Create(scanFilepath)
	if err != nil { // Failed to create file
		return err
	}
	if _, err = outFile.Write(body); err != nil {
		return err
	}
	if err = outFile.Close(); err != nil {
		return err
	}

	return nil
}

func checkVirusTotal(cfg *config.Config, uploadLog *UploadLog, uploadFilepath string, hash string, outFileName string, data []byte) error {
	// Check if valid hash
	if len(hash) != 64 {
		return &errors.InvalidHashError{}
	}

	// Check if on VirusTotal
	log.Print("Checking hash against VirusTotal...")
	scanFilepath := filepath.Join(cfg.ScanOutputDir, filepath.Clean(time.Now().Format(time.UnixDate)+".json"))
	errHashNotFound := &errors.VirusTotalHashNotFound{}
	reader, err := vt.CheckHashVirusTotal(cfg.VirusTotalApiKey, hash)
	if err != nil && !goerrors.As(err, &errHashNotFound) {
		return err
	} else if err == nil {
		if cfg.ScanOutputDir == "" { // We are done here if we are not outputting scans to file
			return nil
		}

		if err = writeVTResultToFile(cfg, *reader); err != nil {
			return err
		}

		log.Print("File analysis retrieved from VirusTotal, writing scan results.")
		if err = uploadLog.UpdateFileScan(uploadFilepath, scanFilepath, "Scan"); err != nil {
			return err
		}
		return nil
	}

	// Upload to VirusTotal, if configured to
	if !cfg.UploadVirusTotal {
		return nil
	}
	reader, err = vt.UploadFileVirusTotal(cfg.VirusTotalApiKey, outFileName, data)
	if err != nil {
		return err
	}

	if err = writeVTResultToFile(cfg, *reader); err != nil {
		return err
	}

	if err = uploadLog.UpdateFileScan(uploadFilepath, scanFilepath, "Analysis"); err != nil {
		return err
	}

	return nil
}
