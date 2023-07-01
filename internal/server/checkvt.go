package server

import (
	"io"
	"log"

	goerrors "errors"

	"github.com/morgenm/basicgopot/pkg/config"
	"github.com/morgenm/basicgopot/pkg/errors"
	"github.com/morgenm/basicgopot/pkg/vt"
)

// writeVTResult will write the given Reader to a given scan writer. Returns nil on success, error on failure.
func writeVTResult(reader io.Reader, writer io.Writer) error {
	// Read the result
	body, err := io.ReadAll(reader)
	if err != nil {
		return err
	}

	if _, err = writer.Write(body); err != nil {
		return err
	}

	return nil
}

func checkVirusTotal(cfg *config.Config, uploadLog *UploadLog, scanWriter io.Writer, scanFilepath string, uploadFilepath string, hash string, outFileName string, data []byte) error {
	// Check if valid hash
	if len(hash) != 64 {
		return &errors.InvalidHashError{}
	}

	// Check if on VirusTotal
	log.Print("Checking hash against VirusTotal...")
	errHashNotFound := &errors.VirusTotalHashNotFound{}
	reader, err := vt.CheckHashVirusTotal(cfg.VirusTotalApiKey, hash)
	if err != nil && !goerrors.As(err, &errHashNotFound) {
		return err
	} else if err == nil {
		if scanWriter == nil { // We are done here if we are not outputting scans to file
			return nil
		}

		if err = writeVTResult(*reader, scanWriter); err != nil {
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

	if scanWriter == nil { // We are done here if we are not outputting scans to file
		return nil
	}

	if err = writeVTResult(*reader, scanWriter); err != nil {
		return err
	}

	if err = uploadLog.UpdateFileScan(uploadFilepath, scanFilepath, "Analysis"); err != nil {
		return err
	}

	return nil
}
