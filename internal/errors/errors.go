// Error handling
package errors

import (
	"log"
)

func CheckErr(err error, outString string) bool {
	if err != nil {
		log.Print(outString, " ", err)
		return true
	} else {
		return false
	}
}

type VirusTotalAPIKeyError struct{}
type VirusTotalAnalysisNotFound struct{}
type InvalidHashError struct{}
type FileTooBig struct{}
type UploadAlreadyInLog struct{}

func (e *VirusTotalAPIKeyError) Error() string {
	return "VirusTotal authentication failure!"
}

func (e *VirusTotalAnalysisNotFound) Error() string {
	return "VirusTotal authentication failure!"
}

func (e *InvalidHashError) Error() string {
	return "Invalid hash!"
}

func (e *FileTooBig) Error() string {
	return "File is too large to upload to VirusTotal!"
}

func (e *UploadAlreadyInLog) Error() string {
	return "This filepath already exists in the log!"
}
