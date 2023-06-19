// The errors package provides error types specific to basicgopot.
package errors

type (
	// An InvalidConfig error is an error indicating that the config file
	// being loaded has invalid data.
	InvalidConfig struct{}
	// A VirusTotalAPIKeyError is an error indicating that VirusTotal did
	// not accept the API key provided in the config.
	VirusTotalAPIKeyError struct{}
	// A VirusTotalHashNotFound is an error indicating that the given hash
	// is not present in VirusTotal.
	VirusTotalHashNotFound struct{}
	// A VirusTotalAnalysisNotFound is an error indicating that there was
	// an error getting the analysis from VirusTotal after uploading a sample.
	VirusTotalAnalysisNotFound struct{}
	// An InvalidHashError is an error indicating that a given hash is not
	// in the sha256 format.
	InvalidHashError struct{}
	// A FileTooBig error is an error indicating that a given file is greater
	// than 32 MBs, which is the limit for uploading to VirusTotal using a free
	// API key.
	FileTooBig struct{}
	// An UploadAlreadyInLog error indicates that a given file name is already
	// present in the UploadLog.
	UploadAlreadyInLog struct{}
	// An UploadNotInLog error indicates that a file not present in the log
	// was accessed.
	UploadNotInLog struct{}
)

func (e *InvalidConfig) Error() string {
	return "The config file is invalid! Ensure that your config/config.json file matches the specifications in the documentation."
}

func (e *VirusTotalAPIKeyError) Error() string {
	return "VirusTotal authentication failure! Validate your API key in the config/config.json file!"
}

func (e *VirusTotalHashNotFound) Error() string {
	return "The given hash is not present in VirusTotal!"
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

func (e *UploadNotInLog) Error() string {
	return "This filepath does not exist in the log!"
}
