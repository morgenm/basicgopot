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

type VirusTotalAPIKeyError struct {}
type InvalidHashError struct {}

func (e *VirusTotalAPIKeyError) Error() string {
	return "VirusTotal authentication failure!"
}

func (e *InvalidHashError) Error() string {
	return "Invalid hash!"
}