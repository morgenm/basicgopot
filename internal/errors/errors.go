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
