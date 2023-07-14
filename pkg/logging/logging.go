// The logging package contains code for logging to the console and on disk.
package logging

import (
	"log"
	"os"
)

// Log will log strings to stdout or to a file, depending on what
// is passed to New().
type Log struct {
	logger  *log.Logger
	logFile *os.File
}

// New returns a pointer to a new log. If filepath = "", then
// log will output to stdout, else it will open the given file and write
// logs to it.
func New(filepath string) (*Log, error) {
	if filepath != "" {
		// Open and create if needed.
		f, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			return nil, err
		}
		// Create a logger with the opened file and default log flags
		return &Log{
			logger:  log.New(f, log.Prefix(), log.Flags()),
			logFile: f,
		}, nil
	} else {
		return &Log{
			logger:  log.Default(),
			logFile: nil,
		}, nil
	}
}

// Close should be called when logging is done, such as when the program is being stopped.
// If the logFile exists, it will be closed.
func (l *Log) Close() error {
	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

func (l *Log) Log(v ...any) {
	l.logger.Print(v...)
}

func (l *Log) Logf(format string, v ...any) {
	l.logger.Printf(format, v...)
}
