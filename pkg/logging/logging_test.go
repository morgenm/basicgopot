package logging

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewStdout tests creating a new log to stdout.
func TestNewStdout(t *testing.T) {
	// Test creating log
	l, err := New("")
	if err != nil {
		t.Fatalf(`TestNewStdout = %v, %v, expected log, nil`, l, err)
	}
	if l.logFile != nil {
		t.Fatalf(`TestNewStdout log file is not nil!`)
	}
	if l.logger == nil {
		t.Fatal(`TestNewStdout logger is nil!`)
	}

	// Test closing log
	if err = l.Close(); err != nil {
		t.Fatalf(`TestNewStdout could not close logger, err = %v!`, err)
	}
}

// TestPrintToFile tests creating a new log file and writing to it.
func TestPrintToFile(t *testing.T) {
	logDir := t.TempDir()

	// Test creating file
	l, err := New(filepath.Join(logDir, "log.log"))
	if err != nil {
		t.Fatalf(`TestPrintToFile = %v, %v, expected log, nil`, l, err)
	}
	if l.logFile == nil {
		t.Fatalf(`TestPrintToFile log file is nil!`)
	}
	if l.logger == nil {
		t.Fatal(`TestPrintToFile logger is nil!`)
	}

	// Print to the file.
	l.Log("TestString ", 5)
	l.Logf("TestString2 %d %s", 22, "lol")

	// Test closing log.
	if err = l.Close(); err != nil {
		t.Fatalf(`TestPrintToFile could not close file, err = %v!`, err)
	}

	// Now open file to validate output.
	f, err := os.Open(filepath.Join(logDir, "log.log"))
	if err != nil {
		t.Fatalf(`TestPrintToFile could not open file, err = %v!`, err)
	}

	// Read log file
	buf, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf(`TestPrintToFile could not read log file, err = %v!`, err)
	}

	// Close log file
	err = f.Close()
	if err != nil {
		t.Fatalf(`TestPrintToFile could not close log file, err = %v!`, err)
	}

	// See if string contains the outputted string from earlier
	s := string(buf)
	if !strings.Contains(s, "TestString 5") || !strings.Contains(s, "TestString2 22 lol") {
		t.Fatalf(`TestPrintToFile the output to the log file did not match the expected value!`)
	}
}
