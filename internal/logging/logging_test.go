package logging

import (
	"bytes"
	"testing"
)

func TestLoggerWritesEnabledLevelsToStderr(t *testing.T) {
	var stderr bytes.Buffer
	logger := &Logger{stderr: &stderr, minLevel: 2}

	logger.Infof("info %d", 1)
	logger.Warningf("warning %d", 2)
	logger.Errorf("error %d", 3)

	const want = "warning 2\nerror 3\n"
	if got := stderr.String(); got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestLoggerDoesNotRequireStderr(t *testing.T) {
	logger := &Logger{minLevel: 1}

	logger.Infof("info")
	logger.Warningf("warning")
	logger.Errorf("error")
}
