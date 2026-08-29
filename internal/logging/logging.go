package logging

import (
	"fmt"
	"io"
	"log/syslog"
)

type Logger struct {
	w        *syslog.Writer
	stderr   io.Writer
	minLevel int
}

func New(level string, stderr io.Writer) *Logger {
	w, _ := syslog.New(syslog.LOG_AUTH|syslog.LOG_INFO, "stns-authorized-keys")
	levels := map[string]int{"debug": 0, "info": 1, "warning": 2, "error": 3}
	min, ok := levels[level]
	if !ok {
		min = 1
	}
	return &Logger{w: w, stderr: stderr, minLevel: min}
}

func (l *Logger) Infof(f string, a ...any) {
	if l == nil || l.minLevel > 1 {
		return
	}
	message := fmt.Sprintf(f, a...)
	if l.w != nil {
		_ = l.w.Info(message)
	}
	if l.stderr != nil {
		_, _ = fmt.Fprintln(l.stderr, message)
	}
}

func (l *Logger) Warningf(f string, a ...any) {
	if l == nil || l.minLevel > 2 {
		return
	}
	message := fmt.Sprintf(f, a...)
	if l.w != nil {
		_ = l.w.Warning(message)
	}
	if l.stderr != nil {
		_, _ = fmt.Fprintln(l.stderr, message)
	}
}

func (l *Logger) Errorf(f string, a ...any) {
	if l == nil {
		return
	}
	message := fmt.Sprintf(f, a...)
	if l.w != nil {
		_ = l.w.Err(message)
	}
	if l.stderr != nil {
		_, _ = fmt.Fprintln(l.stderr, message)
	}
}
