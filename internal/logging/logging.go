package logging

import (
	"fmt"
	"log/syslog"
)

type Logger struct {
	w        *syslog.Writer
	minLevel int
}

func New(level string) *Logger {
	w, _ := syslog.New(syslog.LOG_AUTH|syslog.LOG_INFO, "stns-authorized-keys")
	levels := map[string]int{"debug": 0, "info": 1, "warning": 2, "error": 3}
	min, ok := levels[level]
	if !ok {
		min = 1
	}
	return &Logger{w: w, minLevel: min}
}

func (l *Logger) Infof(f string, a ...any) {
	if l != nil && l.w != nil && l.minLevel <= 1 {
		_ = l.w.Info(fmt.Sprintf(f, a...))
	}
}

func (l *Logger) Warningf(f string, a ...any) {
	if l != nil && l.w != nil && l.minLevel <= 2 {
		_ = l.w.Warning(fmt.Sprintf(f, a...))
	}
}

func (l *Logger) Errorf(f string, a ...any) {
	if l != nil && l.w != nil {
		_ = l.w.Err(fmt.Sprintf(f, a...))
	}
}
