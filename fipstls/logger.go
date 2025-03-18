package fipstls

import (
	"fmt"
)

// LogLevel is used for setting log verbosity levels
type LogLevel int

const (
	LogLevelErr LogLevel = iota
	LogLevelInfo
	LogLevelDebug
)

// Logger is an interface used for logging at different verbosity levels.
type Logger interface {
	Logf(level LogLevel, format string, args ...any)
	Wrap(prefix string) Logger
}

// noopLogger is a logger implementation that does nothing.
type noopLogger struct{}

func (l noopLogger) Wrap(string) Logger            { return l }
func (l noopLogger) Logf(LogLevel, string, ...any) {}

// DefaultLogger is an implementation of the [Logger] interface that allows
// callers to hook in external logging functions.
type DefaultLogger struct {
	Prefix     string
	Level      LogLevel
	LoggerFunc func(format string, args ...any)
}

// Wrap will create a new logger with the prefix appended.
func (l *DefaultLogger) Wrap(prefix string) Logger {
	return &DefaultLogger{
		Prefix:     l.Prefix + prefix,
		Level:      l.Level,
		LoggerFunc: l.LoggerFunc,
	}
}

// Logf is used for logging at the specified [LogLevel]. This method can be
// overridden by setting [DefaultLogger.LoggerFunc].
func (l *DefaultLogger) Logf(level LogLevel, format string, args ...any) {
	if level > l.Level {
		return
	}

	var levelStr string
	switch level {
	case LogLevelDebug:
		levelStr = "DEBUG:"
	case LogLevelInfo:
		levelStr = "INFO:"
	case LogLevelErr:
		levelStr = "ERROR:"
	}

	msg := fmt.Sprintf(format, args...)
	l.LoggerFunc("%-6s %s %s", levelStr, l.Prefix, msg)
}
