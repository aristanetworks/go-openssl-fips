package fipstls

import (
	"fmt"
	"io"
	"log"
)

// Log verbosity levels
const (
	LevelError = iota
	LevelInfo
	LevelDebug
)

// Logger is the interface that wraps basic logging methods.
type Logger interface {
	Log(level int, format string, args ...interface{})
	WithPrefix(prefix string) Logger
}

// noopLogger is a logger implementation that does nothing.
type noopLogger struct{}

func (l noopLogger) Log(level int, format string, args ...interface{}) {}
func (l noopLogger) WithPrefix(prefix string) Logger                   { return l }

// defaultLogger implements Logger using the standard library.
type defaultLogger struct {
	logger *log.Logger
	level  int // Maximum level to log
	prefix string
}

func newDefaultLogger(level int, w io.Writer, prefix string) *defaultLogger {
	return &defaultLogger{
		logger: log.New(w, "", log.LstdFlags),
		level:  level,
		prefix: prefix,
	}
}

// Log will log the message depending on the verbosity level of LevelError = 0, LevelInfo = 1, or
// LevelDebug = 2.
func (l *defaultLogger) Log(level int, format string, args ...interface{}) {
	if level > l.level {
		return
	}

	var levelStr string
	switch level {
	case LevelDebug:
		levelStr = "DEBUG"
	case LevelInfo:
		levelStr = "INFO"
	case LevelError:
		levelStr = "ERROR"
	}

	msg := fmt.Sprintf(format, args...)
	l.logger.Printf("%s: %s %s", levelStr, l.prefix, msg)
}

// WithPrefix appends the new prefix to the current prefix.
func (l *defaultLogger) WithPrefix(prefix string) Logger {
	newLogger := *l
	newLogger.prefix = l.prefix + prefix
	return &newLogger
}
