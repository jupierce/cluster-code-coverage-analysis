package log

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Level represents logging verbosity
type Level int

const (
	ErrorLevel Level = iota
	InfoLevel
	DebugLevel
	TraceLevel
)

var levelNames = map[Level]string{
	ErrorLevel: "ERROR",
	InfoLevel:  "INFO",
	DebugLevel: "DEBUG",
	TraceLevel: "TRACE",
}

// Logger provides structured logging with verbosity control
type Logger struct {
	level      Level
	logDir     string
	logFile    *os.File
	mu         sync.Mutex
	stdout     io.Writer
	stderr     io.Writer
	fileLogger *log.Logger
}

// New creates a new logger
func New(level Level, logDir string) (*Logger, error) {
	l := &Logger{
		level:  level,
		logDir: logDir,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}

	// Create log directory if specified
	if logDir != "" {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return nil, fmt.Errorf("create log directory: %w", err)
		}

		// Create log file
		logPath := filepath.Join(logDir, fmt.Sprintf("coverage-collector-%s.log", time.Now().Format("20060102-150405")))
		f, err := os.Create(logPath)
		if err != nil {
			return nil, fmt.Errorf("create log file: %w", err)
		}
		l.logFile = f
		l.fileLogger = log.New(f, "", log.LstdFlags)
	}

	return l, nil
}

// Close closes the log file
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.logFile != nil {
		return l.logFile.Close()
	}
	return nil
}

// log writes a log message
func (l *Logger) log(level Level, format string, args ...interface{}) {
	if level > l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	levelName := levelNames[level]

	logLine := fmt.Sprintf("[%s] %s: %s", timestamp, levelName, msg)

	// Write to file if available
	if l.fileLogger != nil {
		l.fileLogger.Println(logLine)
	}

	// Write to stdout/stderr
	if level == ErrorLevel {
		fmt.Fprintf(l.stderr, "❌ %s\n", msg)
	} else {
		fmt.Fprintf(l.stdout, "%s\n", msg)
	}
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ErrorLevel, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(InfoLevel, format, args...)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DebugLevel, format, args...)
}

// Trace logs a trace message
func (l *Logger) Trace(format string, args ...interface{}) {
	l.log(TraceLevel, format, args...)
}

// Progress logs a progress message (always shown)
func (l *Logger) Progress(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	msg := fmt.Sprintf(format, args...)

	// Write to file
	if l.fileLogger != nil {
		l.fileLogger.Printf("[PROGRESS] %s", msg)
	}

	// Write to stdout with emoji
	fmt.Fprintf(l.stdout, "⏳ %s\n", msg)
}

// Success logs a success message (always shown)
func (l *Logger) Success(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	msg := fmt.Sprintf(format, args...)

	// Write to file
	if l.fileLogger != nil {
		l.fileLogger.Printf("[SUCCESS] %s", msg)
	}

	// Write to stdout with emoji
	fmt.Fprintf(l.stdout, "✅ %s\n", msg)
}

// Warning logs a warning message
func (l *Logger) Warning(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	msg := fmt.Sprintf(format, args...)

	// Write to file
	if l.fileLogger != nil {
		l.fileLogger.Printf("[WARNING] %s", msg)
	}

	// Write to stdout with emoji
	fmt.Fprintf(l.stdout, "⚠️  %s\n", msg)
}

// ParseLevel parses a string into a log level
func ParseLevel(s string) (Level, error) {
	switch s {
	case "error":
		return ErrorLevel, nil
	case "info":
		return InfoLevel, nil
	case "debug":
		return DebugLevel, nil
	case "trace":
		return TraceLevel, nil
	default:
		return InfoLevel, fmt.Errorf("invalid log level: %s (valid: error, info, debug, trace)", s)
	}
}
