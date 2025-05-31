package golangJwtAuth

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Logger struct {
	Stdout       bool
	DebugLogger  *log.Logger
	OutputLogger *log.Logger
	ErrorLogger  *log.Logger
	Path         string
	File         []*os.File
	mu           sync.RWMutex
	MaxSize      int64
	Closed       bool
}

type LoggerConfig struct {
	Path    string
	MaxSize int64
	rw      os.FileMode
	Stdout  bool
}

func newLogger(config LoggerConfig) (*Logger, error) {
	if config.Path == "" {
		config.Path = "./logs/golangJWTAuth"
	}
	if config.rw == 0 {
		config.rw = 0644
	}
	if config.MaxSize == 0 {
		config.MaxSize = 16 * 1024 * 1024
	}

	if err := os.MkdirAll(config.Path, 0755); err != nil {
		return nil, fmt.Errorf("Failed to create log: %w", err)
	}

	logger := &Logger{
		Path:    config.Path,
		MaxSize: config.MaxSize,
		File:    make([]*os.File, 0, 3),
		Stdout:  config.Stdout,
	}

	if err := logger.initLoggers(config.rw); err != nil {
		logger.Close()
		return nil, err
	}

	return logger, nil
}

func (l *Logger) initLoggers(fileMode os.FileMode) error {
	debugFile, err := l.openLog("debug.log", fileMode)
	if err != nil {
		return err
	}

	outputFile, err := l.openLog("output.log", fileMode)
	if err != nil {
		return err
	}

	errorFile, err := l.openLog("error.log", fileMode)
	if err != nil {
		return err
	}

	l.File = append(l.File, debugFile, outputFile, errorFile)

	flags := log.LstdFlags | log.Lmicroseconds

	var debugWriters []io.Writer = []io.Writer{debugFile}
	var outputWriters []io.Writer = []io.Writer{outputFile}
	var errorWriters []io.Writer = []io.Writer{errorFile}

	if l.Stdout {
		debugWriters = append(debugWriters, os.Stdout)
		outputWriters = append(outputWriters, os.Stdout)
		errorWriters = append(errorWriters, os.Stderr)
	}

	l.DebugLogger = log.New(io.MultiWriter(debugWriters...), "", flags)
	l.OutputLogger = log.New(io.MultiWriter(outputWriters...), "", flags)
	l.ErrorLogger = log.New(io.MultiWriter(errorWriters...), "", flags)

	return nil
}

func (l *Logger) openLog(filename string, fileMode os.FileMode) (*os.File, error) {
	fullPath := filepath.Join(l.Path, filename)
	if info, err := os.Stat(fullPath); err == nil {
		if info.Size() > l.MaxSize {
			if err := l.rotateLog(fullPath); err != nil {
				return nil, fmt.Errorf("Failed to rotate %s: %w", filename, err)
			}
		}
	}

	file, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileMode)
	if err != nil {
		return nil, fmt.Errorf("Failed to open %s: %w", filename, err)
	}
	return file, nil
}

func (l *Logger) rotateLog(logPath string) error {
	timestamp := time.Now().Format("20060102_150405")
	backupPath := fmt.Sprintf("%s.%s", logPath, timestamp)
	return os.Rename(logPath, backupPath)
}

func (l *Logger) writeToLog(target *log.Logger, level string, messages ...string) {
	level = strings.ToUpper(level)
	isValid := map[string]bool{
		"DEBUG":    true,
		"TRACE":    true,
		"INFO":     true,
		"NOTICE":   true,
		"WARNING":  true,
		"ERROR":    true,
		"FATAL":    true,
		"CRITICAL": true,
	}[level]

	if !isValid {
		return
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.Closed || len(messages) == 0 {
		return
	}

	prefix := ""
	if level != "INFO" {
		prefix = fmt.Sprintf("[%s] ", level)
	}

	for i, msg := range messages {
		switch {
		case i == 0:
			target.Printf("%s%s", prefix, msg)
		case i == len(messages)-1:
			target.Printf("└── %s", msg)
		default:
			target.Printf("├── %s", msg)
		}
	}
}

func (l *Logger) Debug(messages ...string) {
	l.writeToLog(l.DebugLogger, "DEBUG", messages...)
}

func (l *Logger) Trace(messages ...string) {
	l.writeToLog(l.DebugLogger, "TRACE", messages...)
}

func (l *Logger) Info(messages ...string) {
	l.writeToLog(l.OutputLogger, "INFO", messages...)
}

func (l *Logger) Notice(messages ...string) {
	l.writeToLog(l.OutputLogger, "NOTICE", messages...)
}

func (l *Logger) Warning(messages ...string) {
	l.writeToLog(l.OutputLogger, "WARNING", messages...)
}

func (l *Logger) Error(messages ...string) error {
	l.writeToLog(l.ErrorLogger, "ERROR", messages...)
	return fmt.Errorf("%s", strings.Join(messages, " "))
}

func (l *Logger) Fatal(messages ...string) error {
	l.writeToLog(l.ErrorLogger, "FATAL", messages...)
	return fmt.Errorf("%s", strings.Join(messages, " "))
}

func (l *Logger) Critical(messages ...string) error {
	l.writeToLog(l.ErrorLogger, "CRITICAL", messages...)
	return fmt.Errorf("%s", strings.Join(messages, " "))
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.Closed {
		return nil
	}

	l.Closed = true
	var errs []error

	for _, file := range l.File {
		if err := file.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("Closing log files: %v", errs)
	}

	return nil
}

func (l *Logger) Flush() error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.Closed {
		return fmt.Errorf("Logger is closed")
	}

	var errs []error
	for _, file := range l.File {
		if err := file.Sync(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("Flushing log files: %v", errs)
	}

	return nil
}
