package logger

import (
	"bytes"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testLogger struct {
	buffer *bytes.Buffer
	mu     sync.Mutex
}

func (t *testLogger) Print(v ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, val := range v {
		t.buffer.WriteString(val.(string))
	}
}

func newTestLogger() *testLogger {
	return &testLogger{
		buffer: &bytes.Buffer{},
	}
}

func (t *testLogger) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.buffer.String()
}

func (t *testLogger) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buffer.Reset()
}

// TestDoLog tests the doLog method which was previously marked as notest
func TestDoLog(t *testing.T) {
	t.Run("LogDebugWithDebugLevel", func(t *testing.T) {
		logger := newTestLogger()
		lw := &LoggerWrapper{
			logLevel: LogDebugLevel,
			logger:   logger,
		}

		lw.doLog(LogDebugLevel, "debug message: %s", "test")
		assert.Contains(t, logger.String(), "debug message: test")
	})

	t.Run("LogDebugWithInfoLevel_ShouldNotLog", func(t *testing.T) {
		logger := newTestLogger()
		lw := &LoggerWrapper{
			logLevel: LogInfoLevel,
			logger:   logger,
		}

		lw.doLog(LogDebugLevel, "debug message: %s", "test")
		assert.Empty(t, logger.String(), "Debug message should not be logged when log level is Info")
	})

	t.Run("LogInfoWithInfoLevel", func(t *testing.T) {
		logger := newTestLogger()
		lw := &LoggerWrapper{
			logLevel: LogInfoLevel,
			logger:   logger,
		}

		lw.doLog(LogInfoLevel, "info message: %s", "test")
		assert.Contains(t, logger.String(), "info message: test")
	})

	t.Run("LogNone_ShouldNotLog", func(t *testing.T) {
		logger := newTestLogger()
		lw := &LoggerWrapper{
			logLevel: LogNone,
			logger:   logger,
		}

		lw.doLog(LogInfoLevel, "info message: %s", "test")
		assert.Empty(t, logger.String(), "Nothing should be logged when log level is LogNone")
	})

	t.Run("NilLogger_UsesDefault", func(t *testing.T) {
		lw := &LoggerWrapper{
			logLevel: LogInfoLevel,
			logger:   nil,
		}

		// This should not panic and should set default logger
		require.NotPanics(t, func() {
			lw.doLog(LogInfoLevel, "test message")
		})
		assert.NotNil(t, lw.logger, "Logger should be set to default when nil")
	})
}

// TestGlobalLogFunctions tests the global logging functions
func TestGlobalLogFunctions(t *testing.T) {
	// Reset the singleton for testing
	initLogger = sync.Once{}
	loggerInstance = LoggerWrapper{}

	logger := newTestLogger()
	Init(LogDebugLevel, logger)

	t.Run("LogDebug", func(t *testing.T) {
		logger.Reset()
		LogDebug("debug: %s %d", "test", 123)
		assert.Contains(t, logger.String(), "debug: test 123")
	})

	t.Run("LogInfo", func(t *testing.T) {
		logger.Reset()
		LogInfo("info: %s", "message")
		assert.Contains(t, logger.String(), "info: message")
	})

	t.Run("LogError", func(t *testing.T) {
		logger.Reset()
		LogError("operation failed", assert.AnError)
		output := logger.String()
		assert.Contains(t, output, "operation failed")
		assert.Contains(t, output, "error:")
	})
}

// TestLoggerInit tests logger initialization
func TestLoggerInit(t *testing.T) {
	t.Run("InitWithNilLogger_UsesDefault", func(t *testing.T) {
		initLogger = sync.Once{}
		loggerInstance = LoggerWrapper{}

		Init(LogInfoLevel, nil)

		// Should not panic when logging
		require.NotPanics(t, func() {
			LogInfo("test")
		})
	})

	t.Run("InitOnce_IgnoresSecondCall", func(t *testing.T) {
		initLogger = sync.Once{}
		loggerInstance = LoggerWrapper{}

		logger1 := newTestLogger()
		logger2 := newTestLogger()

		Init(LogDebugLevel, logger1)
		Init(LogInfoLevel, logger2) // Should be ignored

		LogDebug("test message")
		assert.Contains(t, logger1.String(), "test message", "Should use first logger")
		assert.Empty(t, logger2.String(), "Second logger should not be used")
	})
}

// TestLogLevelFiltering tests that log level filtering works correctly
func TestLogLevelFiltering(t *testing.T) {
	tests := []struct {
		name      string
		setLevel  LogLevel
		logLevel  LogLevel
		shouldLog bool
		logFunc   func(string, ...any)
		message   string
	}{
		{"Debug_WithDebugLevel", LogDebugLevel, LogDebugLevel, true, LogDebug, "debug msg"},
		{"Debug_WithInfoLevel", LogInfoLevel, LogDebugLevel, false, LogDebug, "debug msg"},
		{"Debug_WithNoneLevel", LogNone, LogDebugLevel, false, LogDebug, "debug msg"},
		{"Info_WithDebugLevel", LogDebugLevel, LogInfoLevel, true, LogInfo, "info msg"},
		{"Info_WithInfoLevel", LogInfoLevel, LogInfoLevel, true, LogInfo, "info msg"},
		{"Info_WithNoneLevel", LogNone, LogInfoLevel, false, LogInfo, "info msg"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			initLogger = sync.Once{}
			loggerInstance = LoggerWrapper{}

			logger := newTestLogger()
			Init(tt.setLevel, logger)

			logger.Reset()
			tt.logFunc(tt.message)

			if tt.shouldLog {
				assert.Contains(t, logger.String(), tt.message, "Message should be logged")
			} else {
				assert.Empty(t, logger.String(), "Message should not be logged")
			}
		})
	}
}
