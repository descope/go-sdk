package logger

import (
	"fmt"
	"log"
	"sync"
)

type LoggerInterface interface {
	Print(v ...interface{})
}

type LogLevel uint

const (
	LogNone       LogLevel = iota
	LogInfoLevel  LogLevel = 1
	LogDebugLevel LogLevel = 2
)

type LoggerWrapper struct {
	logLevel LogLevel
	logger   LoggerInterface
}

var (
	initLogger     sync.Once
	loggerInstance LoggerWrapper
)

func Init(LogLevel LogLevel, logger LoggerInterface) {
	if logger == nil {
		logger = log.Default()
	}

	// Initialize of the logger instance once, so this action will be goroutine safe
	// so logging functions bellow can be called in any global context
	initLogger.Do(func() {
		loggerInstance = LoggerWrapper{logLevel: LogLevel, logger: logger}
	})
}

func (lw *LoggerWrapper) doLog(l LogLevel, format string, args ...interface{}) {
	if lw.logLevel < l {
		return
	}
	if lw.logger == nil {
		lw.logger = log.Default()
	}
	lw.logger.Print(fmt.Sprintf(format, args...))
}

func LogDebug(format string, args ...interface{}) {
	loggerInstance.doLog(LogDebugLevel, format, args...)
}

func LogError(format string, err error, args ...interface{}) {
	loggerInstance.doLog(LogInfoLevel, "%s [error: %s]", append([]interface{}{fmt.Sprintf(format, args...)}, err)...)
}

func LogInfo(format string, args ...interface{}) {
	loggerInstance.doLog(LogInfoLevel, format, args...)
}
