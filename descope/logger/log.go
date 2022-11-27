package logger

import (
	"fmt"
	"log"
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
	loggerInstance LoggerWrapper
)

func Init(LogLevel LogLevel, Logger LoggerInterface) {
	if Logger == nil {
		Logger = log.Default()
	}
	loggerInstance = LoggerWrapper{logLevel: LogLevel, logger: Logger}
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
