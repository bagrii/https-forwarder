package logger

import (
	"log"
	"os"
	"io/ioutil"
)

type LoggerLevel uint

const (
	INFO LoggerLevel = iota
	WARNING
	ERROR
)

type LLogger struct {
	*log.Logger
	level LoggerLevel
}

var (
	InfoLogger *LLogger = New(INFO)
	WarningLogger *LLogger = New(WARNING)
	ErrorLogger *LLogger = New(ERROR)
)

func New(level LoggerLevel) *LLogger {
	switch level {
	case INFO:
		return &LLogger{
			level: level,
			Logger: log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime),
		}
	case WARNING:
		return &LLogger{
			level: level,
			Logger: log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime),
		}
	case ERROR:
		return &LLogger{
			level: level,
			Logger: log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime),
		}
	}
	return &LLogger{
		level: level,
		Logger: log.New(os.Stdout, "", log.Ldate|log.Ltime),
	}
}

func (l *LLogger) Disable() {
	l.SetOutput(ioutil.Discard)
}

func (l *LLogger) Enable() {
	switch l.level {
	case INFO, WARNING: 
		l.SetOutput(os.Stdout)
	case ERROR:
		l.SetOutput(os.Stderr)
	default:
		l.SetOutput(os.Stdout)
	}
}