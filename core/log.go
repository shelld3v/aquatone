package core

import (
	"fmt"
	"os"
	"sync"

	"github.com/fatih/color"
)

const (
	FATAL     = 5
	ERROR     = 4
	WARN      = 3
	IMPORTANT = 2
	INFO      = 1
	DEBUG     = 0
)

var LogColors = map[int]*color.Color{
	FATAL:     color.New(color.FgRed).Add(color.Bold),
	ERROR:     color.New(color.FgRed),
	WARN:      color.New(color.FgYellow),
	IMPORTANT: color.New(color.Bold),
}

type Logger struct {
	sync.Mutex

	DebugLog *os.File
	silent   bool
}

func (l *Logger) SetSilent(s bool) {
	l.silent = s
}

func (l *Logger) SetDebugLog(path string) {
	var err error

	l.DebugLog, err = os.Create(path)
	if err != nil {
		l.DebugLog = nil
	}
}

func (l *Logger) CloseDebugLog() {
	if l.DebugLog != nil {
		l.DebugLog.Close()
	}
}

func (l *Logger) Log(level int, format string, args ...interface{}) {
	l.Lock()
	defer l.Unlock()

	if level == DEBUG {
		if l.DebugLog != nil {
			msg := fmt.Sprintf(format, args...)
			l.DebugLog.WriteString(msg)
		}
		return
	}
	if level < ERROR && l.silent {
		return
	}

	if c, ok := LogColors[level]; ok {
		c.Printf(format, args...)
	} else {
		fmt.Printf(format, args...)
	}

	if level == FATAL {
		os.Exit(1)
	}
}

func (l *Logger) Fatal(format string, args ...interface{}) {
	l.Log(FATAL, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.Log(ERROR, format, args...)
}

func (l *Logger) Warn(format string, args ...interface{}) {
	l.Log(WARN, format, args...)
}

func (l *Logger) Important(format string, args ...interface{}) {
	l.Log(IMPORTANT, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.Log(INFO, format, args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.Log(DEBUG, format, args...)
}
