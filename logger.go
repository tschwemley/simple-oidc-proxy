package main

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type LoggerOptions struct {
	Debug   bool
	Exclude []string
	LogFile string
}

type Logger struct {
	log zerolog.Logger
}

func NewLogger(opts LoggerOptions) Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if opts.Debug {
		opts.Exclude = []string{"time", "level"}
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	file := os.Stderr // use stderr by default
	if opts.LogFile != "" {
		file, _ = os.OpenFile(
			opts.LogFile,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0664,
		)
	}

	return Logger{
		// prettifies the output
		log: log.Output(zerolog.ConsoleWriter{
			PartsExclude: opts.Exclude,
			Out:          file,
		}),
	}
}

func (l Logger) Debug(a ...any) {
	l.log.Debug().Msg(fmt.Sprint(a...))
}

func (l Logger) Debugf(str string, a ...any) {
	l.log.Debug().Msg(fmt.Sprintf(str, a...))
}

func (l Logger) Error(a ...any) {
	l.log.Error().Msg(fmt.Sprint(a...))
}

func (l Logger) Errorf(str string, a ...any) {
	l.log.Error().Msg(fmt.Sprintf(str, a...))
}

func (l Logger) Fatal(a ...any) {
	l.log.Fatal().Msg(fmt.Sprint(a...))
}

func (l Logger) Fatalf(str string, a ...any) {
	l.log.Fatal().Msg(fmt.Sprintf(str, a...))
}

func (l Logger) Info(a ...any) {
	l.log.Info().Msg(fmt.Sprint(a...))
}

func (l Logger) Infof(str string, a ...any) {
	l.log.Info().Msg(fmt.Sprintf(str, a...))
}
