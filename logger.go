package main

/*
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

func InitLogger(opts LoggerOptions) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if opts.Debug {
		opts.Exclude = []string{"time", "level"}
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	if opts.LogFile == "" {
		opts.LogFile = "./log.log"
	}

	file, _ := os.OpenFile(
		opts.LogFile,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0664,
	)
	// if err != nil {
	// 	panic(err)
	// }
	// defer file.Close()

	// prettifies the output
	log.Logger = log.Output(zerolog.ConsoleWriter{
		PartsExclude: opts.Exclude, // TODO: make this an option
		Out:          file,
	})
	// log.Logger = zerolog.New(file).With().Logger()
}

func Debug(a ...any) {
	log.Debug().Msg(fmt.Sprint(a...))
}

func Debugf(str string, a ...any) {
	log.Debug().Msg(fmt.Sprintf(str, a...))
}

func Fatal(a ...any) {
	log.Fatal().Msg(fmt.Sprint(a...))
}

func Fatalf(str string, a ...any) {
	log.Fatal().Msg(fmt.Sprintf(str, a...))
}

func Info(a ...any) {
	log.Info().Msg(fmt.Sprint(a...))
}

func Infof(str string, a ...any) {
	log.Info().Msg(fmt.Sprintf(str, a...))
}
*/
