package main

import (
	"os"

	"github.com/rodjunger/chatgptauth"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type OnlyInfoHook struct{}

func (h OnlyInfoHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	if level != zerolog.InfoLevel {
		e.Discard()
	}
}

func main() {
	// Don't use zerolog.DebugLevel to log to console, it will make the output unreadable
	logger := log.Output(zerolog.ConsoleWriter{Out: os.Stdout}).Hook(OnlyInfoHook{}).Level(zerolog.InfoLevel)
	auth, err := chatgptauth.NewAuthClient("user", "password", "", &logger)

	if err != nil {
		log.Error().Err(err).Msg("Failed to create auth client")
		return
	}

	creds, err := auth.Authenticate()

	if err != nil {
		log.Error().Err(err).Msg("Failed to log in")
		return
	}
	logger.Info().Str("Access token", creds.AccessToken).Str("Expiry", creds.ExpiresAt).Msg("logged in")
	//Save credentials to file so you don't have to login again next time
}
