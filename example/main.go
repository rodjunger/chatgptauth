package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

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
	auth, err := chatgptauth.NewAuthClient("user", "pass", "", &logger)

	if err != nil {
		log.Error().Err(err).Msg("Failed to create auth client")
		return
	}

	captcha, err := auth.Begin()

	if err != nil {
		log.Error().Err(err).Msg("Failed to begin auth")
		return
	}

	var answer string

	if captcha.Available() {
		captcha.ToFile("captcha.png")
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Captcha answer: ")
		captchaAnswer, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		answer = strings.Replace(captchaAnswer, "\n", "", -1)
	}

	creds, err := auth.Finish(answer)

	if err != nil {
		log.Error().Err(err).Msg("Failed to finish auth")
		return
	}
	logger.Info().Str("Access token", creds.AccessToken).Str("Expiry", creds.ExpiresAt).Msg("logged in")
	//Save credentials to file so you don't have to login again next time
}
