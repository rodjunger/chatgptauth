## ChatGPTAuth provides requests-based authentication for the OpenAI ChatGPT website.

Extra care was put to ensure that requests match the browser requests in every aspect to avoid blocks, but you still may get rate limit.

It is currently in a VERY wip state, things can and will change.
Captcha answer can only be submitted through STDIN (aka typing) but that will be changed to better support use in other libraries and possibly captcha solvers.

## Installation

`go get -u github.com/rodjunger/chatgptauth`

## Pre-built binaries

Pre-built binaries are not available currently, a CLI is planned.

## Lib usage 

```go
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
```

# Thank you
This lib was made possible by the reverse engineering work of [rawandahmad698](https://github.com/rawandahmad698), my own reverse engineering work (big shoutout to charles proxy), and the awesome maintainers of all libraries used in this project.
