package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/cristalhq/aconfig"
	"github.com/xenitab/dispans/server"
	"github.com/xenitab/pkg/service"
)

func main() {
	cfg, err := newConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config generation returned an error: %v\n", err)
		os.Exit(1)
	}

	err = run(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Application returned an error: %v\n", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	errGroup, ctx, cancel := service.NewErrGroupAndContext()
	defer cancel()

	stopChan := service.NewStopChannel()
	defer signal.Stop(stopChan)

	opts := server.Options{
		Issuer:       cfg.Issuer,
		Address:      cfg.Address,
		Port:         cfg.Port,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURI:  cfg.RedirectURI,
	}

	srv, err := server.New(opts)
	if err != nil {
		return err
	}

	service.Start(ctx, errGroup, srv)

	stoppedBy := service.WaitForStop(stopChan, ctx)
	fmt.Printf("Application stopping. Stopped by: %s\n", stoppedBy)

	cancel()

	timeoutCtx, timeoutCancel := service.NewShutdownTimeoutContext()
	defer timeoutCancel()

	service.Stop(timeoutCtx, errGroup, srv)

	return service.WaitForErrGroup(errGroup)
}

type config struct {
	Issuer       string `flag:"issuer" env:"ISSUER" default:"http://localhost:9096" usage:"address webserver will listen to"`
	Address      string `flag:"address" env:"ADDRESS" default:"127.0.0.1" usage:"address webserver will listen to"`
	Port         int    `flag:"port" env:"PORT" default:"9096" usage:"port webserver will listen to"`
	ClientID     string `flag:"client-id" env:"CLIENT_ID" default:"222222" usage:"Client ID for the test client"`
	ClientSecret string `flag:"client-secret" env:"CLIENT_SECRET" default:"22222222" usage:"Client Secret for the test client"`
	RedirectURI  string `flag:"redirect-uri" env:"REDIRECT_URI" default:"http://localhost:9094" usage:"Redirect URI for the test client"`
}

func newConfig() (config, error) {
	var cfg config

	loader := aconfig.LoaderFor(&cfg, aconfig.Config{
		SkipDefaults: false,
		SkipFiles:    true,
		SkipEnv:      false,
		SkipFlags:    false,
		EnvPrefix:    "",
		FlagPrefix:   "",
		Files:        []string{},
		FileDecoders: map[string]aconfig.FileDecoder{},
	})

	err := loader.Load()
	if err != nil {
		return config{}, err
	}

	return cfg, nil
}
