package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jjjordanmsft/az-template/debounce"
	"github.com/jjjordanmsft/az-template/keyvault"

	log "github.com/sirupsen/logrus"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <config.toml>\n", os.Args[0])
		os.Exit(2)
	}

	cfg, err := loadConfig(os.Args[1])
	if err != nil {
		log.WithError(err).Fatal("Error loading config")
		os.Exit(1)
	}

	keyvaults, err := keyvault.NewKeyvaults()
	if err != nil {
		log.WithError(err).Fatal("Error initializing keyvault")
		os.Exit(1)
	}

	generators, err := loadGenerators(cfg, keyvaults)
	if err != nil {
		log.WithError(err).Fatal("Error loading generators")
		os.Exit(1)
	}

	success := generateAll(keyvaults, generators)
	if cfg.Period == nil && cfg.Listen == nil {
		// No background processes
		log.Info("No listen/wait period configured, exiting.")
		if success {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	ping := make(chan struct{})
	if err := startListener(cfg, keyvaults, ping); err != nil {
		log.WithError(err).Fatal("Error starting listener")
		os.Exit(1)
	}

	var ticker <-chan time.Time
	if cfg.Period != nil {
		ticker = time.Tick(time.Duration(*cfg.Period))
	} else {
		ticker = make(<-chan time.Time)
	}

	sigch := make(chan os.Signal, 2)
	signal.Notify(sigch, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	db, err := debounce.NewFromString("5s:20s")
	if err != nil {
		panic(err)
	}

	for {
		select {
		case sig := <-sigch:
			log.Infof("Signal %s received", sig.String())
			switch sig {
			case syscall.SIGHUP:
				generateAll(keyvaults, generators)

			case syscall.SIGINT, syscall.SIGTERM:
				os.Exit(0)
			}

		case <-ticker:
		case <-ping:
			db.Trigger()

		case <-db.Chan():
			go generateAll(keyvaults, generators)
		}
	}
}

func generateAll(kv *keyvault.Keyvaults, generators []*Generator) bool {
	log.Info("Generating output")
	kv.Invalidate()

	success := true
	for _, gen := range generators {
		err := gen.Generate()
		if err != nil {
			success = false
			log.WithError(err).Errorf("Error processing generator %s", gen.Name)
		}
	}

	return success
}

func loadGenerators(cfg *config, kv *keyvault.Keyvaults) ([]*Generator, error) {
	var baseCtx keyvault.TemplateContext = kv
	if cfg.Keyvault != nil {
		baseCtx = keyvault.WrapContext(baseCtx, *cfg.Keyvault)
	}

	var results []*Generator

	for _, f := range cfg.File {
		gen, err := downloadSecretToFile(baseCtx, f)
		if err != nil {
			return results, err
		}

		results = append(results, gen)
	}

	for _, t := range cfg.Template {
		gen, err := processTemplate(baseCtx, t)
		if err != nil {
			return results, err
		}

		results = append(results, gen)
	}

	return results, nil
}
