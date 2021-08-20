package main

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/Azure/go-autorest/autorest/azure"
	log "github.com/sirupsen/logrus"

	"github.com/jjjordanmsft/az-template/debounce"
	"github.com/jjjordanmsft/az-template/keyvault"
)

const defaultRunTimeout = 5 * time.Minute

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <config.toml>\n", os.Args[0])
		os.Exit(2)
	}

	// Load config file.
	cfg, err := loadConfig(os.Args[1])
	if err != nil {
		log.WithError(err).Fatal("Error loading config")
		os.Exit(1)
	}

	basePath := path.Dir(os.Args[1])

	// Find Azure environment
	var azenv azure.Environment
	if cfg.Environment != nil {
		env, err := azure.EnvironmentFromName(*cfg.Environment)
		if err != nil {
			log.WithError(err).Fatalf("Error loading azure environment '%s'", *cfg.Environment)
			os.Exit(1)
		}

		azenv = env
	} else if cfg.EnvironmentFile != nil {
		env, err := azure.EnvironmentFromFile(relPath(basePath, *cfg.EnvironmentFile))
		if err != nil {
			log.WithError(err).Fatalf("Error loading azure environment from file '%s'", *cfg.EnvironmentFile)
			os.Exit(1)
		}

		azenv = env
	} else {
		azenv = azure.PublicCloud
	}

	// Initialize keyvaults collection
	keyvaults, err := keyvault.NewKeyvaults(azenv)
	if err != nil {
		log.WithError(err).Fatal("Error initializing keyvault")
		os.Exit(1)
	}

	// Create Generators for each step from config file
	generators, err := loadGenerators(cfg, keyvaults, basePath)
	if err != nil {
		log.WithError(err).Fatal("Error loading generators")
		os.Exit(1)
	}

	// Process all outputs immediately. Exit if period/listen unspecified.
	success := generateAll(keyvaults, generators)
	if cfg.Period == nil && cfg.Socket == nil {
		// No background processes
		log.Info("No socket/wait period configured, exiting.")
		if success {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	// Start the listener if one is specified
	ping := make(chan struct{})
	if err := startListener(cfg, keyvaults, ping); err != nil {
		log.WithError(err).Fatal("Error starting listener")
		os.Exit(1)
	}

	// Start the period ticker if one is specified
	var ticker <-chan time.Time
	if cfg.Period != nil {
		ticker = time.Tick(time.Duration(*cfg.Period))
	} else {
		ticker = make(<-chan time.Time)
	}

	// Listen for signals
	sigch := make(chan os.Signal, 2)
	signal.Notify(sigch, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	db, err := debounce.NewFromString("5s:20s")
	if err != nil {
		panic(err)
	}

	// Endless loop
	for {
		select {
		case sig := <-sigch:
			log.Infof("Signal %s received", sig.String())
			switch sig {
			case syscall.SIGHUP:
				reloadGenerators(generators)
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

// generateAll processes all outputs
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

// loadGenerators creates generators for each output in the config
func loadGenerators(cfg *config, kv *keyvault.Keyvaults, basePath string) ([]*Generator, error) {
	var baseCtx keyvault.TemplateContext = kv
	if cfg.Keyvault != nil {
		baseCtx = keyvault.WrapContext(baseCtx, *cfg.Keyvault)
	}

	var results []*Generator

	for _, f := range cfg.File {
		gen, err := downloadSecretToFile(baseCtx, f, basePath)
		if err != nil {
			return results, err
		}

		results = append(results, gen)
	}

	for _, t := range cfg.Template {
		gen, err := processTemplate(baseCtx, t, basePath)
		if err != nil {
			return results, err
		}

		results = append(results, gen)
	}

	runTimeout := cfg.RunTimeout.DurationPtr()
	if runTimeout == nil {
		to := defaultRunTimeout
		runTimeout = &to
	}

	for _, gen := range results {
		if gen.RunTimeout == nil {
			gen.RunTimeout = runTimeout
		}

		if err := gen.Reload(); err != nil {
			return results, err
		}
	}

	return results, nil
}

func reloadGenerators(gens []*Generator) {
	for _, gen := range gens {
		err := gen.Reload()
		if err != nil {
			log.WithError(err).Warnf("Error reloading template for generator '%s'", gen.OutputFile)
		}
	}
}
