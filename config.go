package main

import (
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

// config represents the top-level object from the config TOML
type config struct {
	Period          *duration
	Keyvault        *string
	Listen          *string
	Password        *string
	RunTimeout      *duration
	Environment     *string
	EnvironmentFile *string

	File     []configFile
	Template []configTemplate
}

// configFile directs this to write a secret directly to output
type configFile struct {
	Keyvault   string
	Secret     string
	Output     string
	Mode       *int
	Owner      string
	Run        string
	RunTimeout *duration
}

// configTemplate directs this to process a text template
type configTemplate struct {
	Keyvault   string
	Input      string
	Inline     string
	Output     string
	Mode       *int
	Owner      string
	Run        string
	RunTimeout *duration
}

// duration wraps time.Duration in a manner that can be parsed
type duration time.Duration

// loadConfig reads and decodes the specified TOML file
func loadConfig(file string) (*config, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open "+file)
	}

	var cfg config
	dec := toml.NewDecoder(fd)
	if _, err := dec.Decode(&cfg); err != nil {
		return nil, errors.Wrap(err, "Failed to parse "+file)
	}

	return &cfg, nil
}

func (d *duration) UnmarshalText(text []byte) error {
	dur, err := time.ParseDuration(string(text))
	*d = duration(dur)
	return err
}

func (d *duration) DurationPtr() *time.Duration {
	if d == nil {
		return nil
	} else {
		td := time.Duration(*d)
		return &td
	}
}

func (d *duration) Duration() time.Duration {
	if d == nil {
		return time.Duration(0)
	} else {
		return time.Duration(*d)
	}
}
