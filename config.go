package main

import (
	"os"
	"time"

	"github.com/pelletier/go-toml"
	"github.com/pkg/errors"
)

type config struct {
	Period     *duration
	Keyvault   *string
	Listen     *string
	Password   *string
	RunTimeout *duration

	File     []configFile
	Template []configTemplate
}

type configFile struct {
	Keyvault   string
	Secret     string
	Output     string
	Mode       *int
	Owner      string
	Run        string
	RunTimeout *duration
}

type configTemplate struct {
	Keyvault   string
	Input      string
	Output     string
	Mode       *int
	Owner      string
	Run        string
	RunTimeout *duration
}

type duration time.Duration

func loadConfig(file string) (*config, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open "+file)
	}

	var cfg config
	dec := toml.NewDecoder(fd)
	if err := dec.Decode(&cfg); err != nil {
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
