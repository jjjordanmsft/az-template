package main

import (
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

// config represents the top-level object from the config TOML
type config struct {
	Period          *duration `toml:"period"`
	Keyvault        *string   `toml:"keyvault"`
	Socket          *string   `toml:"socket"`
	SocketMode      *int      `toml:"socketmode"`
	SocketOwner     *string   `toml:"socketowner"`
	PasswordSecret  *string   `toml:"passwordsecret"`
	RunTimeout      *duration `toml:"runtimeout"`
	Environment     *string   `toml:"environment"`
	EnvironmentFile *string   `toml:"environmentfile"`

	File     []configFile     `toml:"file"`
	Template []configTemplate `toml:"template"`
}

// configFile directs this to write a secret directly to output
type configFile struct {
	Keyvault   string    `toml:"keyvault"`
	Secret     string    `toml:"secret"`
	Output     string    `toml:"output"`
	Mode       *int      `toml:"mode"`
	Owner      string    `toml:"owner"`
	Run        string    `toml:"run"`
	RunTimeout *duration `toml:"runtimeout"`
}

// configTemplate directs this to process a text template
type configTemplate struct {
	Keyvault   string    `toml:"keyvault"`
	Input      string    `toml:"input"`
	Inline     string    `toml:"inline"`
	Output     string    `toml:"output"`
	Mode       *int      `toml:"mode"`
	Owner      string    `toml:"owner"`
	Run        string    `toml:"run"`
	RunTimeout *duration `toml:"runtimeout"`

	Args map[string]interface{} `toml:"args"`
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
