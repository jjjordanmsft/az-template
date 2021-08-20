package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/Masterminds/sprig"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/jjjordanmsft/az-template/keyvault"
	"github.com/jjjordanmsft/az-template/utils"
)

type GeneratorFunc = func() ([]byte, error)
type GeneratorLoader = func() (GeneratorFunc, error)

// Generator encapsulates the process for generating an output file.
type Generator struct {
	Name        string
	Func        GeneratorFunc
	Loader      GeneratorLoader
	OutputFile  string
	OutputMode  os.FileMode
	OutputOwner string
	Run         string
	RunTimeout  *time.Duration
	hash        string
}

// Generate processes the full generation of the output file.  If the output
// is the same as the last pass, then it won't be rewritten.  If the output
// has changed, this will also invoke the Run command, if any was specified.
func (gen *Generator) Generate() error {
	start := time.Now()
	log.Infof("Generating: %s", gen.Name)
	dat, err := gen.Func()
	if err != nil {
		log.WithError(err).Warn("Generation failed")
		return err
	}

	b := sha256.Sum256(dat)
	sb := string(b[:])
	if sb == gen.hash {
		log.Info("No change detected, skipping")
		return nil
	}

	tmpfile := gen.OutputFile + ".pretem"
	fd, err := os.OpenFile(tmpfile, os.O_TRUNC|os.O_RDWR|os.O_CREATE, gen.OutputMode)
	if err != nil {
		log.WithError(err).Errorf("Error opening file: %s", gen.OutputFile)
		return err
	}

	fd.Write(dat)
	fd.Close()

	if err := os.Remove(gen.OutputFile); err != nil && exists(gen.OutputFile) {
		log.WithError(err).Warn("Failed to remove original file")
	}
	if err := os.Rename(tmpfile, gen.OutputFile); err != nil {
		log.WithError(err).Errorf("Failed to update output file: %s", gen.OutputFile)
		return err
	}

	log.Infof("File generated in %s", time.Since(start).Truncate(time.Millisecond))

	if gen.Run != "" {
		if err := gen.run(); err != nil {
			return err
		}
	}

	gen.hash = sb

	return nil
}

func (gen *Generator) Reload() error {
	f, err := gen.Loader()
	if err != nil {
		return err
	}

	gen.Func = f
	return nil
}

// run invokes the Run command associated with this output.
func (gen *Generator) run() error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}

	ctx := context.Background()
	if gen.RunTimeout != nil {
		ctx, _ = context.WithTimeout(ctx, *gen.RunTimeout)
	}

	err := exec.CommandContext(ctx, shell, "-c", gen.Run).Run()
	if err == nil {
		log.Infof("Command \"%s\" completed successfully", gen.Run)
		return nil
	} else if exerr, ok := err.(*exec.ExitError); ok {
		log.WithFields(log.Fields{"Code": exerr.ExitCode()}).Errorf("Command \"%s\" exited with error", gen.Run)
		log.Info("Process output:\n", exerr.Stderr)
		return errors.New("Process terminated abnormally")
	} else {
		return err
	}
}

// downloadSecretToFile creates a Generator for a full file-generation step.
func downloadSecretToFile(ctx keyvault.TemplateContext, cfg configFile, basePath string) (*Generator, error) {
	kv, err := ctx.GetClient(cfg.Keyvault)
	if err != nil {
		return nil, err
	}

	return &Generator{
		Name: fmt.Sprintf("Write secret '%s' => '%s'", cfg.Secret, cfg.Output),
		Loader: func() (GeneratorFunc, error) {
			return func() ([]byte, error) {
				b, _, err := kv.GetSecret(cfg.Secret)
				if err != nil {
					return []byte{}, errors.Wrap(err, fmt.Sprintf("Error when fetching '%s' from '%s'", cfg.Secret, kv.Name))
				}

				return []byte(*b.Value), nil
			}, nil
		},
		OutputFile:  relPath(basePath, cfg.Output),
		OutputMode:  getMode(cfg.Mode, 0600),
		OutputOwner: cfg.Owner,
		Run:         cfg.Run,
		RunTimeout:  cfg.RunTimeout.DurationPtr(),
	}, nil
}

// processTemplate creates a Generator for a template processing step.
func processTemplate(ctx keyvault.TemplateContext, cfg configTemplate, basePath string) (*Generator, error) {
	if cfg.Keyvault != "" {
		ctx = keyvault.WrapContext(ctx, cfg.Keyvault)
	}

	name := path.Base(cfg.Input)
	name = name[:len(name)-len(path.Ext(name))]
	fmap := sprig.TxtFuncMap()
	keyvault.GetFuncs(ctx).Populate(fmap)
	utils.Populate(fmap)

	return &Generator{
		Name: fmt.Sprintf("Process template '%s' => '%s'", cfg.Input, cfg.Output),
		Loader: func() (GeneratorFunc, error) {
			tmpl := template.New(name).Funcs(fmap)

			if cfg.Inline != "" {
				var err error
				tmpl, err = tmpl.Parse(cfg.Inline)
				if err != nil {
					return nil, err
				}
			} else {
				var err error
				tmpl, err = tmpl.ParseFiles(relPath(basePath, cfg.Input))
				if err != nil {
					return nil, err
				}
			}

			return func() ([]byte, error) {
				var buf bytes.Buffer
				err := tmpl.Templates()[0].Execute(&buf, cfg.Args)
				return buf.Bytes(), err
			}, nil
		},
		OutputFile:  relPath(basePath, cfg.Output),
		OutputMode:  getMode(cfg.Mode, 0600),
		OutputOwner: cfg.Owner,
		Run:         cfg.Run,
		RunTimeout:  cfg.RunTimeout.DurationPtr(),
	}, nil
}

// Sets the owner for the specified file, and deletes it if it fails.
func setOwnerOrDelete(file, owner string) error {
	err := setOwner(file, owner)
	if err != nil {
		log.WithFields(log.Fields{"file": file, "owner": owner}).WithError(err).Error("Failed to change owner")
		if err := syscall.Unlink(file); err != nil {
			log.WithFields(log.Fields{"file": file}).WithError(err).Error("Failed to delete file")
		} else {
			log.Infof("Deleted %s", file)
		}
	}

	return err
}

// Sets the owner:group for the specified file
func setOwner(file, owner string) error {
	if owner == "" {
		return nil
	}

	// Get current ownership
	usr, err := user.Current()
	if err != nil {
		return err
	}

	uid, _ := strconv.Atoi(usr.Uid)
	gid, _ := strconv.Atoi(usr.Gid)

	parts := strings.Split(owner, ":")
	if u, err := strconv.Atoi(parts[0]); err == nil {
		uid = u
		if usr, err := user.LookupId(parts[0]); err == nil {
			gid, _ = strconv.Atoi(usr.Gid)
		}
	} else {
		usr, err := user.Lookup(parts[0])
		if err != nil {
			return err
		}

		uid, _ = strconv.Atoi(usr.Uid)
		gid, _ = strconv.Atoi(usr.Gid)
	}

	if len(parts) == 2 {
		if g, err := strconv.Atoi(parts[1]); err == nil {
			gid = g
		} else {
			if grp, err := user.LookupGroup(parts[1]); err == nil {
				gid, _ = strconv.Atoi(grp.Gid)
			} else {
				return err
			}
		}
	}

	return syscall.Chown(file, uid, gid)
}

func getMode(mode *int, dflt int) os.FileMode {
	if mode == nil {
		return os.FileMode(dflt)
	} else {
		return os.FileMode(*mode)
	}
}

func exists(file string) bool {
	_, err := os.Stat(file)
	return err == nil
}

func relPath(base, p string) string {
	if path.IsAbs(p) {
		return p
	} else {
		return path.Join(base, p)
	}
}
