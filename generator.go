package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"
	"syscall"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/jjjordanmsft/az-template/keyvault"
)

type Generator struct {
	Name        string
	Func        func() ([]byte, error)
	OutputFile  string
	OutputMode  os.FileMode
	OutputOwner string
	Sentinel    string
	hash        string
}

func (gen *Generator) Generate() error {
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
		log.WithError(err).Infof("Error opening file: %s", gen.OutputFile)
		return err
	}

	fd.Write(dat)
	fd.Close()

	if err := os.Remove(gen.OutputFile); err != nil {
		log.WithError(err).Warn("Failed to remove original file (OK)")
	}
	if err := os.Rename(tmpfile, gen.OutputFile); err != nil {
		log.WithError(err).Errorf("Failed to update output file: %s", gen.OutputFile)
		return err
	}

	gen.hash = sb

	if gen.Sentinel != "" {
		if err := ioutil.WriteFile(gen.Sentinel, []byte{}, 0666); err != nil {
			log.WithError(err).Warnf("Failed to update sentinel: %s", gen.Sentinel)
		}
	}

	return nil
}

func downloadSecretToFile(ctx keyvault.TemplateContext, cfg configFile) (*Generator, error) {
	kv, err := ctx.GetClient(cfg.Keyvault)
	if err != nil {
		return nil, err
	}

	return &Generator{
		Name: fmt.Sprintf("Write secret '%s' to '%s'", cfg.Secret, cfg.Output),
		Func: func() ([]byte, error) {
			b, err := kv.GetSecret(cfg.Secret)
			if err != nil {
				return []byte{}, errors.Wrap(err, fmt.Sprintf("Error when fetching '%s' from '%s'", cfg.Secret, kv.Name))
			}

			return []byte(*b.Value), nil
		},
		OutputFile:  cfg.Output,
		OutputMode:  getMode(cfg.Mode, 0600),
		OutputOwner: cfg.Owner,
		Sentinel:    cfg.Sentinel,
	}, nil
}

func processTemplate(ctx keyvault.TemplateContext, cfg configTemplate) (*Generator, error) {
	if cfg.Keyvault != "" {
		ctx = keyvault.WrapContext(ctx, cfg.Keyvault)
	}

	name := path.Base(cfg.Input)
	name = name[:len(name)-len(path.Ext(name))]
	fmap := sprig.TxtFuncMap()
	keyvault.GetFuncs(ctx).Populate(fmap)
	tmpl := template.New(name).Funcs(fmap)

	tmpl, err := tmpl.ParseFiles(cfg.Input)
	if err != nil {
		return nil, err
	}

	return &Generator{
		Name: fmt.Sprintf("Process template '%s' to '%s'", cfg.Input, cfg.Output),
		Func: func() ([]byte, error) {
			var buf bytes.Buffer
			err := tmpl.Templates()[0].Execute(&buf, nil)
			return buf.Bytes(), err
		},
		OutputFile:  cfg.Output,
		OutputMode:  getMode(cfg.Mode, 0600),
		OutputOwner: cfg.Owner,
		Sentinel:    cfg.Sentinel,
	}, nil
}

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

func setOwner(file, owner string) error {
	if owner == "" {
		return nil
	}

	uid := 0
	gid := 0

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
