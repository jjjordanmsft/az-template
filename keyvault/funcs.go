package keyvault

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"text/template"
)

// Funcs provides template functions with a TemplateContext to look up
// keyvault Clients.
type Funcs struct {
	TemplateContext
}

// certListResult is the type returned by the listcerts function.
type certListResult struct {
	Name       string
	Thumbprint string
	Version    string
	ID         string
	Tags       map[string]string
}

// certResult is the type returned by the cert function.
type certResult struct {
	Name        string
	Thumbprint  string
	Version     string
	ID          string
	Certificate interface{}
	Tags        map[string]string
}

// secretListResult is the type returned by the (non-existent) listsecrets function.
type secretListResult struct {
	Name    string
	Version string
	ID      string
}

// secretResult is the type returned by the secret function.
type secretResult struct {
	Name    string
	Version string
	ID      string
	Value   string
	Tags    map[string]string
}

// Populate adds keyvault template functions to the specified FuncMap
func (f *Funcs) Populate(m template.FuncMap) {
	m["listcerts"] = f.listCertificates
	m["secret"] = f.getSecret
	m["cert"] = f.getCertificate
}

func (f *Funcs) client(kvname ...string) (*Client, error) {
	if len(kvname) == 1 {
		return f.GetClient(kvname[0])
	} else {
		return f.GetClient("")
	}
}

func (f *Funcs) getSecret(secret string, kvname ...string) (*secretResult, error) {
	cl, err := f.client(kvname...)
	if err != nil {
		return nil, err
	}

	b, err := cl.GetSecret(secret)
	if err != nil {
		return nil, err
	}

	id, name, version := splitID(b.ID)
	return &secretResult{
		Name:    name,
		Version: version,
		ID:      id,
		Value:   *b.Value,
		Tags:    cvtTags(b.Tags),
	}, nil
}

func (f *Funcs) listCertificates(kvname ...string) (results []*certListResult, err error) {
	cl, err := f.client(kvname...)
	if err != nil {
		return
	}

	lst, err := cl.ListCertificates()
	if err != nil {
		return
	}

	for _, ci := range lst {
		id, name, version := splitID(ci.ID)
		results = append(results, &certListResult{
			Name:       name,
			Version:    version,
			ID:         id,
			Thumbprint: decodeThumbprint(*ci.X509Thumbprint),
			Tags:       cvtTags(ci.Tags),
		})
	}

	return
}

func (f *Funcs) getCertificate(cert string, kvname ...string) (*certResult, error) {
	cl, err := f.client(kvname...)
	if err != nil {
		return nil, err
	}

	b, p, err := cl.GetCertificate(cert)
	if err != nil {
		return nil, err
	}

	id, name, version := splitID(b.ID)
	return &certResult{
		Name:        name,
		Thumbprint:  decodeThumbprint(*b.X509Thumbprint),
		Version:     version,
		ID:          id,
		Certificate: p,
		Tags:        cvtTags(b.Tags),
	}, nil
}

// cvtTags rewrites a map[string]*string such that templates can use it
func cvtTags(tags map[string]*string) map[string]string {
	result := make(map[string]string)
	for k, v := range tags {
		if v != nil {
			result[k] = *v
		} else {
			result[k] = ""
		}
	}

	return result
}

// splitID splits a keyvault ID into: id, name, version
func splitID(id *string) (string, string, string) {
	if id == nil {
		return "", "", ""
	}

	u, err := url.Parse(*id)
	if err != nil {
		return *id, "", ""
	}

	uparts := strings.Split(u.Path, "/")
	if len(uparts) >= 4 {
		return *id, uparts[2], uparts[3]
	} else if len(uparts) >= 3 {
		return *id, uparts[2], ""
	} else {
		return *id, "", ""
	}
}

func decodeThumbprint(thumb string) string {
	dc, err := base64.RawURLEncoding.DecodeString(thumb)
	if err != nil {
		return ""
	}

	return hex.EncodeToString(dc)
}
