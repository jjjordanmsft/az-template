package keyvault

import (
	"crypto/x509"
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

// CertListResult is the type returned by the listcerts function.
type CertListResult struct {
	Name       string
	Thumbprint string
	Version    string
	ID         string
	Tags       map[string]string
}

// CertResult is the type returned by the cert function.
type CertResult struct {
	Name        string
	Thumbprint  string
	Version     string
	ID          string
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
	Tags        map[string]string
}

// SecretListResult is the type returned by the listsecrets function.
type SecretListResult struct {
	Name    string
	Version string
	ID      string
	Managed bool
	Tags    map[string]string
}

// SecretResult is the type returned by the secret function.
type SecretResult struct {
	Name        string
	Version     string
	ID          string
	Value       string
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
	Key         interface{}
	Managed     bool
	Tags        map[string]string
}

type KeyResult struct {
	Name    string
	Version string
	//ID string
	Value interface{}
	Tags  map[string]string
}

// Populate adds keyvault template functions to the specified FuncMap
func (f *Funcs) Populate(m template.FuncMap) {
	m["listcerts"] = f.listCertificates
	m["listsecrets"] = f.listSecrets
	m["secret"] = f.getSecret
	m["cert"] = f.getCertificate
	m["key"] = f.getKey
}

func (f *Funcs) client(kvname ...string) (*Client, error) {
	if len(kvname) == 1 {
		return f.GetClient(kvname[0])
	} else {
		return f.GetClient("")
	}
}

func (f *Funcs) getSecret(secret string, kvname ...string) (*SecretResult, error) {
	cl, err := f.client(kvname...)
	if err != nil {
		return nil, err
	}

	b, p, err := cl.GetSecret(secret)
	if err != nil {
		return nil, err
	}

	id, name, version := splitID(b.ID)
	return &SecretResult{
		Name:        name,
		Version:     version,
		ID:          id,
		Value:       *b.Value,
		Tags:        cvtTags(b.Tags),
		Certificate: p.Certificate,
		Chain:       p.Chain,
		Key:         p.Key,
		Managed:     b.Managed != nil && *b.Managed,
	}, nil
}

func (f *Funcs) listCertificates(kvname ...string) (results []*CertListResult, err error) {
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
		results = append(results, &CertListResult{
			Name:       name,
			Version:    version,
			ID:         id,
			Thumbprint: decodeThumbprint(*ci.X509Thumbprint),
			Tags:       cvtTags(ci.Tags),
		})
	}

	return
}

func (f *Funcs) listSecrets(kvname ...string) (results []*SecretListResult, err error) {
	cl, err := f.client(kvname...)
	if err != nil {
		return
	}

	lst, err := cl.ListSecrets()
	if err != nil {
		return
	}

	for _, si := range lst {
		id, name, version := splitID(si.ID)
		results = append(results, &SecretListResult{
			Name:    name,
			Version: version,
			ID:      id,
			Managed: si.Managed != nil && *si.Managed,
			Tags:    cvtTags(si.Tags),
		})
	}

	return
}

func (f *Funcs) getCertificate(cert string, kvname ...string) (*CertResult, error) {
	cl, err := f.client(kvname...)
	if err != nil {
		return nil, err
	}

	b, p, err := cl.GetCertificate(cert)
	if err != nil {
		return nil, err
	}

	id, name, version := splitID(b.ID)
	return &CertResult{
		Name:        name,
		Thumbprint:  decodeThumbprint(*b.X509Thumbprint),
		Version:     version,
		ID:          id,
		Certificate: p.Certificate,
		Chain:       p.Chain,
		Tags:        cvtTags(b.Tags),
	}, nil
}

func (f *Funcs) getKey(name string, kvname ...string) (*KeyResult, error) {
	cl, err := f.client(kvname...)
	if err != nil {
		return nil, err
	}

	k, err := cl.GetKey(name)
	//id, name, version := splitID(k.Kid)
	return &KeyResult{
		Name: name,
		//Version: version,
		//id: k.Kid,
		Value: k.Key,
		Tags:  cvtTags(k.Tags),
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
