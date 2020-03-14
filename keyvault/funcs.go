package keyvault

import (
	"strings"
	"text/template"
)

type Funcs struct {
	TemplateContext
}

type certListResult struct {
	Name       string
	Thumbprint string
	Version    string
	Tags       map[string]string
}

type certResult struct {
	Name        string
	Thumbprint  string
	Version     string
	Certificate interface{}
	Tags        map[string]string
}

type secretListResult struct {
	Name    string
	Version string
}

type secretResult struct {
	Name    string
	Version string
	Value   string
	Tags    map[string]string
}

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

	name, version := splitID(b.ID)
	return &secretResult{
		Name:    name,
		Version: version,
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
		name, version := splitID(ci.ID)
		results = append(results, &certListResult{
			Name:       name,
			Version:    version,
			Thumbprint: *ci.X509Thumbprint,
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

	name, version := splitID(b.ID)
	return &certResult{
		Name:        name,
		Thumbprint:  *b.X509Thumbprint,
		Version:     version,
		Certificate: p,
		Tags:        cvtTags(b.Tags),
	}, nil
}

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

func splitID(id *string) (string, string) {
	if id == nil {
		return "", ""
	}

	idParts := strings.Split(*id, "/")
	if len(idParts) == 1 {
		return idParts[0], ""
	} else {
		return idParts[0], idParts[1]
	}
}
