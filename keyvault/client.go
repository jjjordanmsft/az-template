package keyvault

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"time"

	"golang.org/x/crypto/pkcs12"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/pkg/errors"
)

// Client presents a simple interface to a keyvault client and provides caching.
type Client struct {
	name            string
	baseUrl         string
	client          keyvault.BaseClient
	secretCache     map[string]*secretCacheItem
	certCache       map[string]*certCacheItem
	keyCache        map[string]*keyCacheItem
	certListCache   *certListCacheItem
	secretListCache *secretListCacheItem
}

type secretCacheItem struct {
	stale          bool
	currentVersion string
	versions       map[string]*keyvault.SecretBundle
	parsed         map[string]*ParsedSecret
}

type ParsedSecret struct {
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
	Key         interface{}
}

type certCacheItem struct {
	stale          bool
	currentVersion string
	versions       map[string]*keyvault.CertificateBundle
	parsed         map[string]*ParsedSecret
}

type keyCacheItem struct {
	stale          bool
	currentVersion string
	versions       map[string]*keyvault.KeyBundle
}

type certListCacheItem struct {
	stale   bool
	results []*keyvault.CertificateItem
}

type secretListCacheItem struct {
	stale   bool
	results []*keyvault.SecretItem
}

// Name returns the client name
func (c *Client) Name() string {
	return c.name
}

// GetSecret retrieves the latest version of the specified secret
func (c *Client) GetSecret(secret string) (*keyvault.SecretBundle, *ParsedSecret, error) {
	cache, ok := c.secretCache[secret]
	if !ok {
		cache = &secretCacheItem{
			stale:    true,
			versions: make(map[string]*keyvault.SecretBundle),
			parsed:   make(map[string]*ParsedSecret),
		}

		c.secretCache[secret] = cache
	}

	if cache.stale {
		ver, err := c.getLatestSecretVersion(secret)
		if err != nil {
			return nil, nil, err
		}

		cache.currentVersion = ver
		cache.stale = false
	}

	if bundle, ok := cache.versions[cache.currentVersion]; ok {
		return bundle, cache.parsed[cache.currentVersion], nil
	} else if bundle, err := c.client.GetSecret(context.Background(), c.baseUrl, secret, cache.currentVersion); err != nil {
		return nil, nil, err
	} else {
		parsed := parseSecret(&bundle)
		cache.versions[cache.currentVersion] = &bundle
		cache.parsed[cache.currentVersion] = parsed
		return &bundle, parsed, nil
	}
}

// GetCertificate retrieves the latest version of the specified certificate
func (c *Client) GetCertificate(cert string) (*keyvault.CertificateBundle, *ParsedSecret, error) {
	cache, ok := c.certCache[cert]
	if !ok {
		cache = &certCacheItem{
			stale:    true,
			versions: make(map[string]*keyvault.CertificateBundle),
			parsed:   make(map[string]*ParsedSecret),
		}

		c.certCache[cert] = cache
	}

	if cache.stale {
		ver, err := c.getLatestCertificateVersion(cert)
		if err != nil {
			return nil, nil, err
		}

		cache.currentVersion = ver
		cache.stale = false
	}

	if bundle, ok := cache.versions[cache.currentVersion]; ok {
		return bundle, cache.parsed[cache.currentVersion], nil
	} else if bundle, err := c.client.GetCertificate(context.Background(), c.baseUrl, cert, cache.currentVersion); err != nil {
		return nil, nil, err
	} else if xcert, err := x509.ParseCertificates(*bundle.Cer); err != nil {
		return nil, nil, err
	} else {
		p := &ParsedSecret{}
		p.AddCerts(xcert)
		cache.versions[cache.currentVersion] = &bundle
		cache.parsed[cache.currentVersion] = p
		return &bundle, p, nil
	}
}

func (c *Client) GetKey(key string) (*keyvault.KeyBundle, error) {
	cache, ok := c.keyCache[key]
	if !ok {
		kci := &keyCacheItem{
			stale:    true,
			versions: make(map[string]*keyvault.KeyBundle),
		}

		c.keyCache[key] = kci
	}

	if cache.stale {
		ver, err := c.getLatestKeyVersion(key)
		if err != nil {
			return nil, err
		}

		cache.currentVersion = ver
		cache.stale = false
	}

	if bundle, ok := cache.versions[cache.currentVersion]; ok {
		return bundle, nil
	} else if bundle, err := c.client.GetKey(context.Background(), c.baseUrl, key, cache.currentVersion); err != nil {
		return nil, err
	} else {
		cache.versions[cache.currentVersion] = &bundle
		return &bundle, nil
	}
}

// ListCertificates returns all certificates in the keyvault
func (c *Client) ListCertificates() ([]*keyvault.CertificateItem, error) {
	if c.certListCache == nil {
		c.certListCache = &certListCacheItem{
			stale: true,
		}
	}

	if c.certListCache.stale {
		var includePending bool = false
		var results []*keyvault.CertificateItem

		lst, err := c.client.GetCertificates(context.Background(), c.baseUrl, nil, &includePending)
		if err != nil {
			return results, err
		}

		for ; lst.NotDone(); lst.Next() {
			for _, crt := range lst.Values() {
				c := crt
				results = append(results, &c)
			}
		}

		c.certListCache.results = results
		c.certListCache.stale = false
	}

	return c.certListCache.results, nil
}

func (c *Client) ListSecrets() ([]*keyvault.SecretItem, error) {
	if c.secretListCache == nil {
		c.secretListCache = &secretListCacheItem{
			stale: true,
		}
	}

	if c.secretListCache.stale {
		var results []*keyvault.SecretItem

		lst, err := c.client.GetSecrets(context.Background(), c.baseUrl, nil)
		if err != nil {
			return results, err
		}

		for ; lst.NotDone(); lst.Next() {
			for _, sec := range lst.Values() {
				s := sec
				results = append(results, &s)
			}
		}

		c.secretListCache.results = results
		c.secretListCache.stale = false
	}

	return c.secretListCache.results, nil
}

func (c *Client) getLatestSecretVersion(secret string) (string, error) {
	var maxresults int32 = 20
	lst, err := c.client.GetSecretVersions(context.Background(), c.baseUrl, secret, &maxresults)
	if err != nil {
		return "", errors.Wrap(err, "Failed to list secret versions")
	}

	var latest keyvault.SecretItem
	first := true
	for ; lst.NotDone(); lst.Next() {
		for _, sec := range lst.Values() {
			if first {
				first = false
				latest = sec
			} else if secretDate(latest) < secretDate(sec) {
				latest = sec
			}
		}
	}

	if first {
		return "", errors.New("No secrets returned")
	}

	idParts := strings.Split(*latest.ID, "/")
	idVersion := idParts[len(idParts)-1]

	return idVersion, nil
}

func secretDate(itm keyvault.SecretItem) time.Duration {
	atr := itm.Attributes
	if atr.Created != nil && atr.Updated != nil {
		if atr.Created.Duration() > atr.Updated.Duration() {
			return (*atr.Created).Duration()
		} else {
			return (*atr.Updated).Duration()
		}
	} else if atr.Created != nil {
		return (*atr.Created).Duration()
	} else if atr.Updated != nil {
		return (*atr.Updated).Duration()
	} else {
		return date.UnixTime(date.UnixEpoch()).Duration()
	}
}

func (c *Client) getLatestCertificateVersion(cert string) (string, error) {
	var maxresults int32 = 20
	lst, err := c.client.GetCertificateVersions(context.Background(), c.baseUrl, cert, &maxresults)
	if err != nil {
		return "", errors.Wrap(err, "Failed to list certificate versions")
	}

	var latest keyvault.CertificateItem
	first := true
	for ; lst.NotDone(); lst.Next() {
		for _, crt := range lst.Values() {
			if first {
				first = false
				latest = crt
			} else if certDate(latest) < certDate(crt) {
				latest = crt
			}
		}
	}

	if first {
		return "", errors.New("No certificates returned")
	}

	idParts := strings.Split(*latest.ID, "/")
	idVersion := idParts[len(idParts)-1]

	return idVersion, nil
}

func certDate(itm keyvault.CertificateItem) time.Duration {
	atr := itm.Attributes
	if atr.Created != nil && atr.Updated != nil {
		if atr.Created.Duration() > atr.Updated.Duration() {
			return (*atr.Created).Duration()
		} else {
			return (*atr.Updated).Duration()
		}
	} else if atr.Created != nil {
		return (*atr.Created).Duration()
	} else if atr.Updated != nil {
		return (*atr.Updated).Duration()
	} else {
		return date.UnixTime(date.UnixEpoch()).Duration()
	}
}

func (c *Client) getLatestKeyVersion(key string) (string, error) {
	var maxresults int32 = 20
	lst, err := c.client.GetKeyVersions(context.Background(), c.baseUrl, key, &maxresults)
	if err != nil {
		return "", errors.Wrap(err, "Failed to list key versions")
	}

	var latest keyvault.KeyItem
	first := true
	for ; lst.NotDone(); lst.Next() {
		for _, k := range lst.Values() {
			if first {
				first = false
				latest = k
			} else if keyDate(latest) < keyDate(k) {
				latest = k
			}
		}
	}

	if first {
		return "", errors.New("No keys returned")
	}

	idParts := strings.Split(*latest.Kid, "/")
	idVersion := idParts[len(idParts)-1]

	return idVersion, nil
}

func keyDate(itm keyvault.KeyItem) time.Duration {
	atr := itm.Attributes
	if atr.Created != nil && atr.Updated != nil {
		if atr.Created.Duration() > atr.Updated.Duration() {
			return (*atr.Created).Duration()
		} else {
			return (*atr.Updated).Duration()
		}
	} else if atr.Created != nil {
		return (*atr.Created).Duration()
	} else if atr.Updated != nil {
		return (*atr.Updated).Duration()
	} else {
		return date.UnixTime(date.UnixEpoch()).Duration()
	}
}

// Invalidate clears all caches for this client.
func (c *Client) Invalidate() {
	for _, scache := range c.secretCache {
		scache.stale = true
	}

	for _, ccache := range c.certCache {
		ccache.stale = true
	}

	for _, kcache := range c.keyCache {
		kcache.stale = true
	}

	if c.certListCache != nil {
		c.certListCache.stale = true
	}

	if c.secretListCache != nil {
		c.secretListCache.stale = true
	}
}

func parseSecret(sec *keyvault.SecretBundle) *ParsedSecret {
	var pems []*pem.Block
	if raw, err := base64.StdEncoding.DecodeString(*sec.Value); err == nil {
		pems, err = pkcs12.ToPEM(raw, "")
		if err != nil {
			return &ParsedSecret{}
		}
	} else {
		pems = readPEMs([]byte(*sec.Value))
	}

	return parsePEMs(pems)
}

func ParsePEMData(data []byte) (*ParsedSecret, error) {
	pems := readPEMs(data)
	if len(pems) == 0 {
		return nil, errors.New("No PEM blocks found")
	}

	return parsePEMs(pems), nil
}

func parsePEMs(pems []*pem.Block) *ParsedSecret {
	res := &ParsedSecret{}

	var certs []*x509.Certificate
	for _, p := range pems {
		switch p.Type {
		case "PRIVATE KEY":
			if k, err := x509.ParsePKCS8PrivateKey(p.Bytes); err == nil {
				res.Key = k
			} else if k, err := x509.ParsePKCS1PrivateKey(p.Bytes); err == nil { // NOTE: This can happen if we went the pkcs12 route, above
				res.Key = k
			} else if k, err := x509.ParseECPrivateKey(p.Bytes); err == nil {
				res.Key = k
			}
		case "RSA PRIVATE KEY":
			if k, err := x509.ParsePKCS1PrivateKey(p.Bytes); err == nil {
				res.Key = k
			}
		case "EC PRIVATE KEY":
			if k, err := x509.ParseECPrivateKey(p.Bytes); err == nil {
				res.Key = k
			}
		case "CERTIFICATE":
			if c, err := x509.ParseCertificate(p.Bytes); err == nil {
				certs = append(certs, c)
			}
		}
	}

	res.AddCerts(certs)
	return res
}

func readPEMs(data []byte) []*pem.Block {
	var result []*pem.Block
	for {
		p, rest := pem.Decode(data)
		if p == nil {
			return result
		}

		result = append(result, p)
		data = rest
	}
}

func (ps *ParsedSecret) AddCerts(certs []*x509.Certificate) error {
	leaf, chain, err := sortCerts(certs)
	if err == nil {
		ps.Certificate = leaf
		ps.Chain = chain
	} else if len(certs) == 1 {
		ps.Certificate = certs[0]
		ps.Chain = certs
	} else {
		return err
	}

	return nil
}

func sortCerts(certs []*x509.Certificate) (*x509.Certificate, []*x509.Certificate, error) {
	subjects := make(map[string]*x509.Certificate)
	used := make(map[string]bool)

	for _, cert := range certs {
		subjects[cert.Subject.CommonName] = cert
		used[cert.Subject.CommonName] = false
	}

	var result []*x509.Certificate
	for _, cert := range certs {
		if used[cert.Subject.CommonName] {
			continue
		}

		var sublist []*x509.Certificate
		c := cert
		for {
			sublist = append(sublist, c)
			used[c.Subject.CommonName] = true

			if u, ok := used[c.Issuer.CommonName]; ok && !u {
				if iss, ok := subjects[c.Issuer.CommonName]; ok {
					c = iss
				} else {
					break
				}
			} else {
				break
			}
		}

		result = append(sublist, result...)
	}

	// Verify ...
	for i := 0; i < len(result)-1; i++ {
		if result[i].Issuer.CommonName != result[i+1].Subject.CommonName {
			return nil, result, errors.New("Invalid chain")
		}
	}

	if len(result) == 0 {
		return nil, result, nil
	}

	return result[0], result, nil
}
