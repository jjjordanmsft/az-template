package keyvault

import (
	"context"
	"crypto/x509"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.0/keyvault"
	"github.com/Azure/go-autorest/autorest/date"
	"github.com/pkg/errors"
)

type Client struct {
	name          string
	baseUrl       string
	client        keyvault.BaseClient
	secretCache   map[string]*secretCacheItem
	certCache     map[string]*certCacheItem
	certListCache *certListCacheItem
}

type secretCacheItem struct {
	stale          bool
	currentVersion string
	versions       map[string]*keyvault.SecretBundle
}

type certCacheItem struct {
	stale          bool
	currentVersion string
	versions       map[string]*keyvault.CertificateBundle
	parsed         map[string]*x509.Certificate
}

type certListCacheItem struct {
	stale   bool
	results []*keyvault.CertificateItem
}

func (c *Client) Name() string {
	return c.name
}

func (c *Client) GetSecret(secret string) (*keyvault.SecretBundle, error) {
	cache, ok := c.secretCache[secret]
	if !ok {
		cache = &secretCacheItem{
			stale:    true,
			versions: make(map[string]*keyvault.SecretBundle),
		}

		c.secretCache[secret] = cache
	}

	if cache.stale {
		ver, err := c.getLatestSecretVersion(secret)
		if err != nil {
			return nil, err
		}

		cache.currentVersion = ver
		cache.stale = false
	}

	if bundle, ok := cache.versions[cache.currentVersion]; ok {
		return bundle, nil
	} else if bundle, err := c.client.GetSecret(context.Background(), c.baseUrl, secret, cache.currentVersion); err != nil {
		return nil, err
	} else {
		cache.versions[cache.currentVersion] = &bundle
		return &bundle, nil
	}
}

func (c *Client) GetCertificate(cert string) (*keyvault.CertificateBundle, *x509.Certificate, error) {
	cache, ok := c.certCache[cert]
	if !ok {
		cache = &certCacheItem{
			stale:    true,
			versions: make(map[string]*keyvault.CertificateBundle),
			parsed:   make(map[string]*x509.Certificate),
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
	} else if xcert, err := x509.ParseCertificate(*bundle.Cer); err != nil {
		return nil, nil, err
	} else {
		cache.versions[cache.currentVersion] = &bundle
		cache.parsed[cache.currentVersion] = xcert
		return &bundle, xcert, nil
	}
}

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
				c := &crt
				results = append(results, c)
			}
		}

		c.certListCache.results = results
		c.certListCache.stale = false
	}

	return c.certListCache.results, nil
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

func (c *Client) Invalidate() {
	for _, scache := range c.secretCache {
		scache.stale = true
	}

	for _, ccache := range c.certCache {
		ccache.stale = true
	}

	c.certListCache.stale = true
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
