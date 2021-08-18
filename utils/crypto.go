package utils

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"github.com/jjjordanmsft/az-template/keyvault"
)

func toCER(iface interface{}) (string, error) {
	switch v := iface.(type) {
	case *x509.Certificate:
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.Raw})), nil
	case *keyvault.CertResult:
		if v.Certificate == nil {
			return "", errors.New("nil Certificate")
		} else {
			return toCER(v.Certificate)
		}
	case *keyvault.SecretResult:
		if v.Certificate == nil {
			return "", errors.New("nil Certificate")
		} else {
			return toCER(v.Certificate)
		}
	default:
		return "", errors.New("Unsupported type to tocer")
	}
}

func toPKCS8(key interface{}) (string, error) {
	switch v := key.(type) {
	case *keyvault.SecretResult:
		if v.Key == nil {
			return "", errors.New("nil key")
		} else {
			return toPKCS8(v.Key)
		}

	default:
		raw, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return "", err
		} else {
			return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})), nil
		}
	}
}

func toPKCS1Private(c interface{}) (string, error) {
	switch v := c.(type) {
	case *rsa.PrivateKey:
		return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(v)})), nil
	case *keyvault.SecretResult:
		if v.Key == nil {
			return "", errors.New("nil key")
		} else {
			return toPKCS1Private(v.Key)
		}

	default:
		return "", errors.New("Unsupported type to topkcs1private")
	}
}

func toPKCS1Public(c interface{}) (string, error) {
	switch v := c.(type) {
	case *rsa.PublicKey:
		return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(v)})), nil
	case *keyvault.SecretResult:
		if v.Key == nil {
			return "", errors.New("nil key")
		} else {
			return toPKCS1Public(v.Certificate)
		}
	case *x509.Certificate:
		return toPKCS1Public(v.PublicKey)
	case *keyvault.CertResult:
		if v.Certificate == nil {
			return "", errors.New("nil certificate")
		} else {
			return toPKCS1Public(v.Certificate)
		}

	default:
		return "", errors.New("Unsupported type to topkcs1public")
	}
}

func toCERChain(c interface{}, direction ...int) (string, error) {
	switch v := c.(type) {
	case *keyvault.SecretResult:
		return toCERChain(v.Chain, direction...)
	case *keyvault.CertResult:
		return toCERChain(v.Chain, direction...)
	case []*x509.Certificate:
		var buf bytes.Buffer

		if len(direction) != 1 || direction[0] >= 0 {
			for _, c := range v {
				pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
			}
		} else {
			for i := len(v) - 1; i >= 0; i-- {
				pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: v[i].Raw})
			}
		}

		return buf.String(), nil
	default:
		return "", errors.New("Unsupported type to tocerchain")
	}
}

func parsePEM(c interface{}) (*keyvault.ParsedSecret, error) {
	switch v := c.(type) {
	case string:
		return keyvault.ParsePEMData([]byte(v))
	case []byte:
		return keyvault.ParsePEMData(v)
	default:
		return nil, errors.New("Unsupported type to parsepem")
	}
}

func thumb(c interface{}) (string, error) {
	switch v := c.(type) {
	case *x509.Certificate:
		h := sha1.New().Sum(v.Raw)
		return hex.EncodeToString(h), nil
	case *keyvault.CertResult:
		return v.Thumbprint, nil
	case *keyvault.SecretResult:
		return thumb(v.Certificate)
	case *keyvault.ParsedSecret:
		return thumb(v.Certificate)
	default:
		return "", errors.New("Unsupported type to thumb")
	}
}
