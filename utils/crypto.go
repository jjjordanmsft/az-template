package utils

import (
	"crypto/rsa"
	"crypto/x509"
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
