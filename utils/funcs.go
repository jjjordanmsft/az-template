package utils

import (
	"text/template"
)

func Populate(m template.FuncMap) {
	m["topkcs8"] = toPKCS8
	m["topkcs1public"] = toPKCS1Public
	m["topkcs1private"] = toPKCS1Private
	m["tocer"] = toCER
}
