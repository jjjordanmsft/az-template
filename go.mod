module github.com/jjjordanmsft/az-template

require (
	contrib.go.opencensus.io/exporter/ocagent v0.4.6 // indirect
	github.com/Azure/azure-sdk-for-go v25.1.0+incompatible
	github.com/Azure/go-autorest v11.5.0+incompatible
	github.com/BurntSushi/toml v0.3.1
	github.com/Masterminds/goutils v1.1.0 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/sprig v2.22.0+incompatible
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/dimchansky/utfbom v1.1.0 // indirect
	github.com/google/uuid v1.1.1 // indirect
	github.com/huandu/xstrings v1.3.0 // indirect
	github.com/imdario/mergo v0.3.8 // indirect
	github.com/mitchellh/copystructure v1.0.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.4.2
	go.opencensus.io v0.19.0 // indirect
	golang.org/x/crypto v0.0.0-20190222235706-ffb98f73852f // indirect
)

// Workaround: https://www.gitmemory.com/issue/Azure/go-autorest/449/520897732
replace contrib.go.opencensus.io/exporter/ocagent => contrib.go.opencensus.io/exporter/ocagent v0.4.7

go 1.13
