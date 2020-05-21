module go.aporeto.io/midgard-lib

go 1.13

require (
	go.aporeto.io/elemental v1.100.1-0.20200507181306-04bb5d99c40b
	go.aporeto.io/gaia v1.94.1-0.20200507181343-1afc93b1db22
	go.aporeto.io/tg v1.34.1-0.20200407170614-39186fcd83e1
)

require (
	cloud.google.com/go v0.53.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/opentracing/opentracing-go v1.1.0
	github.com/smartystreets/goconvey v1.6.4
	go.uber.org/zap v1.14.0
	golang.org/x/tools v0.0.0-20200226171234-020676185e75 // indirect
)

replace go.aporeto.io/gaia => go.aporeto.io/gaia v1.94.1-0.20200520061514-ef2c396bd7c2
