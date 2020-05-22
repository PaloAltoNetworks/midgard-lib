module go.aporeto.io/midgard-lib

go 1.13

require (
	go.aporeto.io/elemental v1.100.1-0.20200507181306-04bb5d99c40b
	go.aporeto.io/gaia v1.94.1-0.20200521012706-db645176ba31
	go.aporeto.io/tg v1.34.1-0.20200515195223-79e45f8c54f8
)

require (
	cloud.google.com/go v0.53.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/opentracing/opentracing-go v1.1.0
	github.com/smartystreets/goconvey v1.6.4
	go.uber.org/zap v1.14.0
	golang.org/x/tools v0.0.0-20200226171234-020676185e75 // indirect
)


replace go.aporeto.io/gaia => ../gaia
