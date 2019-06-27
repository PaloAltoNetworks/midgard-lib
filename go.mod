module go.aporeto.io/midgard-lib

go 1.12

require (
	cloud.google.com/go v0.40.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/opentracing/opentracing-go v1.1.0
	github.com/smartystreets/goconvey v0.0.0-20190330032615-68dc04aab96a
	go.aporeto.io/addedeffect v1.41.1
	go.aporeto.io/elemental v1.56.0
	go.aporeto.io/gaia v14.278.0+incompatible
	go.aporeto.io/manipulate v1.69.0
	go.aporeto.io/tg v1.15.1
	go.uber.org/zap v1.10.0
)

replace go.aporeto.io/gaia => ../gaia
