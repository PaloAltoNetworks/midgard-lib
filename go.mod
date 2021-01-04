module go.aporeto.io/midgard-lib

go 1.13

require (
	go.aporeto.io/elemental v1.100.1-0.20201110214307-3e4e638fb38b
	go.aporeto.io/gaia v1.95.0
	go.aporeto.io/tg v1.34.1-0.20201026071503-46fe5dfd3023
)

require (
	cloud.google.com/go v0.53.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/opentracing/opentracing-go v1.1.0
	github.com/smartystreets/goconvey v1.6.4
	go.uber.org/zap v1.15.0
)

replace go.aporeto.io/gaia => go.aporeto.io/gaia v1.94.1-0.20200827173832-97fd4ee2be85
