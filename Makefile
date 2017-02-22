include domingo.mk

PROJECT_NAME := midgard-lib

ci: domingo_contained_build

init: domingo_init
test: domingo_test
release: build
build:
