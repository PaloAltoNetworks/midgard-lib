include domingo.mk

PROJECT_NAME := midgard-lib

ci: domingo_contained_build

init: install_monolithe install_monolithe_plugins codegen domingo_init
test: domingo_test
release: build

## Code generation

install_monolithe:
	pip install -U git+https://github.com/aporeto-inc/monolithe.git

install_monolithe_plugins:
	pip install -U 'git+https://github.com/aporeto-inc/elemental.git@${ELEMENTAL_VERSION}#subdirectory=monolithe'

build:
