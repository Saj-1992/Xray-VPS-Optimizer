SHELL := /usr/bin/env bash

.PHONY: build lint fmt test clean

build:
	bash build.sh

lint: build
	shellcheck dist/server-tools.sh build.sh tests/smoke.sh tests/unit.sh tools/merge-isp.sh
	shfmt -i 2 -ci -d src build.sh tests

fmt:
	shfmt -i 2 -ci -w src build.sh tests

test:
	bash tests/smoke.sh
	bash tests/unit.sh

clean:
	rm -f dist/server-tools.sh
