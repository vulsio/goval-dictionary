.PHONY: \
	all \
	build \
	install \
	lint \
	golangci \
	vet \
	fmt \
	mlint \
	fmtcheck \
	pretest \
	test \
	unused \
	cov \
	clean \
	build-integration \
	clean-integration \
	fetch-rdb \
	fetch-redis \
	diff-cveid \
	diff-package \
	diff-server-rdb \
	diff-server-redis \
	diff-server-rdb-redis

SRCS = $(shell git ls-files '*.go')
PKGS = $(shell go list ./...)
VERSION := $(shell git describe --tags --abbrev=0)
REVISION := $(shell git rev-parse --short HEAD)
LDFLAGS := -X 'github.com/vulsio/goval-dictionary/config.Version=$(VERSION)' \
	-X 'github.com/vulsio/goval-dictionary/config.Revision=$(REVISION)'
GO := CGO_ENABLED=0 go

all: build test

build: main.go
	$(GO) build -a -ldflags "$(LDFLAGS)" -o goval-dictionary $<

install: main.go
	$(GO) install -ldflags "$(LDFLAGS)"

lint:
	go install github.com/mgechev/revive@latest
	revive -config ./.revive.toml -formatter plain $(PKGS)

golangci:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run

vet:
	echo $(PKGS) | xargs env $(GO) vet || exit;

fmt:
	gofmt -s -w $(SRCS)

fmtcheck:
	$(foreach file,$(SRCS),gofmt -s -d $(file);)

pretest: lint vet fmtcheck

test: pretest
	$(GO) test -cover -v ./... || exit;

cov:
	@ go get -v github.com/axw/gocov/gocov
	@ go get golang.org/x/tools/cmd/cover
	gocov test | gocov report

clean:
	echo $(PKGS) | xargs go clean || exit;
	echo $(PKGS) | xargs go clean || exit;

PWD := $(shell pwd)
BRANCH := $(shell git symbolic-ref --short HEAD)
build-integration:
	@ git stash save
	$(GO) build -ldflags "$(LDFLAGS)" -o integration/goval-dict.new
	git checkout $(shell git describe --tags --abbrev=0)
	@git reset --hard
	$(GO) build -ldflags "$(LDFLAGS)" -o integration/goval-dict.old
	git checkout $(BRANCH)
	@ git stash apply stash@{0} && git stash drop stash@{0}

clean-integration:
	-pkill goval-dict.old
	-pkill goval-dict.new
	-rm integration/goval-dict.old integration/goval-dict.new integration/oval.old.sqlite3 integration/oval.new.sqlite3
	-rm -rf integration/diff
	-docker kill redis-old redis-new
	-docker rm redis-old redis-new

fetch-rdb:
	integration/goval-dict.old fetch debian --dbpath=$(PWD)/integration/oval.old.sqlite3 7 8 9 10 11
	integration/goval-dict.old fetch ubuntu --dbpath=$(PWD)/integration/oval.old.sqlite3 14.04 16.04 18.04 20.04 21.04 21.10 22.04 22.10 23.04
	integration/goval-dict.old fetch redhat --dbpath=$(PWD)/integration/oval.old.sqlite3 5 6 7 8 9
	integration/goval-dict.old fetch oracle --dbpath=$(PWD)/integration/oval.old.sqlite3 5 6 7 8 9
	integration/goval-dict.old fetch amazon --dbpath=$(PWD)/integration/oval.old.sqlite3 1 2 2022 2023
	integration/goval-dict.old fetch alpine --dbpath=$(PWD)/integration/oval.old.sqlite3 3.2 3.3 3.4 3.5 3.6 3.7 3.8 3.9 3.10 3.11 3.12 3.13 3.14 3.15 3.16 3.17
	integration/goval-dict.old fetch suse --dbpath=$(PWD)/integration/oval.old.sqlite3 --suse-type opensuse 10.2 10.3 11.0 11.1 11.2 11.3 11.4 12.1 12.2 12.3 13.1 13.2 tumbleweed
	integration/goval-dict.old fetch suse --dbpath=$(PWD)/integration/oval.old.sqlite3 --suse-type opensuse-leap 42.1 42.2 42.3 15.0 15.1 15.2 15.3
	integration/goval-dict.old fetch suse --dbpath=$(PWD)/integration/oval.old.sqlite3 --suse-type suse-enterprise-server 9 10 11 12 15
	integration/goval-dict.old fetch suse --dbpath=$(PWD)/integration/oval.old.sqlite3 --suse-type suse-enterprise-desktop 10 11 12 15
	integration/goval-dict.old fetch fedora --dbpath=$(PWD)/integration/oval.old.sqlite3 32 33 34 35

	integration/goval-dict.new fetch debian --dbpath=$(PWD)/integration/oval.new.sqlite3 7 8 9 10 11
	integration/goval-dict.new fetch ubuntu --dbpath=$(PWD)/integration/oval.new.sqlite3 14.04 16.04 18.04 20.04 21.04 21.10 22.04 22.10 23.04
	integration/goval-dict.new fetch redhat --dbpath=$(PWD)/integration/oval.new.sqlite3 5 6 7 8 9
	integration/goval-dict.new fetch oracle --dbpath=$(PWD)/integration/oval.new.sqlite3 5 6 7 8 9
	integration/goval-dict.new fetch amazon --dbpath=$(PWD)/integration/oval.new.sqlite3 1 2 2022 2023
	integration/goval-dict.new fetch alpine --dbpath=$(PWD)/integration/oval.new.sqlite3 3.2 3.3 3.4 3.5 3.6 3.7 3.8 3.9 3.10 3.11 3.12 3.13 3.14 3.15 3.16 3.17
	integration/goval-dict.new fetch suse --dbpath=$(PWD)/integration/oval.new.sqlite3 --suse-type opensuse 10.2 10.3 11.0 11.1 11.2 11.3 11.4 12.1 12.2 12.3 13.1 13.2 tumbleweed
	integration/goval-dict.new fetch suse --dbpath=$(PWD)/integration/oval.new.sqlite3 --suse-type opensuse-leap 42.1 42.2 42.3 15.0 15.1 15.2 15.3
	integration/goval-dict.new fetch suse --dbpath=$(PWD)/integration/oval.new.sqlite3 --suse-type suse-enterprise-server 9 10 11 12 15
	integration/goval-dict.new fetch suse --dbpath=$(PWD)/integration/oval.new.sqlite3 --suse-type suse-enterprise-desktop 10 11 12 15
	integration/goval-dict.new fetch fedora --dbpath=$(PWD)/integration/oval.new.sqlite3 32 33 34 35

fetch-redis:
	docker run --name redis-old -d -p 127.0.0.1:6379:6379 redis
	docker run --name redis-new -d -p 127.0.0.1:6380:6379 redis

	integration/goval-dict.old fetch debian --dbtype redis --dbpath "redis://127.0.0.1:6379/0" 7 8 9 10 11
	integration/goval-dict.old fetch ubuntu --dbtype redis --dbpath "redis://127.0.0.1:6379/0" 14.04 16.04 18.04 20.04 21.04 21.10 22.04 22.10 23.04
	integration/goval-dict.old fetch redhat --dbtype redis --dbpath "redis://127.0.0.1:6379/0" 5 6 7 8 9
	integration/goval-dict.old fetch oracle --dbtype redis --dbpath "redis://127.0.0.1:6379/0" 5 6 7 8 9
	integration/goval-dict.old fetch amazon --dbtype redis --dbpath "redis://127.0.0.1:6379/0" 1 2 2022 2023
	integration/goval-dict.old fetch alpine --dbtype redis --dbpath "redis://127.0.0.1:6379/0" 3.2 3.3 3.4 3.5 3.6 3.7 3.8 3.9 3.10 3.11 3.12 3.13 3.14 3.15 3.16 3.17
	integration/goval-dict.old fetch suse --dbtype redis --dbpath "redis://127.0.0.1:6379/0" --suse-type opensuse 10.2 10.3 11.0 11.1 11.2 11.3 11.4 12.1 12.2 12.3 13.1 13.2 tumbleweed
	integration/goval-dict.old fetch suse --dbtype redis --dbpath "redis://127.0.0.1:6379/0" --suse-type opensuse-leap 42.1 42.2 42.3 15.0 15.1 15.2 15.3
	integration/goval-dict.old fetch suse --dbtype redis --dbpath "redis://127.0.0.1:6379/0" --suse-type suse-enterprise-server 9 10 11 12 15
	integration/goval-dict.old fetch suse --dbtype redis --dbpath "redis://127.0.0.1:6379/0" --suse-type suse-enterprise-desktop 10 11 12 15
	integration/goval-dict.old fetch fedora --dbtype redis --dbpath "redis://127.0.0.1:6379/0" 32 33 34 35

	integration/goval-dict.new fetch debian --dbtype redis --dbpath "redis://127.0.0.1:6380/0" 7 8 9 10 11
	integration/goval-dict.new fetch ubuntu --dbtype redis --dbpath "redis://127.0.0.1:6380/0" 14.04 16.04 18.04 20.04 21.04 21.10 22.04 22.10 23.04
	integration/goval-dict.new fetch redhat --dbtype redis --dbpath "redis://127.0.0.1:6380/0" 5 6 7 8 9
	integration/goval-dict.new fetch oracle --dbtype redis --dbpath "redis://127.0.0.1:6380/0" 5 6 7 8 9
	integration/goval-dict.new fetch amazon --dbtype redis --dbpath "redis://127.0.0.1:6380/0" 1 2 2022 2023
	integration/goval-dict.new fetch alpine --dbtype redis --dbpath "redis://127.0.0.1:6380/0" 3.2 3.3 3.4 3.5 3.6 3.7 3.8 3.9 3.10 3.11 3.12 3.13 3.14 3.15 3.16 3.17
	integration/goval-dict.new fetch suse --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --suse-type opensuse 10.2 10.3 11.0 11.1 11.2 11.3 11.4 12.1 12.2 12.3 13.1 13.2 tumbleweed
	integration/goval-dict.new fetch suse --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --suse-type opensuse-leap 42.1 42.2 42.3 15.0 15.1 15.2 15.3
	integration/goval-dict.new fetch suse --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --suse-type suse-enterprise-server 9 10 11 12 15
	integration/goval-dict.new fetch suse --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --suse-type suse-enterprise-desktop 10 11 12 15
	integration/goval-dict.new fetch fedora --dbtype redis --dbpath "redis://127.0.0.1:6380/0" 32 33 34 35

diff-cveid:
	@ python integration/diff_server_mode.py --sample-rate 0.01 cveid debian 7 8 9 10 11
	@ python integration/diff_server_mode.py --sample-rate 0.01 cveid ubuntu 14.04 16.04 18.04 20.04 21.04 21.10 22.04 22.10 23.04
	@ python integration/diff_server_mode.py --sample-rate 0.01 cveid redhat 5 6 7 8 9
	@ python integration/diff_server_mode.py --sample-rate 0.01 cveid oracle 5 6 7 8 9
	@ python integration/diff_server_mode.py --sample-rate 0.01 --arch x86_64 cveid oracle 5 6 7 8 9
	@ python integration/diff_server_mode.py --sample-rate 0.01 cveid amazon 1 2 2022 2023
	@ python integration/diff_server_mode.py --sample-rate 0.01 --arch x86_64 cveid amazon 1 2 2022 2023
	@ python integration/diff_server_mode.py --sample-rate 0.01 --arch aarch64 cveid amazon 2 2022 2023
	@ python integration/diff_server_mode.py --sample-rate 0.01 cveid alpine 3.2 3.3 3.4 3.5 3.6 3.7 3.8 3.9 3.10 3.11 3.12 3.13 3.14 3.15 3.16 3.17
	@ python integration/diff_server_mode.py --sample-rate 0.01 cveid suse --suse-type opensuse 10.2 10.3 11.0 11.1 11.2 11.3 11.4 12.1 12.2 12.3 13.1 13.2 tumbleweed
	@ python integration/diff_server_mode.py --sample-rate 0.01 cveid suse --suse-type opensuse.leap 42.1 42.2 42.3 15.0 15.1 15.2 15.3
	@ python integration/diff_server_mode.py --sample-rate 0.01 cveid suse --suse-type suse.linux.enterprise.server 9 10 11 12 15
	@ python integration/diff_server_mode.py --sample-rate 0.01 cveid suse --suse-type suse.linux.enterprise.desktop 10 11 12 15
	@ python integration/diff_server_mode.py --sample-rate 0.01 cveid fedora 32 33 34 35


diff-package:
	@ python integration/diff_server_mode.py --sample-rate 0.01 package debian 7 8 9 10 11
	@ python integration/diff_server_mode.py --sample-rate 0.01 package ubuntu 14.04 16.04 18.04 20.04 21.04 21.10 22.04 22.10 23.04
	@ python integration/diff_server_mode.py --sample-rate 0.01 package redhat 5 6 7 8 9
	@ python integration/diff_server_mode.py --sample-rate 0.01 package oracle 5 6 7 8 9
	@ python integration/diff_server_mode.py --sample-rate 0.01 --arch x86_64 package oracle 5 6 7 8 9
	@ python integration/diff_server_mode.py --sample-rate 0.01 package amazon 1 2 2022 2023
	@ python integration/diff_server_mode.py --sample-rate 0.01 --arch x86_64 package amazon 1 2 2022 2023
	@ python integration/diff_server_mode.py --sample-rate 0.01 --arch aarch64 package amazon 2 2022 2023
	@ python integration/diff_server_mode.py --sample-rate 0.01 package alpine 3.2 3.3 3.4 3.5 3.6 3.7 3.8 3.9 3.10 3.11 3.12 3.13 3.14 3.15 3.16 3.17
	@ python integration/diff_server_mode.py --sample-rate 0.01 package suse --suse-type opensuse 10.2 10.3 11.0 11.1 11.2 11.3 11.4 12.1 12.2 12.3 13.1 13.2 tumbleweed
	@ python integration/diff_server_mode.py --sample-rate 0.01 package suse --suse-type opensuse.leap 42.1 42.2 42.3 15.0 15.1 15.2 15.3
	@ python integration/diff_server_mode.py --sample-rate 0.01 package suse --suse-type suse.linux.enterprise.server 9 10 11 12 15
	@ python integration/diff_server_mode.py --sample-rate 0.01 package suse --suse-type suse.linux.enterprise.desktop 10 11 12 15
	@ python integration/diff_server_mode.py --sample-rate 0.01 package fedora 32 33 34 35

diff-server-rdb:
	integration/goval-dict.old server --dbpath=$(PWD)/integration/oval.old.sqlite3 --port 1325 > /dev/null 2>&1 &
	integration/goval-dict.new server --dbpath=$(PWD)/integration/oval.new.sqlite3 --port 1326 > /dev/null 2>&1 &
	make diff-cveid
	make diff-package
	pkill goval-dict.old
	pkill goval-dict.new

diff-server-redis:
	integration/goval-dict.old server --dbtype redis --dbpath "redis://127.0.0.1:6379/0" --port 1325 > /dev/null 2>&1 &
	integration/goval-dict.new server --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --port 1326 > /dev/null 2>&1 &
	make diff-cveid
	make diff-package
	pkill goval-dict.old
	pkill goval-dict.new

diff-server-rdb-redis:
	integration/goval-dict.new server --dbpath=$(PWD)/integration/oval.new.sqlite3 --port 1325 > /dev/null 2>&1 &
	integration/goval-dict.new server --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --port 1326 > /dev/null 2>&1 &
	make diff-cveid
	make diff-package
	pkill goval-dict.new
