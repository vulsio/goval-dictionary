.PHONY: \
	build \
	install \
	all \
	vendor \
 	lint \
	vet \
	fmt \
	fmtcheck \
	pretest \
	test \
	cov \
	clean \
	build-integration \
	clean-integration \
	fetch-rdb \
	fetch-redis \
	diff-cveid \
	diff-pakcage \
	diff-server-rdb \
	diff-server-redis \
	diff-server-rdb-redis

SRCS = $(shell git ls-files '*.go')
PKGS =  ./commands ./config ./db ./db/rdb ./fetcher ./models ./util
VERSION := $(shell git describe --tags --abbrev=0)
REVISION := $(shell git rev-parse --short HEAD)
LDFLAGS := -X 'github.com/kotakanbe/goval-dictionary/config.Version=$(VERSION)' \
	-X 'github.com/kotakanbe/goval-dictionary/config.Revision=$(REVISION)'
GO := GO111MODULE=on go
GO_OFF := GO111MODULE=off go

all: build

build: main.go pretest
	$(GO) build -a -ldflags "$(LDFLAGS)" -o goval-dictionary $<

b: 	main.go pretest
	$(GO) build -ldflags "$(LDFLAGS)" -o goval-dictionary $<

install: main.go pretest
	$(GO) install -ldflags "$(LDFLAGS)"

lint:
	$(GO_OFF) get -u golang.org/x/lint/golint
	golint $(PKGS)

vet:
	echo $(PKGS) | xargs env $(GO) vet || exit;

fmt:
	gofmt -s -w $(SRCS)

mlint:
	$(foreach file,$(SRCS),gometalinter $(file) || exit;)

fmtcheck:
	$(foreach file,$(SRCS),gofmt -s -d $(file);)

pretest: lint vet fmtcheck

test: 
	$(GO) test -cover -v ./... || exit;

unused:
	$(foreach pkg,$(PKGS),unused $(pkg);)

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
	-docker kill redis-old redis-new
	-docker rm redis-old redis-new

fetch-rdb:
	integration/goval-dict.old fetch debian --dbpath=$(PWD)/integration/oval.old.sqlite3 7 8 9 10
	integration/goval-dict.old fetch ubuntu --dbpath=$(PWD)/integration/oval.old.sqlite3 14 16 18 19 20
	integration/goval-dict.old fetch redhat --dbpath=$(PWD)/integration/oval.old.sqlite3 5 6 7 8
	integration/goval-dict.old fetch oracle --dbpath=$(PWD)/integration/oval.old.sqlite3
	integration/goval-dict.old fetch amazon --dbpath=$(PWD)/integration/oval.old.sqlite3
	integration/goval-dict.old fetch alpine --dbpath=$(PWD)/integration/oval.old.sqlite3 3.3 3.4 3.5 3.6

	integration/goval-dict.new fetch debian --dbpath=$(PWD)/integration/oval.new.sqlite3 7 8 9 10
	integration/goval-dict.new fetch ubuntu --dbpath=$(PWD)/integration/oval.new.sqlite3 14 16 18 19 20
	integration/goval-dict.new fetch redhat --dbpath=$(PWD)/integration/oval.new.sqlite3 5 6 7 8
	integration/goval-dict.new fetch oracle --dbpath=$(PWD)/integration/oval.new.sqlite3
	integration/goval-dict.new fetch amazon --dbpath=$(PWD)/integration/oval.new.sqlite3
	integration/goval-dict.new fetch alpine --dbpath=$(PWD)/integration/oval.new.sqlite3 3.3 3.4 3.5 3.6

fetch-redis:
	docker run --name redis-old -d -p 127.0.0.1:6379:6379 redis
	docker run --name redis-new -d -p 127.0.0.1:6380:6379 redis
	
	integration/goval-dict.old fetch debian --dbtype redis --dbpath "redis://127.0.0.1:6379/0" 7 8 9 10
	integration/goval-dict.old fetch ubuntu --dbtype redis --dbpath "redis://127.0.0.1:6379/0" 14 16 18 19 20
	integration/goval-dict.old fetch redhat --dbtype redis --dbpath "redis://127.0.0.1:6379/0" 5 6 7 8
	integration/goval-dict.old fetch oracle --dbtype redis --dbpath "redis://127.0.0.1:6379/0"
	integration/goval-dict.old fetch amazon --dbtype redis --dbpath "redis://127.0.0.1:6379/0"
	integration/goval-dict.old fetch alpine --dbtype redis --dbpath "redis://127.0.0.1:6379/0" 3.3 3.4 3.5 3.6

	integration/goval-dict.new fetch debian --dbtype redis --dbpath "redis://127.0.0.1:6380/0" 7 8 9 10
	integration/goval-dict.new fetch ubuntu --dbtype redis --dbpath "redis://127.0.0.1:6380/0" 14 16 18 19 20
	integration/goval-dict.new fetch redhat --dbtype redis --dbpath "redis://127.0.0.1:6380/0" 5 6 7 8
	integration/goval-dict.new fetch oracle --dbtype redis --dbpath "redis://127.0.0.1:6380/0"
	integration/goval-dict.new fetch amazon --dbtype redis --dbpath "redis://127.0.0.1:6380/0"
	integration/goval-dict.new fetch alpine --dbtype redis --dbpath "redis://127.0.0.1:6380/0" 3.3 3.4 3.5 3.6

diff-cveid:
	# @ python integration/diff_server_mode.py cveid debian 7 8 9 10
	# @ python integration/diff_server_mode.py cveid ubuntu 14 16 18 19 20
	# @ python integration/diff_server_mode.py cveid redhat 5 6 7 8
	# @ python integration/diff_server_mode.py cveid oracle 5 6 7 8
	# @ python integration/diff_server_mode.py cveid amazon 1 2
	# @ python integration/diff_server_mode.py cveid alpine 3.3 3.4 3.5 3.6


diff-package:
	# @ python integration/diff_server_mode.py package debian 7 8 9 10
	# @ python integration/diff_server_mode.py package ubuntu 14 16 18 19 20
	# @ python integration/diff_server_mode.py package redhat 5 6 7 8
	# @ python integration/diff_server_mode.py package oracle 5 6 7 8
	# @ python integration/diff_server_mode.py package amazon 1 2
	# @ python integration/diff_server_mode.py package alpine 3.3 3.4 3.5 3.6

diff-server-rdb:
	integration/goval-dict.old server --dbpath=$(PWD)/integration/oval.old.sqlite3 --port 1325 > /dev/null & 
	integration/goval-dict.new server --dbpath=$(PWD)/integration/oval.new.sqlite3 --port 1326 > /dev/null &
	make diff-cveid
	make diff-package
	pkill goval-dict.old
	pkill goval-dict.new

diff-server-redis:
	integration/goval-dict.old server --dbtype redis --dbpath "redis://127.0.0.1:6379/0" --port 1325 > /dev/null & 
	integration/goval-dict.new server --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --port 1326 > /dev/null &
	make diff-cveid
	make diff-package
	pkill goval-dict.old
	pkill goval-dict.new

diff-server-rdb-redis:
	integration/goval-dict.new server --dbpath=$(PWD)/integration/oval.new.sqlite3 --port 1325 > /dev/null &
	integration/goval-dict.new server --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --port 1326 > /dev/null &
	make diff-cveid
	make diff-package
	pkill goval-dict.new
