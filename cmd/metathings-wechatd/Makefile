GO=$(shell which go)
SRC=$(shell ls *.go)
BIN=../../bin/metathings-wechatd

all: build

build:
	$(GO) build -o $(BIN) $(SRC)
