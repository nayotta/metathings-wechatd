#! /usr/bin/env sh

set -e

go run $GOPATH/src/github.com/nayotta/metathings-wechatd/cmd/metathings-wechatd/main.go -c /etc/metathings-wechatd/wechatd.yaml serve
