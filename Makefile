RM=$(shell which rm)
CLEAN_PATHS=./bin ./lib

all: \
	protos \
	wechatd_bin

clean:
	$(RM) -rf $(CLEAN_PATHS)

protos:
	$(MAKE) -C pkg/proto all

wechatd_bin:
	$(MAKE) -C cmd/metathings-wechatd all
