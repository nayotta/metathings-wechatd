package metathings_wechatd_storage

import (
	log "github.com/sirupsen/logrus"
)

type Storage interface{}

func NewStorage(driver, uri string, logger log.FieldLogger) (Storage, error) {
	panic("unimplemented")
}
