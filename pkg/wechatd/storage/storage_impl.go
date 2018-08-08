package metathings_wechatd_storage

import (
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	log "github.com/sirupsen/logrus"
)

type storageImpl struct {
	db     *gorm.DB
	logger log.FieldLogger
}

func (self *storageImpl) GetApplicationCredential(openid string) (ApplicationCredential, error) {
	var app_cred ApplicationCredential
	err := self.db.First(&app_cred, "openid = ?", openid).Error
	if err != nil {
		return ApplicationCredential{}, err
	}
	self.logger.WithField("openid", openid).Debugf("get application credential by openid")
	return app_cred, nil
}

func (self *storageImpl) CreateApplicationCredential(app_cred ApplicationCredential) (ApplicationCredential, error) {
	err := self.db.Create(&app_cred).Error
	if err != nil {
		return ApplicationCredential{}, err
	}

	self.db.First(&app_cred, "openid = ?", *app_cred.Openid)
	self.logger.WithFields(log.Fields{"openid": *app_cred.Openid}).Debugf("create application credential")

	return app_cred, nil
}

func (self *storageImpl) GetTokensByOpenid(openid string) ([]Token, error) {
	var tokens []Token
	err := self.db.Find(&tokens, "openid = ?", openid).Error
	if err != nil {
		return tokens, err
	}

	self.logger.WithField("openid", openid).Debugf("get tokens by openid")

	return tokens, nil
}

func (self *storageImpl) CreateToken(tkn Token) (Token, error) {
	err := self.db.Create(&tkn).Error
	if err != nil {
		return tkn, err
	}

	self.db.First(&tkn, "id = ?", *tkn.Id)
	self.logger.WithField("openid", tkn.Openid).Debugf("create token")

	return tkn, nil
}

func (self *storageImpl) DeleteToken(tkn_id string) error {
	err := self.db.Delete("id = ?", tkn_id).Error
	if err != nil {
		return err
	}
	self.logger.WithField("tkn_id", tkn_id).Debugf("delete token")
	return nil
}

func (self *storageImpl) UpdateApplicationCredential(openid string, app_cred ApplicationCredential) (ApplicationCredential, error) {
	err := self.db.Model(ApplicationCredential{}).Where("openid = ?", openid).Updates(ApplicationCredential{
		ApplicationCredentialId:     app_cred.ApplicationCredentialId,
		ApplicationCredentialSecret: app_cred.ApplicationCredentialSecret,
	}).Error
	if err != nil {
		return ApplicationCredential{}, err
	}

	self.logger.WithField("openid", openid).Debugf("update application credential")
	return ApplicationCredential{
		Openid:                      &openid,
		ApplicationCredentialId:     app_cred.ApplicationCredentialId,
		ApplicationCredentialSecret: app_cred.ApplicationCredentialSecret,
	}, nil
}

func (self *storageImpl) DeleteApplicationCredential(openid string) error {
	err := self.db.Delete(ApplicationCredential{}, "openid = ?", openid).Error
	if err != nil {
		return err
	}

	self.logger.WithField("openid", openid).Debugf("delete application credential")
	return nil
}

func (self *storageImpl) ClearExpiredTokens(expired_at time.Time, openid ...string) error {
	var err error

	if len(openid) > 0 {
		oid := openid[0]
		err = self.db.Where("openid = ? and created_at < ?", oid, expired_at).Delete(Token{}).Error
	} else {
		err = self.db.Where("created_at < ?", expired_at).Delete(Token{}).Error
	}

	if err != nil {
		return err
	}

	return nil
}

func newStorageImpl(driver, uri string, logger log.FieldLogger) (Storage, error) {
	db, err := gorm.Open(driver, uri)
	if err != nil {
		return nil, err
	}

	db.AutoMigrate(&ApplicationCredential{})
	db.AutoMigrate(&Token{})

	return &storageImpl{
		logger: logger.WithField("#module", "storage"),
		db:     db,
	}, nil
}
