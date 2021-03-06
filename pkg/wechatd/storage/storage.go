package metathings_wechatd_storage

import (
	"time"

	log "github.com/sirupsen/logrus"
)

type ApplicationCredential struct {
	CreatedAt time.Time
	UpdatedAt time.Time

	ApplicationCredentialId     *string `gorm:"column:application_credential_id"`
	ApplicationCredentialSecret *string `gorm:"column:application_credential_secret"`
	Openid                      *string `gorm:"column:openid"`
}

type Token struct {
	Id        *string
	CreatedAt time.Time
	UpdatedAt time.Time

	Openid *string
	Text   *string
}

type Storage interface {
	GetApplicationCredential(openid string) (ApplicationCredential, error)
	CreateApplicationCredential(app_cred ApplicationCredential) (ApplicationCredential, error)
	UpdateApplicationCredential(openid string, app_cred ApplicationCredential) (ApplicationCredential, error)
	DeleteApplicationCredential(openid string) error
	GetTokensByOpenid(openid string) ([]Token, error)
	CreateToken(tkn Token) (Token, error)
	DeleteToken(tkn_id string) error
	ClearExpiredTokens(expired_at time.Time, openid ...string) error
}

func NewStorage(driver, uri string, logger log.FieldLogger) (Storage, error) {
	return newStorageImpl(driver, uri, logger)
}
