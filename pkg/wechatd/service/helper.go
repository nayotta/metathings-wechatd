package metathings_wechatd_service

import "math/rand"

var (
	ASCII_LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	DIGITS        = "0123456789"
	SYMBOLS       = "!@#$%^&*()_+-=[]{};':,.<>/?|"
)

var (
	USERNAME_SIZE        = 16
	FIRST_USERNAME_CHARS = ASCII_LETTERS
	REST_USERNAME_CHARS  = ASCII_LETTERS + DIGITS
)

func random_username() string {
	buf := make([]byte, USERNAME_SIZE)
	buf[0] = FIRST_USERNAME_CHARS[rand.Intn(len(FIRST_USERNAME_CHARS))]
	for i := 1; i < USERNAME_SIZE; i++ {
		buf[i] = REST_USERNAME_CHARS[rand.Intn(len(REST_USERNAME_CHARS))]
	}
	return string(buf)
}

var (
	PASSWORD_MIN_SIZE = 24
	PASSWORD_MAX_SIZE = 36
	PASSWORD_CHARS    = ASCII_LETTERS + DIGITS + SYMBOLS
)

func random_password() string {
	pwd_sz := int(float32(PASSWORD_MAX_SIZE-PASSWORD_MIN_SIZE)*rand.Float32()) + PASSWORD_MIN_SIZE
	buf := make([]byte, pwd_sz)
	for i := 0; i < pwd_sz; i++ {
		buf[i] = PASSWORD_CHARS[rand.Intn(len(PASSWORD_CHARS))]
	}
	return string(buf)
}
