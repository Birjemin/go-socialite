package socialite

import (
	"errors"
)

// ISocialite interface
type ISocialite interface {
	// GetAuthorizeURL get authorize url
	GetAuthorizeURL(args ...string) string

	// Token get token
	Token(code string) (interface{}, error)

	// RefreshToken refresh token
	RefreshToken(refreshToken string) (interface{}, error)

	// GetMe get open_id if it needs necessarily
	GetMe(accessToken string) (interface{}, error)

	// GetUserInfo get user info
	GetUserInfo(accessToken, openID string) (interface{}, error)
}

// RespToken struct
type RespToken struct {
	Code         int    `json:"code"`
	Msg          string `json:"msg"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenID       string `json:"openid"`
}

// Default struct
type Default struct{

}

// GetAuthorizeURL get authorize url
func (d *Default) GetAuthorizeURL(args ...string) string {
	return "invalid"
}

// Token token
func (d *Default) Token(code string) (interface{}, error) {
	return nil, errors.New("invalid")
}

// RefreshToken refresh token
func (d *Default) RefreshToken(refreshToken string) (interface{}, error) {
	return nil, errors.New("invalid")
}

// GetMe get me
func (d *Default) GetMe(accessToken string) (interface{}, error) {
	return nil, errors.New("can not support")
}

// GetUserInfo get user info
func (d *Default) GetUserInfo(accessToken, openID string) (interface{}, error) {
	return nil, errors.New("invalid")
}

