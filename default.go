package socialite

import (
	"errors"
)

// RespToken struct
type RespToken struct {
	Code         int    `json:"code"`
	Msg          string `json:"msg"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenID       string `json:"openid"`
}

// RespUserInfo user info
type RespUserInfo struct {
	Code     int    `json:"code"`
	Msg      string `json:"msg"`
	OpenID   string `json:"open_id"`
	Nickname string `json:"nickname"`
	Gender   int    `json:"gender"`
	Country  string `json:"country"`
	Province string `json:"province"`
	City     string `json:"city"`
	Avatar   string `json:"avatar"`
}

// RespMe response of me
type RespMe struct {
	Code     int    `json:"code"`
	Msg      string `json:"msg"`
	ClientID string `json:"client_id"`
	OpenID   string `json:"openid"`
}

type Default struct{}

// GetAuthorizeURL get authorize url
func (d *Default) GetAuthorizeURL(args ...string) string {
	return "invalid"
}

// Token token
func (d *Default) Token(code string) (*RespToken, error) {
	return nil, errors.New("invalid")
}

// RefreshToken refresh token
func (d *Default) RefreshToken(refreshToken string) (*RespToken, error) {
	return nil, errors.New("invalid")
}

// GetMe get me
func (d *Default) GetMe(accessToken string) (*RespMe, error) {
	return nil, errors.New("can not support")
}

// GetUserInfo get user info
func (d *Default) GetUserInfo(accessToken, openID string) (*RespUserInfo, error) {
	return nil, errors.New("invalid")
}

