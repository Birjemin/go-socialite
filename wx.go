package socialite

import (
	"errors"
	"fmt"
	"socialite/utils"
)

const (
	wxAuthorizeURL = "https://open.weixin.qq.com/connect/qrconnect"
	wxResponseType = "code"
	wxScope        = "snsapi_login"

	wxTokenURL      = "https://api.weixin.qq.com/sns/oauth2/access_token"
	wxGrantTypeAuth = "authorization_code"

	wxRefreshTokenURL  = "https://api.weixin.qq.com/sns/oauth2/refresh_token"
	wxGrantTypeRefresh = "refresh_token"

	wxUserInfoURL = "https://api.weixin.qq.com/sns/userinfo"
)

// Wx
// @doc: https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
type Wx struct {
	AppID       string
	AppSecret   string
	RedirectURL string
	HTTPRequest *utils.HTTPClient
}

// wxRespErrorToken response of err
type wxRespErrorToken struct {
	ErrCode int    `json:"errcode"`
	ErrMsg  string `json:"errmsg"`
}

// WxRespToken response of me
type WxRespToken struct {
	wxRespErrorToken
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenID       string `json:"openid"`
	Scope        string `json:"scope"`
	UnionID      string `json:"unionid"`
}

// WxUserInfo user info
type WxUserInfo struct {
	wxRespErrorToken
	OpenID     string      `json:"openid"`
	Nickname   string      `json:"nickname"`
	Sex        int         `json:"sex"`
	Province   string      `json:"province"`
	City       string      `json:"city"`
	Country    string      `json:"country"`
	HeadImgURL string      `json:"headimgurl"`
	Privilege  interface{} `json:"privilege"`
	UnionID    string      `json:"unionid"`
}

// GetAuthorizeURL get authorize url
func (w *Wx) GetAuthorizeURL(args ...string) string {

	params := make(map[string]string, 5)
	params["appid"] = w.AppID
	params["response_type"] = wxResponseType
	params["redirect_uri"] = w.RedirectURL
	params["scope"] = wxScope

	length := len(args)

	if length > 0 {
		params["state"] = args[0]
	}

	return fmt.Sprintf("%s?%s", wxAuthorizeURL, utils.QuerySortByKeyStr2(params))
}

// Token get token
func (w *Wx) Token(code string) (interface{}, error) {

	return w.doToken(wxTokenURL, code)
}

// doToken handle
func (w *Wx) doToken(url, code string) (ret *WxRespToken, err error) {

	params := map[string]string{
		"grant_type": wxGrantTypeAuth,
		"appid":      w.AppID,
		"secret":     w.AppSecret,
		"code":       code,
	}

	if err := w.HTTPRequest.HTTPGet(url, params); err != nil {
		return nil, err
	}

	ret = new(WxRespToken)
	if w.HTTPRequest.GetResponseJSON(ret) != nil {
		return nil, err
	}
	return ret, nil
}

// RefreshToken refresh token
func (w *Wx) RefreshToken(refreshToken string) (interface{}, error) {

	return w.doRefreshToken(wxRefreshTokenURL, refreshToken)
}

// doRefreshToken handle
func (w *Wx) doRefreshToken(url, refreshToken string) (ret *WxRespToken, err error) {

	params := map[string]string{
		"grant_type":    wxGrantTypeRefresh,
		"appid":         w.AppID,
		"refresh_token": refreshToken,
	}

	if err := w.HTTPRequest.HTTPGet(url, params); err != nil {
		return nil, err
	}

	ret = new(WxRespToken)
	if w.HTTPRequest.GetResponseJSON(ret) != nil {
		return nil, err
	}
	return ret, nil
}

// GetMe get me
func (w *Wx) GetMe(accessToken string) (interface{}, error) {
	return nil, errors.New("can not support")
}

// GetUserInfo get user info
func (w *Wx) GetUserInfo(accessToken, openID string) (interface{}, error) {

	return w.doGetUserInfo(wxUserInfoURL, accessToken, openID)
}

// doGetUserInfo handle
func (w *Wx) doGetUserInfo(url, accessToken, openID string) (*WxUserInfo, error) {

	params := map[string]string{
		"access_token": accessToken,
		"openid":       openID,
	}

	if err := w.HTTPRequest.HTTPGet(url, params); err != nil {
		return nil, err
	}

	ret := new(WxUserInfo)
	if err := w.HTTPRequest.GetResponseJSON(ret); err != nil {
		return nil, err
	}
	return ret, nil
}
