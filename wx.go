package socialite

import (
	"errors"
	"fmt"
	"socialite/utils"
)

const (
	wxAuthorizeURL = "https://open.weixin.qq.com/connect/qrconnect"
	wxResponseType = "code"

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

// wxRespToken response of me
type wxRespToken struct {
	wxRespErrorToken
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenID       string `json:"openid"`
	Scope        string `json:"scope"`
	UnionID      string `json:"unionid"`
}

// wxUserInfo user info
type wxUserInfo struct {
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

	length := len(args)

	if length < 1 {
		panic("args is invalid, please input state, scope, display")
	} else {
		params["scope"] = args[0]
		if length >= 2 {
			params["state"] = args[1]
		}
	}

	return fmt.Sprintf("%s?%s", wxAuthorizeURL, utils.QuerySortByKeyStr2(params))
}

// Token get token
func (w *Wx) Token(code string) (*RespToken, error) {

	b, err := w.doToken(wxTokenURL, code)
	if err != nil {
		return nil, err
	}
	return w.getRespToken(b)
}

// doToken handle
func (w *Wx) doToken(url, code string) (ret *wxRespToken, err error) {

	params := map[string]string{
		"grant_type": wxGrantTypeAuth,
		"appid":      w.AppID,
		"secret":     w.AppSecret,
		"code":       code,
	}

	if err := w.HTTPRequest.HTTPGet(url, params); err != nil {
		return nil, err
	}

	ret = new(wxRespToken)
	if w.HTTPRequest.GetResponseJSON(ret) != nil {
		return nil, err
	}
	return ret, nil
}

// getRespToken response
func (w *Wx) getRespToken(temp *wxRespToken) (*RespToken, error) {

	ret := new(RespToken)
	if temp.ErrCode != 0 {
		ret.Code = temp.ErrCode
		ret.Msg = temp.ErrMsg
		return ret, errors.New("get token error")
	}
	ret.AccessToken = temp.AccessToken
	ret.RefreshToken = temp.RefreshToken
	ret.ExpiresIn = temp.ExpiresIn
	ret.OpenID = temp.OpenID
	return ret, nil
}

// RefreshToken refresh token
func (w *Wx) RefreshToken(refreshToken string) (*RespToken, error) {

	b, err := w.doRefreshToken(wxRefreshTokenURL, refreshToken)
	if err != nil {
		return nil, err
	}
	return w.getRespToken(b)
}

// doRefreshToken handle
func (w *Wx) doRefreshToken(url, refreshToken string) (ret *wxRespToken, err error) {

	params := map[string]string{
		"grant_type":    wxGrantTypeRefresh,
		"appid":         w.AppID,
		"refresh_token": refreshToken,
	}

	if err := w.HTTPRequest.HTTPGet(url, params); err != nil {
		return nil, err
	}

	ret = new(wxRespToken)
	if w.HTTPRequest.GetResponseJSON(ret) != nil {
		return nil, err
	}
	return ret, nil
}

// GetUserInfo get user info
func (w *Wx) GetUserInfo(accessToken, openID string) (*RespUserInfo, error) {

	b, err := w.doGetUserInfo(wxUserInfoURL, accessToken, openID)
	if err != nil {
		return nil, err
	}
	return w.getRespUserInfo(b)
}

// doGetUserInfo handle
func (w *Wx) doGetUserInfo(url, accessToken, openID string) (ret *wxUserInfo, err error) {

	params := map[string]string{
		"access_token": accessToken,
	}

	if err := w.HTTPRequest.HTTPGet(url, params); err != nil {
		return nil, err
	}

	ret = new(wxUserInfo)
	if w.HTTPRequest.GetResponseJSON(ret) != nil {
		return nil, err
	}
	return ret, nil
}

// getRespUserInfo response
func (w *Wx) getRespUserInfo(temp *wxUserInfo) (*RespUserInfo, error) {

	ret := new(RespUserInfo)
	if temp.ErrCode != 0 {
		ret.Code = temp.ErrCode
		ret.Msg = temp.ErrMsg
		return ret, errors.New("get user info error")
	}
	ret.OpenID = temp.OpenID
	ret.Nickname = temp.Nickname
	ret.Gender = temp.Sex
	ret.Country = temp.Country
	ret.Province = temp.Province
	ret.City = temp.City
	ret.Avatar = temp.HeadImgURL
	return ret, nil
}
