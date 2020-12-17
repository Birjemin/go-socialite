package socialite

import (
	"errors"
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"regexp"
	"socialite/utils"
	"strconv"
)

const (
	// authorize url
	qqAuthorizeURL        = "https://graph.qq.com/oauth2.0/authorize"
	authorizeResponseType = "code"

	// token url
	qqTokenURL         = "https://graph.qq.com/oauth2.0/token"
	qqGrantTypeAuth    = "authorization_code"
	qqGrantTypeRefresh = "refresh_token"

	qqMeURL = "https://graph.qq.com/oauth2.0/me"

	qqUserInfoURL = "https://graph.qq.com/user/get_user_info"
)

// Qq
// @doc: https://wiki.open.qq.com/wiki/website/%E4%BD%BF%E7%94%A8Authorization_Code%E8%8E%B7%E5%8F%96Access_Token
type Qq struct {
	appID       string
	appSecret   string
	redirectUri string
	HTTPRequest *utils.HTTPClient
}

// qqRespErrorToken response of err
type qqRespErrorToken struct {
	Error          int    `json:"error"`
	ErrDescription string `json:"error_description"`
}

// QqRespMe response of me
type QqRespMe struct {
	Code     int    `json:"code"`
	Msg      string `json:"msg"`
	ClientID string `json:"client_id"`
	OpenID   string `json:"openid"`
}

// qqUserInfo user info
type qqUserInfo struct {
	Ret      int    `json:"ret"`
	Msg      string `json:"msg"`
	Nickname string `json:"nickname"`
}

// GetAuthorizeURL get authorize url
func (q *Qq) GetAuthorizeURL(args ...string) string {

	params := make(map[string]string, 6)
	params["response_type"] = authorizeResponseType
	params["client_id"] = q.appID
	params["redirect_uri"] = q.redirectUri

	length := len(args)

	if length < 1 {
		panic("args is invalid, please input state, scope, display")
	} else {
		params["state"] = args[0]
		if length >= 2 {
			params["scope"] = args[1]
			if length >= 3 {
				params["display"] = args[2]
			}
		}
	}

	return fmt.Sprintf("%s?%s", qqAuthorizeURL, utils.QuerySortByKeyStr2(params))
}

// Token get token
func (q *Qq) Token(code string) (*RespToken, error) {

	b, err := q.doToken(qqTokenURL, code)
	if err != nil {
		return nil, err
	}
	return q.getRespToken(b)
}

// doToken handle
func (q *Qq) doToken(url, code string) (ret []byte, err error) {

	params := map[string]string{
		"grant_type":    qqGrantTypeAuth,
		"client_id":     q.appID,
		"client_secret": q.appSecret,
		"code":          code,
		"redirect_uri":  q.redirectUri,
	}

	if err := q.HTTPRequest.HTTPGet(url, params); err != nil {
		return nil, err
	}

	ret, err = q.HTTPRequest.GetResponseByte()
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// getRespToken response
func (q *Qq) getRespToken(b []byte) (*RespToken, error) {

	match, _ := regexp.Match("error", b)

	ret := new(RespToken)

	// error
	if match {
		// regexp
		pattern, err := regexp.Compile(`{.*}`)
		if err != nil {
			return ret, err
		}

		respErr := new(qqRespErrorToken)
		if err := jsoniter.Unmarshal(pattern.Find(b), &respErr); err != nil {
			return ret, err
		}
		ret.Code = respErr.Error
		ret.Msg = respErr.ErrDescription

		return ret, errors.New("get token error")
	} else {

		pattern, err := regexp.Compile(`access_token=(\S*)&expires_in=(\S*)&refresh_token=(\S*)`)
		if err != nil {
			return ret, err
		}
		temp := pattern.FindSubmatch(b)

		if len(temp) != 4 {
			return ret, errors.New("length of result is invalid")
		}
		ret.AccessToken = string(temp[1])
		expired, _ := strconv.ParseInt(string(temp[2]), 10, 64)
		ret.ExpiresIn = int(expired)
		ret.RefreshToken = string(temp[3])
		return ret, nil
	}
}

// RefreshToken refresh token
func (q *Qq) RefreshToken(refreshToken string) (*RespToken, error) {

	b, err := q.doRefreshToken(qqTokenURL, refreshToken)
	if err != nil {
		return nil, err
	}
	return q.getRespToken(b)
}

// doRefreshToken handle
func (q *Qq) doRefreshToken(url, refreshToken string) (ret []byte, err error) {

	params := map[string]string{
		"grant_type":    qqGrantTypeRefresh,
		"client_id":     q.appID,
		"client_secret": q.appSecret,
		"refresh_token": refreshToken,
	}

	if err := q.HTTPRequest.HTTPGet(url, params); err != nil {
		return nil, err
	}

	ret, err = q.HTTPRequest.GetResponseByte()
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// GetMe get me
func (q *Qq) GetMe(accessToken string) (*QqRespMe, error) {

	b, err := q.doGetMe(qqMeURL, accessToken)
	if err != nil {
		return nil, err
	}
	return q.getRespMe(b)
}

// doGetMe handle
func (q *Qq) doGetMe(url, accessToken string) (ret []byte, err error) {

	params := map[string]string{
		"access_token": accessToken,
	}

	if err := q.HTTPRequest.HTTPGet(url, params); err != nil {
		return nil, err
	}

	ret, err = q.HTTPRequest.GetResponseByte()
	if err != nil {
		return nil, err
	}
	return ret, nil
}

// getRespMe response
func (q *Qq) getRespMe(b []byte) (*QqRespMe, error) {

	match, _ := regexp.Match("error", b)
	ret := new(QqRespMe)

	// regexp
	pattern, err := regexp.Compile(`{.*}`)
	if err != nil {
		return ret, err
	}

	// error
	if match {
		respErr := new(qqRespErrorToken)
		if err := jsoniter.Unmarshal(pattern.Find(b), &respErr); err != nil {
			return ret, err
		}
		ret.Code = respErr.Error
		ret.Msg = respErr.ErrDescription

		return ret, errors.New("get token error")
	} else {

		if err := jsoniter.Unmarshal(pattern.Find(b), &ret); err != nil {
			return ret, err
		}
		return ret, nil
	}
}

// GetUserInfo get user info
func (q *Qq) GetUserInfo(accessToken, openID string) (*RespUserInfo, error) {

	b, err := q.doGetUserInfo(qqUserInfoURL, accessToken, openID)
	if err != nil {
		return nil, err
	}
	return q.getRespUserInfo(b)
}

// doGetUserInfo handle
func (q *Qq) doGetUserInfo(url, accessToken, openID string) (ret *qqUserInfo, err error) {

	params := map[string]string{
		"access_token":       accessToken,
		"oauth_consumer_key": q.appID,
		"openid":             openID,
	}

	if err := q.HTTPRequest.HTTPGet(url, params); err != nil {
		return nil, err
	}

	ret = new(qqUserInfo)
	if q.HTTPRequest.GetResponseJSON(ret) != nil {
		return nil, err
	}
	return ret, nil
}

// getRespUserInfo response
func (q *Qq) getRespUserInfo(temp *qqUserInfo) (*RespUserInfo, error) {

	ret := new(RespUserInfo)
	if temp.Ret != 0 {
		ret.Code = temp.Ret
		ret.Msg = temp.Msg
		return ret, errors.New("get user info error")
	}
	ret.Nickname = temp.Nickname
	return ret, nil
}
