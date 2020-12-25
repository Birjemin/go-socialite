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
	AppID       string
	AppSecret   string
	RedirectURL string
	HTTPRequest *utils.HTTPClient
}

// qqRespErrorToken response of err
type qqRespErrorToken struct {
	ErrCode int    `json:"error"`
	ErrMsg  string `json:"error_description"`
}

// QqRespToken struct
type QqRespToken struct {
	qqRespErrorToken
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// QqRespMe response of me
type QqRespMe struct {
	qqRespErrorToken
	ClientID string `json:"client_id"`
	OpenID   string `json:"openid"`
}

// QqRespUserInfo user info
type QqRespUserInfo struct {
	Ret              int    `json:"ret"`
	Msg              string `json:"msg"`
	IsLost           int    `json:"is_lost"`
	Nickname         string `json:"nickname"`
	Gender           string `json:"gender"`
	GenderType       int    `json:"gender_type"`
	Province         string `json:"province"`
	City             string `json:"city"`
	Year             string `json:"year"`
	Constellation    string `json:"constellation"`
	FigureURL        string `json:"figureurl"`
	FigureURL1       string `json:"figureurl_1"`
	FigureURL2       string `json:"figureurl_2"`
	FigureQqURL      string `json:"figureurl_qq"`
	FigureQqURL1     string `json:"figureurl_qq_1"`
	FigureQqURL2     string `json:"figureurl_qq_2"`
	FigureURLType    string `json:"figureurl_type"`
	IsYellowVIP      string `json:"is_yellow_vip"`
	VIP              string `json:"vip"`
	YellowVIPLevel   string `json:"yellow_vip_level"`
	Level            string `json:"level"`
	IsYellowVIPLevel string `json:"is_yellow_year_vip"`
}

// GetAuthorizeURL get authorize url
func (q *Qq) GetAuthorizeURL(args ...string) string {

	params := make(map[string]string, 6)
	params["response_type"] = authorizeResponseType
	params["client_id"] = q.AppID
	params["redirect_uri"] = q.RedirectURL

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
func (q *Qq) Token(code string) (interface{}, error) {

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
		"client_id":     q.AppID,
		"client_secret": q.AppSecret,
		"code":          code,
		"redirect_uri":  q.RedirectURL,
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

// RefreshToken refresh token
func (q *Qq) RefreshToken(refreshToken string) (interface{}, error) {

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
		"client_id":     q.AppID,
		"client_secret": q.AppSecret,
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

// getRespToken response
func (q *Qq) getRespToken(b []byte) (*QqRespToken, error) {

	match, _ := regexp.Match("error", b)

	ret := new(QqRespToken)

	// error
	if match {
		// regexp
		pattern, err := regexp.Compile(`{.*}`)
		if err != nil {
			return ret, err
		}

		if err := jsoniter.Unmarshal(pattern.Find(b), &ret); err != nil {
			return ret, err
		}

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

// GetMe get me
func (q *Qq) GetMe(accessToken string) (interface{}, error) {

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
		if err := jsoniter.Unmarshal(pattern.Find(b), &ret); err != nil {
			return ret, err
		}

		return ret, errors.New("get token error")
	} else {

		if err := jsoniter.Unmarshal(pattern.Find(b), &ret); err != nil {
			return ret, err
		}
		return ret, nil
	}
}

// GetUserInfo get user info
func (q *Qq) GetUserInfo(accessToken, openID string) (interface{}, error) {
	return q.doGetUserInfo(qqUserInfoURL, accessToken, openID)
}

// doGetUserInfo handle
func (q *Qq) doGetUserInfo(url, accessToken, openID string) (*QqRespUserInfo, error) {

	params := map[string]string{
		"access_token":       accessToken,
		"oauth_consumer_key": q.AppID,
		"openid":             openID,
	}

	if err := q.HTTPRequest.HTTPGet(url, params); err != nil {
		return nil, err
	}

	var ret = new(QqRespUserInfo)
	if err := q.HTTPRequest.GetResponseJSON(ret); err != nil {
		return nil, err
	}

	return ret, nil
}
