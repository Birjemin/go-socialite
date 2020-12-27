package socialite

import (
	"errors"
	"fmt"
	"socialite/utils"
)

const (
	wbAuthorizeURL = "https://api.weibo.com/oauth2/authorize"
	wbResponseType = "code"
	wbScope        = "snsapi_login"

	wbTokenURL      = "https://api.weibo.com/oauth2/access_token"
	wbGrantTypeAuth = "authorization_code"

	wbUserInfoURL = "https://api.weibo.com/2/users/show.json"
)

// Weibo struct
type Weibo struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	HTTPRequest  *utils.HTTPClient
}

// wbRespErrorToken response of err
type wbRespErrorToken struct {
	ErrorCode int    `json:"error_code"`
	Error     string `json:"error"`
	Request   string `json:"request"`
	ErrorURI  string `json:"error_uri"`
}

// WbRespToken response of me
type WbRespToken struct {
	wbRespErrorToken
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	RemindIn    string `json:"remind_in"`
	UID         string `json:"uid"`
	IsRealName  string `json:"isRealName"`
}

// WbUserInfo user info
type WbUserInfo struct {
	wbRespErrorToken
	ID              int    `json:"id"`
	ScreenName      string `json:"screen_name"`
	Name            string `json:"name"`
	Province        string `json:"province"`
	City            string `json:"city"`
	Location        string `json:"location"`
	Description     string `json:"description"`
	URL             string `json:"url"`
	ProfileImageURL string `json:"profile_image_url"`
	Domain          string `json:"domain"`
	Gender          string `json:"gender"`
	FriendsCount    int    `json:"friends_count"`
	FollowersCount  int    `json:"followers_count"`
	StatusesCount   int    `json:"statuses_count"`
	FavouritesCount int    `json:"favourites_count"`
	CreatedAt       string `json:"created_at"`
	Following       bool   `json:"following"`
	AllowAllActMsg  bool   `json:"allow_all_act_msg"`
	GeoEnabled      bool   `json:"geo_enabled"`
	Verified        bool   `json:"verified"`
	Status          struct {
		Annotations         []interface{} `json:"annotations"`
		CommentsCount       int           `json:"comments_count"`
		CreatedAt           string        `json:"created_at"`
		Favorited           bool          `json:"favorited"`
		Geo                 string        `json:"geo"`
		ID                  int           `json:"id"`
		InReplyToScreenName string        `json:"in_reply_to_screen_name"`
		InReplyToStatusID   string        `json:"in_reply_to_status_id"`
		InReplyToUserID     string        `json:"in_reply_to_user_id"`
		Mid                 string        `json:"mid"`
		RepostsCount        int           `json:"reposts_count"`
		Source              string        `json:"source"`
		Text                string        `json:"text"`
		Truncated           bool          `json:"truncated"`
	} `json:"status"`
	AllowAllComment  bool   `json:"allow_all_comment"`
	AvatarLarge      string `json:"avatar_large"`
	VerifiedReason   string `json:"verified_reason"`
	FollowMe         bool   `json:"follow_me"`
	OnlineStatus     int    `json:"online_status"`
	BiFollowersCount int    `json:"bi_followers_count"`
}

// GetAuthorizeURL get authorize url
// @doc: https://open.weibo.com/wiki/%E6%8E%88%E6%9D%83%E6%9C%BA%E5%88%B6%E8%AF%B4%E6%98%8E
// @doc: https://open.weibo.com/wiki/Oauth2/authorize
// @explain: two document, ridiculous~
func (w *Weibo) GetAuthorizeURL(args ...string) string {

	params := map[string]string{
		"client_id":    w.ClientID,
		"redirect_uri": w.RedirectURL,
	}

	length := len(args)
	if length >= 1 {
		params["state"] = args[0]
		if length >= 2 {
			params["display"] = args[1]
			if length >= 3 {
				params["forcelogin"] = args[2]
				if length >= 4 {
					params["scope"] = args[3]
					if length >= 5 {
						params["language"] = args[4]
					}
				}
			}
		}
	}

	return fmt.Sprintf("%s?%s", wbAuthorizeURL, utils.QuerySortByKeyStr2(params))
}

// Token token
func (w *Weibo) Token(code string) (interface{}, error) {
	return w.doToken(wbTokenURL, code)
}

// doToken handle
func (w *Weibo) doToken(url, code string) (ret *WbRespToken, err error) {
	params := map[string]string{
		"grant_type":    wbGrantTypeAuth,
		"client_id":     w.ClientID,
		"client_secret": w.ClientSecret,
		"redirect_uri":  w.RedirectURL,
		"code":          code,
	}

	if err := w.HTTPRequest.HTTPPost(url, params); err != nil {
		return nil, err
	}

	ret = new(WbRespToken)
	if w.HTTPRequest.GetResponseJSON(ret) != nil {
		return nil, err
	}
	return ret, nil
}

// RefreshToken refresh token
func (w *Weibo) RefreshToken(refreshToken string) (interface{}, error) {
	return nil, errors.New("invalid")
}

// GetMe get me
func (w *Weibo) GetMe(accessToken string) (interface{}, error) {
	return nil, errors.New("can not support")
}

// GetUserInfo get user info
func (w *Weibo) GetUserInfo(accessToken, openID string) (interface{}, error) {
	return w.doGetUserInfo(wbUserInfoURL, accessToken, openID)
}

// doGetUserInfo handle
func (w *Weibo) doGetUserInfo(url, accessToken, UID string) (*WbUserInfo, error) {

	params := map[string]string{
		"access_token": accessToken,
		"uid":          UID,
	}

	if err := w.HTTPRequest.HTTPGet(url, params); err != nil {
		return nil, err
	}

	ret := new(WbUserInfo)
	if err := w.HTTPRequest.GetResponseJSON(ret); err != nil {
		return nil, err
	}
	return ret, nil
}
