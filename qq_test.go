package socialite

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"socialite/utils"
	"testing"
	"time"
)

var (
	httpClient = &utils.HTTPClient{
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}

	qqObj = &Qq{
		AppID:       "test_app_id",
		AppSecret:   "test_app_secret",
		RedirectURL: "http://localhost/redirect_uri",
		HTTPRequest: httpClient,
	}
)

// TestGetAuthorizeUrl test GetAuthorizeURL
func TestGetAuthorizeURL(t *testing.T) {

	url1 := "https://graph.qq.com/oauth2.0/authorize?client_id=test_app_id&redirect_uri=http%3A%2F%2Flocalhost%2Fredirect_uri&response_type=code&state=rand_str"
	url2 := "https://graph.qq.com/oauth2.0/authorize?client_id=test_app_id&redirect_uri=http%3A%2F%2Flocalhost%2Fredirect_uri&response_type=code&scope=get_user_info&state=rand_str"
	url3 := "https://graph.qq.com/oauth2.0/authorize?client_id=test_app_id&display=pc&redirect_uri=http%3A%2F%2Flocalhost%2Fredirect_uri&response_type=code&scope=get_user_info&state=rand_str"

	ast := assert.New(t)

	ast.Equal(url1, qqObj.GetAuthorizeURL("rand_str"))
	ast.Equal(url2, qqObj.GetAuthorizeURL("rand_str", "get_user_info"))
	ast.Equal(url3, qqObj.GetAuthorizeURL("rand_str", "get_user_info", "pc"))
	ast.Equal(url3, qqObj.GetAuthorizeURL("rand_str", "get_user_info", "pc", "extra"))
}

// TestGetErrRespToken
func TestGetErrRespToken(t *testing.T) {

	ast := assert.New(t)
	temp := []byte(`callback( {"error":100002,"error_description":"param client_secret is wrong or lost "} );`)

	ret, err := qqObj.getRespToken(temp)
	if err != nil {
		ast.Equal("get token error", err.Error())
	}
	if ret == nil {
		ast.Fail("err result")
		return
	}
	ast.Equal(100002, ret.Code)
}

// TestGetSuccessRespToken
func TestGetSuccessRespToken(t *testing.T) {

	ast := assert.New(t)
	temp := []byte(`access_token=FE04************************CCE2&expires_in=7776000&refresh_token=88E4************************BE14`)

	ret, err := qqObj.getRespToken(temp)
	if err != nil {
		ast.Fail(err.Error())
		return
	}

	ast.Equal(0, ret.Code)
	ast.Equal("FE04************************CCE2", ret.AccessToken)
	ast.Equal(7776000, ret.ExpiresIn)
	ast.Equal("88E4************************BE14", ret.RefreshToken)
}

// TestQqToken
func TestQqToken(t *testing.T) {

	ast := assert.New(t)

	var ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ret := `access_token=FE04************************CCE2&expires_in=7776000&refresh_token=88E4************************BE14`
		for _, v := range []string{"grant_type", "client_id", "client_secret", "code", "redirect_uri"} {
			val := r.FormValue(v)
			if val == "" {
				ret = `callback( {"error":100004,"error_description":"param grant_type is wrong or lost "} );`
				break
			}
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(ret)); err != nil {
			t.Fatal(err)
		}
	}))

	defer ts.Close()

	// success
	b, err := qqObj.doToken(ts.URL, "code")
	if err != nil {
		ast.Error(err)
	}

	ret, err := qqObj.getRespToken(b)
	if err != nil {
		ast.Error(err)
	}

	ast.Equal(0, ret.Code)
	ast.Equal("FE04************************CCE2", ret.AccessToken)
	ast.Equal(7776000, ret.ExpiresIn)
	ast.Equal("88E4************************BE14", ret.RefreshToken)

	// fail
	b, err = qqObj.doToken(ts.URL, "")
	if err != nil {
		ast.Fail(err.Error())
		return
	}

	ret, err = qqObj.getRespToken(b)
	if err != nil {
		ast.Equal("get token error", err.Error())
	}
	if ret == nil {
		ast.Fail("err result")
		return
	}
	ast.Equal(100004, ret.Code)
}

// TestQqRefreshToken
func TestQqRefreshToken(t *testing.T) {

	ast := assert.New(t)

	var ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ret := `access_token=FE04************************CCE2&expires_in=7776000&refresh_token=88E4************************BE14`
		for _, v := range []string{"grant_type", "client_id", "client_secret", "refresh_token"} {
			val := r.FormValue(v)
			if val == "" {
				ret = `callback( {"error":100004,"error_description":"param grant_type is wrong or lost "} );`
				break
			}
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(ret)); err != nil {
			t.Fatal(err)
		}
	}))

	defer ts.Close()

	// success
	b, err := qqObj.doRefreshToken(ts.URL, "refresh-token")
	if err != nil {
		ast.Error(err)
	}

	ret, err := qqObj.getRespToken(b)
	if err != nil {
		ast.Error(err)
	}

	ast.Equal(0, ret.Code)
	ast.Equal("FE04************************CCE2", ret.AccessToken)
	ast.Equal(7776000, ret.ExpiresIn)
	ast.Equal("88E4************************BE14", ret.RefreshToken)

	// fail
	b, err = qqObj.doRefreshToken(ts.URL, "")
	if err != nil {
		ast.Fail(err.Error())
		return
	}

	ret, err = qqObj.getRespToken(b)
	if err != nil {
		ast.Equal("get token error", err.Error())
	}
	if ret == nil {
		ast.Fail("err result")
		return
	}
	ast.Equal(100004, ret.Code)
}

// TestGetErrRespMe
func TestGetErrRespMe(t *testing.T) {

	ast := assert.New(t)
	temp := []byte(`callback( {"error":100016,"error_description":"access token check failed"} );`)

	ret, err := qqObj.getRespMe(temp)
	if err != nil {
		ast.Equal("get token error", err.Error())
	}
	if ret == nil {
		ast.Fail("err result")
		return
	}
	ast.Equal(100016, ret.Code)
}

// TestGetSuccessRespMe
func TestGetSuccessRespMe(t *testing.T) {

	ast := assert.New(t)
	temp := []byte(`callback( {"client_id":"YOUR_APPID","openid":"YOUR_OPENID"} ); `)

	ret, err := qqObj.getRespMe(temp)
	if err != nil {
		ast.Fail(err.Error())
		return
	}

	ast.Equal(0, ret.Code)
	ast.Equal("YOUR_APPID", ret.ClientID)
	ast.Equal("YOUR_OPENID", ret.OpenID)
}

// TestQqMe
func TestQqMe(t *testing.T) {

	ast := assert.New(t)

	var ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ret := `callback( {"client_id":"YOUR_APPID","openid":"YOUR_OPENID"} );`
		val := r.FormValue("access_token")
		if val == "" {
			ret = `callback( {"error":100016,"error_description":"access token check failed"} );`
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(ret)); err != nil {
			t.Fatal(err)
		}
	}))

	defer ts.Close()

	// success
	b, err := qqObj.doGetMe(ts.URL, "ACCESS_TOKEN")
	if err != nil {
		ast.Error(err)
	}

	ret, err := qqObj.getRespMe(b)
	if err != nil {
		ast.Error(err)
	}

	ast.Equal(0, ret.Code)
	ast.Equal("YOUR_OPENID", ret.OpenID)
	ast.Equal("YOUR_APPID", ret.ClientID)

	// fail
	b, err = qqObj.doGetMe(ts.URL, "")
	if err != nil {
		ast.Fail(err.Error())
		return
	}

	ret, err = qqObj.getRespMe(b)
	if err != nil {
		ast.Equal("get token error", err.Error())
	}
	if ret == nil {
		ast.Fail("err result")
		return
	}
	ast.Equal(100016, ret.Code)
}

// TestQqUserInfo
func TestQqUserInfo(t *testing.T) {

	ast := assert.New(t)

	var ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ret := `{"ret":0,"msg":"","nickname":"YOUR_NICK_NAME"}`
		val := r.FormValue("access_token")
		if val == "" {
			ret = `{"ret":1001,"msg":"invalid openid"}`
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(ret)); err != nil {
			t.Fatal(err)
		}
	}))

	defer ts.Close()

	// success
	ret, err := qqObj.doGetUserInfo(ts.URL, "YOUR_ACCESS_TOKEN", "YOUR_OPENID")
	if err != nil {
		ast.Error(err)
	}

	ast.Equal(0, ret.Ret)
	ast.Equal("YOUR_NICK_NAME", ret.Nickname)

	// fail
	ret, err = qqObj.doGetUserInfo(ts.URL, "", "")
	if err != nil {
		ast.Fail(err.Error())
		return
	}

	ast.Equal(1001, ret.Ret)
}
