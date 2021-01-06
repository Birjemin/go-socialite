package socialite

import (
	"github.com/birjemin/socialite/utils"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var (
	wxHTTPClient = &utils.HTTPClient{
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}

	wxObj = &Wechat{
		AppID:       "APPID",
		AppSecret:   "SECRET",
		RedirectURL: "REDIRECT_URI",
		HTTPRequest: wxHTTPClient,
	}
)

// TestWxGetAuthorizeURL test GetAuthorizeURL
func TestWxGetAuthorizeURL(t *testing.T) {

	url1 := "https://open.weixin.qq.com/connect/qrconnect?appid=APPID&redirect_uri=REDIRECT_URI&response_type=code&scope=snsapi_login&state=SCOPE"
	url2 := "https://open.weixin.qq.com/connect/qrconnect?appid=APPID&redirect_uri=REDIRECT_URI&response_type=code&scope=snsapi_login&state=SCOPE"

	ast := assert.New(t)

	ast.Equal(url1, wxObj.GetAuthorizeURL("SCOPE"))
	ast.Equal(url2, wxObj.GetAuthorizeURL("SCOPE", "STATE"))
}

// TestWxToken
func TestWxToken(t *testing.T) {

	ast := assert.New(t)

	var ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ret := `{"access_token":"YOUR_ACCESS_TOKEN","expires_in":7200,"refresh_token":"YOUR_REFRESH_TOKEN","openid":"OPENID","scope":"SCOPE","unionid":"o6_bmasdasdsad6_2sgVt7hMZOPfL"}`
		for _, v := range []string{"appid", "secret", "code", "grant_type"} {
			val := r.FormValue(v)
			if val == "" {
				ret = `{"errcode":40029,"errmsg":"invalid code"}`
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
	ret, err := wxObj.doToken(ts.URL, "code")
	if err != nil {
		ast.Error(err)
	}

	ast.Equal(0, ret.ErrCode)
	ast.Equal("YOUR_ACCESS_TOKEN", ret.AccessToken)
	ast.Equal(7200, ret.ExpiresIn)
	ast.Equal("YOUR_REFRESH_TOKEN", ret.RefreshToken)

	// fail
	ret, err = wxObj.doToken(ts.URL, "")
	if err != nil {
		ast.Fail(err.Error())
		return
	}
	ast.Equal(40029, ret.ErrCode)
}

// TestWxRefreshToken
func TestWxRefreshToken(t *testing.T) {

	ast := assert.New(t)

	var ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ret := `{"access_token":"YOUR_ACCESS_TOKEN","expires_in":7200,"refresh_token":"YOUR_REFRESH_TOKEN","openid":"OPENID","scope":"SCOPE"}`
		for _, v := range []string{"appid", "grant_type", "refresh_token"} {
			val := r.FormValue(v)
			if val == "" {
				ret = `{"errcode":40030,"errmsg":"invalid refresh_token"}`
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
	ret, err := wxObj.doRefreshToken(ts.URL, "YOUR_REFRESH_TOKEN")
	if err != nil {
		ast.Error(err)
	}

	ast.Equal(0, ret.ErrCode)
	ast.Equal("YOUR_ACCESS_TOKEN", ret.AccessToken)
	ast.Equal(7200, ret.ExpiresIn)
	ast.Equal("YOUR_REFRESH_TOKEN", ret.RefreshToken)

	// fail
	ret, err = wxObj.doRefreshToken(ts.URL, "")
	if err != nil {
		ast.Fail(err.Error())
		return
	}

	ast.Equal(40030, ret.ErrCode)
}

// TestWxUserInfo
func TestWxUserInfo(t *testing.T) {

	ast := assert.New(t)

	var ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ret := `{"openid":"YOUR_OPENID","nickname":"NICKNAME","sex":1,"province":"PROVINCE","city":"CITY","country":"COUNTRY","headimgurl":"https://thirdwx.qlogo.cn/mmopen/g3MonUZtNHkdmzicIlibx6iaFqAc56vxLSUfpb6n5WKSYVY0ChQKkiaJSgQ1dZuTOgvLLrhJbERQQ4eMsv84eavHiaiceqxibJxCfHe/0","privilege":["PRIVILEGE1","PRIVILEGE2"],"unionid":" o6_bmasdasdsad6_2sgVt7hMZOPfL"}`
		val := r.FormValue("access_token")
		if val == "" {
			ret = `{"errcode":40003,"errmsg":"invalid openid"}`
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(ret)); err != nil {
			t.Fatal(err)
		}
	}))

	defer ts.Close()

	// success
	ret, err := wxObj.doGetUserInfo(ts.URL, "YOUR_ACCESS_TOKEN", "YOUR_OPENID")
	if err != nil {
		ast.Error(err)
	}

	ast.Equal(0, ret.ErrCode)
	ast.Equal("YOUR_OPENID", ret.OpenID)

	// fail
	ret, err = wxObj.doGetUserInfo(ts.URL, "", "")
	if err != nil {
		ast.Fail(err.Error())
		return
	}

	ast.Equal(40003, ret.ErrCode)
}
