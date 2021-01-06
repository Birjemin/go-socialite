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
	wbHTTPClient = &utils.HTTPClient{
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}

	wbObj = &Weibo{
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  "REDIRECT_URI",
		HTTPRequest:  wbHTTPClient,
	}
)

// TestGetAuthorizeUrl test GetAuthorizeURL
func TestWbGetAuthorizeURL(t *testing.T) {

	url1 := "https://api.weibo.com/oauth2/authorize?client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&state=STATE"
	url2 := "https://api.weibo.com/oauth2/authorize?client_id=CLIENT_ID&display=mobile&redirect_uri=REDIRECT_URI&state=STATE"

	ast := assert.New(t)

	ast.Equal(url1, wbObj.GetAuthorizeURL("STATE"))
	ast.Equal(url2, wbObj.GetAuthorizeURL("STATE", "mobile"))
}

// TestWbToken
func TestWbToken(t *testing.T) {

	ast := assert.New(t)

	var ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ret := `{"access_token":"YOUR_ACCESS_TOKEN","remind_in":"157679999","expires_in":7200,"uid":"UID","isRealName":"true"}`
		for _, v := range []string{"client_id", "grant_type", "code", "client_secret", "redirect_uri"} {
			val := r.FormValue(v)
			if val == "" {
				ret = `{"error":"HTTP METHOD is not suported for this request!","error_code":10021,"request":"/oauth2/access_token","error_uri":"/oauth2/access_token"}`
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
	ret, err := wbObj.doToken(ts.URL, "code")
	if err != nil {
		ast.Error(err)
	}

	ast.Equal(0, ret.ErrorCode)
	ast.Equal("YOUR_ACCESS_TOKEN", ret.AccessToken)
	ast.Equal(7200, ret.ExpiresIn)

	// fail
	ret, err = wbObj.doToken(ts.URL, "")
	if err != nil {
		ast.Fail(err.Error())
		return
	}
	ast.Equal(10021, ret.ErrorCode)
}

// TestWbUserInfo
func TestWbUserInfo(t *testing.T) {

	ast := assert.New(t)

	var ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ret := `{"id":101,"idstr":"xxx","class":1,"screen_name":"xx","name":"xxx","province":"33","city":"1","location":"浙江","description":"","story_read_state":-1,"vclub_member":0,"is_teenager":0,"is_guardian":0,"is_teenager_list":0,"pc_new":0,"special_follow":false,"planet_video":0,"video_mark":0,"live_status":0}
`
		val := r.FormValue("access_token")
		if val == "" {
			ret = `{"error":"source parameter(appkey) is missing","error_code":10006,"request":"/2/users/show.json"}`
		}

		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(ret)); err != nil {
			t.Fatal(err)
		}
	}))

	defer ts.Close()

	// success
	ret, err := wbObj.doGetUserInfo(ts.URL, "YOUR_ACCESS_TOKEN", "YOUR_OPENID")
	if err != nil {
		ast.Error(err)
	}

	ast.Equal(101, ret.ID)

	// fail
	ret, err = wbObj.doGetUserInfo(ts.URL, "", "")
	if err != nil {
		ast.Fail(err.Error())
		return
	}

	ast.Equal(10006, ret.ErrorCode)
}
