## go-socialite

oauth2授权登录(QQ、Wchat、Weibo)

[![Build Status](https://travis-ci.com/Birjemin/go-socialite.svg?branch=master)](https://travis-ci.com/Birjemin/go-socialite) 
[![Go Report Card](https://goreportcard.com/badge/github.com/birjemin/go-socialite)](https://goreportcard.com/report/github.com/birjemin/go-socialite) 
[![codecov](https://codecov.io/gh/Birjemin/go-socialite/branch/master/graph/badge.svg)](https://codecov.io/gh/Birjemin/go-socialite)


### 引入方式
```
go get github.com/birjemin/go-socialite
```

### 使用方式

- 初始化

```golang
var (
	httpClient = &utils.HTTPClient{
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}

	defaultObj = &socialite.Default{}

	qqObj = &socialite.Qq{
		AppID:       "",
		AppSecret:   "",
		RedirectURL: "https://domain/qq/callback",
		HTTPRequest: httpClient,
	}

	wxObj = &socialite.Wechat{
		AppID:       "",
		AppSecret:   "",
		RedirectURL: "https://domain/qq/callback",
		HTTPRequest: httpClient,
	}

	wbObj = &socialite.Weibo{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "http://domain.com/wb/callback",
		HTTPRequest:  httpClient,
	}
)

func dispatch(platform string) socialite.ISocialite {
	var obj socialite.ISocialite

	switch platform {
	case "qq":
		obj = qqObj
	case "wx":
		obj = wxObj
	case "wb":
		obj = wbObj
	default:
		obj = defaultObj
	}

	return obj
}
obj := dispatch("wx")
// obj := dispatch("wb")
// obj := dispatch("qq")

```

- 获取授权地址（登录完成之后会带上`CODE`跳转到回调地址中）
```golang
log.Print("authorize_url: ", obj.GetAuthorizeURL())
```

- 获取授权AccessToken()
```golang
// 上一步得到的CODE
resp, err := obj.Token("CODE")
// 断言
ret, ok := resp.(*socialite.WxRespToken)
if ok {
    log.Printf("ret: %#v", ret)
}
```

- 获取用户的OPEN_ID(qq接口专有，wechat、weibo在上一步中已经返回用户标识)
```golang
resp, err := obj.GetMe("ACCESS_TOKEN")
// 断言
ret, ok := resp.(*socialite.QqRespMe)
if ok {
    log.Printf("ret: %#v", ret)
}
```

- 获取用户信息
```golang
resp, err := obj.GetUserInfo("ACCESS_TOKEN", "OPEN_ID")
// 断言
ret, ok := resp.(*socialite.WxUserInfo)
if ok {
    log.Printf("ret: %#v", ret)
}
```

### 测试
- 测试
    ```
    go test
    ```
- 格式化代码
    ```
    golint
    ```
- 覆盖率
    ```
    go test -cover
    go test -coverprofile=coverage.out 
    go tool cover -html=coverage.out
    ```

### 备注
无