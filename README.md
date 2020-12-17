## wxgameod-微信小游戏开放数据后台接口

[![Build Status](https://travis-ci.com/Birjemin/wxgameod.svg?branch=master)](https://travis-ci.com/Birjemin/wxgameod) 
[![Go Report Card](https://goreportcard.com/badge/github.com/birjemin/wxgameod)](https://goreportcard.com/report/github.com/birjemin/wxgameod) 
[![codecov](https://codecov.io/gh/Birjemin/wxgameod/branch/master/graph/badge.svg)](https://codecov.io/gh/Birjemin/wxgameod)


[开发者中心](https://developers.weixin.qq.com/minigame/dev/api-backend/open-api/data/storage.removeUserStorage.html)

### 引入方式
```
go get github.com/birjemin/wxgameod
```

### 接口列表

- [removeUserStorage](https://developers.weixin.qq.com/minigame/dev/api-backend/open-api/data/storage.removeUserStorage.html) ✅
- [setUserInteractiveData](https://developers.weixin.qq.com/minigame/dev/api-backend/open-api/data/storage.setUserInteractiveData.html) ✅
- [setUserStorage](https://developers.weixin.qq.com/minigame/dev/api-backend/open-api/data/storage.setUserStorage.html) ✅

### 使用方式

- 示例

```golang
httpClient := &utils.HTTPClient{
    Client: &http.Client{
        Timeout: 5 * time.Second,
    },
}
var m = SetUserStorage{
    AccessToken: "ACCESS_TOKEN",
    SessionKey:  "SESSION_KEY",
    OpenID:      "OPEN_ID",
    KvList:      "{\"kv_list\":[{\"key\":\"1\",\"value\":\"0\"}]}",
    HTTPRequest: httpClient,
}

if ret, err := m.doSetUserStorage(ts.URL); err != nil {
    t.Error(err)
} else {
    if ret.ErrCode != 0 {
        t.Error(errors.New("msg: " + ret.ErrMsg))
    }
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