package socialite

type Default struct{}

// RespToken struct
type RespToken struct {
	Code         int    `json:"code"`
	Msg          string `json:"msg"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	OpenID       string `json:"openid"`
}

// RespUserInfo user info
type RespUserInfo struct {
	Code     int    `json:"code"`
	Msg      string `json:"msg"`
	OpenID   string `json:"open_id"`
	Nickname string `json:"nickname"`
	Gender   int    `json:"gender"`
	Country  string `json:"country"`
	Province string `json:"province"`
	City     string `json:"city"`
	Avatar   string `json:"avatar"`
}

// ISocialite interface
type ISocialite interface {
	// GetAuthorizeURL get authorize url
	GetAuthorizeURL(args string) string

	// Token get token
	Token(code string) (*RespToken, error)

	// RefreshToken refresh token
	RefreshToken(refreshToken string) (*RespToken, error)

	// GetUserInfo get user info
	GetUserInfo(accessToken, openID string) (*RespUserInfo, error)
}
