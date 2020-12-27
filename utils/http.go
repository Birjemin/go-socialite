package utils

import (
	"errors"
	jsoniter "github.com/json-iterator/go"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// HTTPClient http's client
type HTTPClient struct {
	Client   *http.Client
	Response *http.Response
}

// HTTPGet get method
func (c *HTTPClient) HTTPGet(url string, params map[string]string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errors.New("sending http get request error")
	}
	req.URL.RawQuery = HTTPQueryBuild(params)
	if c.Response, err = c.Client.Do(req); err != nil {
		return errors.New("http get response error")
	}
	return nil
}

// HTTPPost post string
func (c *HTTPClient) HTTPPost(url string, params map[string]string) error {
	var query = HTTPQueryBuild(params)

	return c.doPostRequest(url, query, "application/x-www-form-urlencoded;charset=UTF-8")
}

// HTTPPostJSON post json
func (c *HTTPClient) HTTPPostJSON(url, jsonStr string) error {
	return c.doPostRequest(url, jsonStr, "application/json;charset=UTF-8")
}

// doPostRequest
func (c *HTTPClient) doPostRequest(url, str, contentType string) (err error) {
	var req *http.Request
	if req, err = http.NewRequest("POST", url, strings.NewReader(str)); err != nil {
		return errors.New("sending http request error")
	}
	req.Header.Set("Content-Type", contentType)
	c.Response, err = c.Client.Do(req)
	return
}

// GetResponseJSON get response json
func (c *HTTPClient) GetResponseJSON(response interface{}) error {
	if c.Response.Body == nil {
		return errors.New("http request response body is empty")
	}

	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	defer c.Response.Body.Close()
	return json.NewDecoder(c.Response.Body).Decode(response)
}

// GetResponseByte get response byte
func (c *HTTPClient) GetResponseByte() (body []byte, err error) {
	if c.Response.Body == nil {
		return []byte{}, errors.New("http request response body is empty")
	}
	defer c.Response.Body.Close()
	return ioutil.ReadAll(c.Response.Body)
}

// HTTPQueryBuild http_query_build
func HTTPQueryBuild(params map[string]string) string {
	var query = make(url.Values)
	for k, v := range params {
		query.Add(k, v)
	}
	return query.Encode()
}
