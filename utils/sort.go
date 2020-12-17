package utils

import (
	"bytes"
	"net/url"
	"sort"
)

// SortByKey sort by key
func SortByKey(m map[string]string) (str []string) {
	for k := range m {
		str = append(str, k)
	}
	sort.Strings(str)
	return
}

// QuerySortByKeyStr sign (using buffer could be better than string)
func QuerySortByKeyStr(m map[string]string) (str string) {
	keys := SortByKey(m)
	var ret bytes.Buffer
	ret.WriteString(str)

	for _, gk := range keys {
		if gk != "sign" {
			// str += gk + m[gk]
			ret.WriteString(gk)
			ret.WriteString(m[gk])
		}
	}
	return ret.String()
}

// QuerySortByKeyStr2 query sort by key str2
func QuerySortByKeyStr2(params map[string]string) (str string) {
	// or you can create new url.Values struct and encode that like so
	q := url.Values{}
	for key, val := range params {
		q.Add(key, val)
	}
	return q.Encode()
}
