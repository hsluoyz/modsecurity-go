package variables

import (
	"fmt"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

const (
	bodyTypeNone = iota
	bodyTypeUrlencoded
	bodyTypeMultipart
)

type bodyParser struct {
	contentType string
	parser      func(t *modsecurity.Transaction, params map[string]string) (interface{}, error)
}

var parsers = map[int]*bodyParser{
	bodyTypeUrlencoded: &bodyParser{
		contentType: "application/x-www-form-urlencoded",
		parser: func(t *modsecurity.Transaction, params map[string]string) (interface{}, error) {
			body, err := t.Request.Body.String()
			if err != nil {
				t.AbortWithError(http.StatusRequestEntityTooLarge, err)
			}
			return url.ParseQuery(body)
		},
	},
	bodyTypeMultipart: &bodyParser{
		contentType: "multipart/",
		parser: func(t *modsecurity.Transaction, params map[string]string) (interface{}, error) {
			mr := multipart.NewReader(t.Request.Body, params["boundary"])
			form, err := mr.ReadForm(t.Engine.RequestBodyInMem)
			if err == multipart.ErrMessageTooLarge {
				t.AbortWithError(http.StatusRequestEntityTooLarge, err)
			}
			return form, err
		},
	},
}

func requestBodyParse(t *modsecurity.Transaction, types ...int) (int, interface{}) {
	var err error
	if !(t.Request.Method == "POST" || t.Request.Method == "PUT" || t.Request.Method == "PATCH") {
		return bodyTypeNone, nil
	}
	if !t.Engine.RequestBodyAccess || t.Request.Body.Len() == 0 {
		return bodyTypeNone, nil
	}
	ct := t.Request.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	ct, params, _ := mime.ParseMediaType(ct)
	for _, tp := range types {
		parser, has := parsers[tp]
		if !has {
			continue
		}
		if !strings.HasPrefix(ct, parser.contentType) {
			continue
		}
		cacheKey := fmt.Sprintf("RESPONSE_BODY:%s", parser.contentType)
		res, has := t.VariableCache[cacheKey]
		if !has {
			res, err = parser.parser(t, params)
			t.VariableCache[cacheKey] = res
			if err != nil {
				t.RequestBodyError = err
			}
		}
		if res != nil {
			return tp, res
		}
	}

	return bodyTypeNone, nil
}
