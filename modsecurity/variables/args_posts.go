package variables

import (
	"mime"
	"net/http"
	"net/url"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewVariableArgsPost() modsecurity.Variable {
	return &VariableArgsPost{
		filter: &filter{},
	}
}

func argsPost(t *modsecurity.Transaction) map[string][]string {
	if t.Request.Method == "POST" || t.Request.Method == "PUT" || t.Request.Method == "PATCH" {
		return nil
	}
	if !t.Engine.RequestBodyAccess || t.Request.Body.Len() == 0 {
		return nil
	}
	ct := t.Request.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	ct, params, _ := mime.ParseMediaType(ct)
	switch {
	case ct == "application/x-www-form-urlencoded":
		body, err := t.Request.Body.String()
		if err != nil {
			t.AbortWithError(http.StatusRequestEntityTooLarge, err)
		}
		val, _ := url.ParseQuery(body)
		return val
	case ct == "multipart/form-data":
		// TODO: Add multipart result
		boundary, ok := params["boundary"]
		_ = boundary
		_ = ok
	}
	return nil
}

type VariableArgsPost struct {
	*filter
}

func (*VariableArgsPost) Name() string {
	return "ARGS_POST"
}
func (v *VariableArgsPost) Fetch(t *modsecurity.Transaction) []string {
	return v.filter.Fetch(argsPost(t))
}
