package variables

import (
	"mime"
	"net/http"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func NewVariableRequestBody() modsecurity.Variable {
	return &VariableRequestBody{}
}

type VariableRequestBody struct {
}

func (*VariableRequestBody) Include(string) error { return nil }
func (*VariableRequestBody) Exclude(string) error { return nil }

func (*VariableRequestBody) Name() string {
	return "REQUEST_BODY"
}
func (v *VariableRequestBody) Fetch(t *modsecurity.Transaction) []string {
	if !(t.Request.Method == "POST" || t.Request.Method == "PUT" || t.Request.Method == "PATCH") {
		return nil
	}
	if !t.Engine.RequestBodyAccess || t.Request.Body.Len() == 0 {
		return nil
	}
	ct := t.Request.Header.Get("Content-Type")
	if ct == "" {
		return nil
	}
	ct, _, _ = mime.ParseMediaType(ct)
	if ct != "application/x-www-form-urlencoded" {
		return nil
	}
	body, err := t.Request.Body.String()
	if err != nil {
		t.AbortWithError(http.StatusRequestEntityTooLarge, err)
		return nil
	}
	return []string{body}
}
