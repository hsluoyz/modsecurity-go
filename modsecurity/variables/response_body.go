package variables

import (
	"net/http"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func NewVariableResponseBody() modsecurity.Variable {
	return &VariableResponseBody{}
}

type VariableResponseBody struct {
}

func (*VariableResponseBody) Include(string) error { return nil }
func (*VariableResponseBody) Exclude(string) error { return nil }

func (*VariableResponseBody) Name() string {
	return "RESPONSE_BODY"
}
func (v *VariableResponseBody) Fetch(t *modsecurity.Transaction) []string {
	if !t.Engine.ResponseBodyAccess || t.Response.Body.Len() == 0 {
		return nil
	}
	body, err := t.Response.Body.String()
	if err != nil {
		t.AbortWithError(http.StatusInternalServerError, err)
		return nil
	}
	return []string{body}
}
