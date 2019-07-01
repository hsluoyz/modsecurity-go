package variables

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewVariableResponseContentLength() modsecurity.Variable {
	return &VariableResponseContentLength{}
}

type VariableResponseContentLength struct {
}

func (*VariableResponseContentLength) Name() string {
	return "RESPONSE_CONTENT_LENGTH"
}
func (*VariableResponseContentLength) Include(string) error { return nil }
func (*VariableResponseContentLength) Exclude(string) error { return nil }
func (*VariableResponseContentLength) Fetch(t *modsecurity.Transaction) []string {
	if res := t.Response.Header.Get("Content-Length"); res != "" {
		return []string{res}
	}
	return []string{"0"}
}
