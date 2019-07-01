package variables

import (
	"mime"

	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewVariableResponseContentType() modsecurity.Variable {
	return &VariableResponseContentType{}
}

type VariableResponseContentType struct {
}

func (*VariableResponseContentType) Name() string {
	return "RESPONSE_CONTENT_TYPE"
}
func (*VariableResponseContentType) Include(string) error { return nil }
func (*VariableResponseContentType) Exclude(string) error { return nil }
func (*VariableResponseContentType) Fetch(t *modsecurity.Transaction) []string {
	ct := t.Response.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	ct, _, _ = mime.ParseMediaType(ct)
	return []string{ct}
}
