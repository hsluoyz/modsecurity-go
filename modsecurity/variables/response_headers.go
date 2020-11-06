package variables

import (
	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func NewVariableResponseHeaders() modsecurity.Variable {
	return &VariableResponseHeaders{
		filter: &filter{},
	}
}

type VariableResponseHeaders struct {
	*filter
}

func (*VariableResponseHeaders) Name() string {
	return "RESPONSE_HEADERS"
}
func (v *VariableResponseHeaders) Fetch(t *modsecurity.Transaction) []string {
	return v.filter.Fetch(t.Response.Header)
}
