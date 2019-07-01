package variables

import "github.com/senghoo/modsecurity-go/modsecurity"

func NewVariableResponseHeadersNames() modsecurity.Variable {
	return &VariableResponseHeadersNames{
		filter: &filter{},
	}
}

type VariableResponseHeadersNames struct {
	*filter
}

func (*VariableResponseHeadersNames) Name() string {
	return "RESPONSE_HEADERS_NAMES"
}
func (v *VariableResponseHeadersNames) Fetch(t *modsecurity.Transaction) []string {
	return v.filter.Names(t.Response.Header)
}
