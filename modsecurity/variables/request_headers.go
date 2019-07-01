package variables

import "github.com/senghoo/modsecurity-go/modsecurity"

func NewVariableRequestHeaders() modsecurity.Variable {
	return &VariableRequestHeaders{
		filter: &filter{},
	}
}

type VariableRequestHeaders struct {
	*filter
}

func (*VariableRequestHeaders) Name() string {
	return "REQUEST_HEADERS"
}
func (v *VariableRequestHeaders) Fetch(t *modsecurity.Transaction) []string {
	return v.filter.Fetch(t.Request.Header)
}
