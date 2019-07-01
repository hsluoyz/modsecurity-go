package variables

import "github.com/senghoo/modsecurity-go/modsecurity"

func NewVariableRequestHeadersNames() modsecurity.Variable {
	return &VariableRequestHeadersNames{
		filter: &filter{},
	}
}

type VariableRequestHeadersNames struct {
	*filter
}

func (*VariableRequestHeadersNames) Name() string {
	return "REQUEST_HEADERS_NAMES"
}
func (v *VariableRequestHeadersNames) Fetch(t *modsecurity.Transaction) []string {
	if t == nil || t.URL == nil {
		return nil
	}
	return v.filter.Names(t.Request.Header)
}
