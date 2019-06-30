package variables

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewVariableQueryString() modsecurity.Variable {
	return &VariableQueryString{}
}

type VariableQueryString struct {
}

func (*VariableQueryString) Name() string {
	return "QUERY_STRING"
}
func (*VariableQueryString) Include(string) error { return nil }
func (*VariableQueryString) Exclude(string) error { return nil }
func (*VariableQueryString) Fetch(t *modsecurity.Transaction) []string {
	if t.URL == nil {
		return nil
	}
	return []string{t.URL.RawQuery}
}
