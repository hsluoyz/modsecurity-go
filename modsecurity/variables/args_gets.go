package variables

import "github.com/hsluoyz/modsecurity-go/modsecurity"

func NewVariableArgsGet() modsecurity.Variable {
	return &VariableArgsGet{
		filter: &filter{},
	}
}

type VariableArgsGet struct {
	*filter
}

func (*VariableArgsGet) Name() string {
	return "ARGS_GET"
}
func (v *VariableArgsGet) Fetch(t *modsecurity.Transaction) []string {
	if t == nil || t.URL == nil {
		return nil
	}
	return v.filter.Fetch(t.URL.Query())
}
