package variables

import "github.com/senghoo/modsecurity-go/modsecurity"

func NewVariableArgsGetNames() modsecurity.Variable {
	return &VariableArgsGetNames{
		filter: &filter{},
	}
}

type VariableArgsGetNames struct {
	*filter
}

func (*VariableArgsGetNames) Name() string {
	return "ARGS_GET_NAMES"
}
func (v *VariableArgsGetNames) Fetch(t *modsecurity.Transaction) []string {
	if t == nil || t.URL == nil {
		return nil
	}
	return v.filter.Names(t.URL.Query())
}
