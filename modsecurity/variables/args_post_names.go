package variables

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewVariableArgsPostNames() modsecurity.Variable {
	return &VariableArgsPostNames{
		filter: &filter{},
	}
}

type VariableArgsPostNames struct {
	*filter
}

func (*VariableArgsPostNames) Name() string {
	return "ARGS_POST_NAMES"
}
func (v *VariableArgsPostNames) Fetch(t *modsecurity.Transaction) []string {
	return v.filter.Names(argsPost(t))
}
