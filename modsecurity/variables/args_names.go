package variables

import (
	"github.com/senghoo/modsecurity-go/modsecurity"
)

func NewVariableArgsNames() modsecurity.Variable {
	return &VariableArgsNames{
		merger: &merger{
			[]modsecurity.Variable{
				NewVariableArgsGetNames(),
				NewVariableArgsPostNames(),
			},
		},
	}
}

type VariableArgsNames struct {
	*merger
}

func (*VariableArgsNames) Name() string {
	return "ARGS_NAMES"
}
func (v *VariableArgsNames) Fetch(t *modsecurity.Transaction) []string {
	return v.merger.Fetch(t)
}
