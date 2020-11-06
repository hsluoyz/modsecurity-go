package variables

import (
	"github.com/hsluoyz/modsecurity-go/modsecurity"
)

func NewVariableArgs() modsecurity.Variable {
	return &VariableArgs{
		merger: &merger{
			[]modsecurity.Variable{
				NewVariableArgsGet(),
				NewVariableArgsPost(),
			},
		},
	}
}

type VariableArgs struct {
	*merger
}

func (*VariableArgs) Name() string {
	return "ARGS"
}
func (v *VariableArgs) Fetch(t *modsecurity.Transaction) []string {
	return v.merger.Fetch(t)
}
