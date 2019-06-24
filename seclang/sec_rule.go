package seclang

import (
	"fmt"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

func init() {
	RegisterDire(new(DireRule))
}

// DireRequestBodyAccess
type DireRule struct {
	rule *modsecurity.SecRule
}

func (*DireRule) Token() int {
	return parser.TkDirRule
}

func (r *DireRule) FromSecLang(d parser.Directive) (Dire, error) {
	if d.Token() != r.Token() {
		return nil, fmt.Errorf("DireRule expect directive with token %d, but %d", r.Token(), d.Token())
	}
	dd, ok := d.(*parser.RuleDirective)
	if !ok {
		return nil, fmt.Errorf("DireRule can't accpet directive %#v", d)
	}
	variables, err := MakeVariables(dd.Variable)
	if err != nil {
		return nil, err
	}
	trans, err := MakeTrans(dd.Actions.Trans)
	if err != nil {
		return nil, err
	}
	operator, err := MakeOperator(dd.Operator)
	if err != nil {
		return nil, err
	}
	actions, err := MakeActions(dd.Actions.Action)
	if err != nil {
		return nil, err
	}
	return &DireRule{
		&modsecurity.SecRule{
			Id:        dd.Actions.Id,
			Phase:     dd.Actions.Phase,
			Not:       dd.Operator.Not,
			Variables: variables,
			Trans:     trans,
			Operator:  operator,
			Actions:   actions,
		},
	}, nil
}

func (r *DireRule) Execute(e *modsecurity.Engine) error {
	e.AddSecRule(r.rule)
	return nil
}
