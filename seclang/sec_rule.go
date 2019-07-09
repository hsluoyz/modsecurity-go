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

func newDireRule() *DireRule {
	return &DireRule{
		modsecurity.NewSecRule(),
	}
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
	dr := newDireRule()
	dr.rule.Not = dd.Operator.Not
	dr.rule.Operator = operator
	dr.rule.Trans = trans
	dr.rule.Variables = variables
	err = dr.applyActions(dd.Actions)
	if err != nil {
		return nil, err
	}
	return dr, nil
}

func (r *DireRule) Execute(e *modsecurity.Engine) error {
	e.AddSecRule(r.rule)
	return nil
}
