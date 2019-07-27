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
	rule  *modsecurity.SecRule
	chain bool
}

func (*DireRule) Token() int {
	return parser.TkDirRule
}

func newDireRule() *DireRule {
	return &DireRule{
		rule: modsecurity.NewSecRule(),
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
	dr := newDireRule()
	err := dr.applyVariables(dd.Variable)
	if err != nil {
		return nil, err
	}

	err = dr.applyTrans(dd.Actions.Trans)
	if err != nil {
		return nil, err
	}

	err = dr.applyOperator(dd.Operator)
	if err != nil {
		return nil, err
	}

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
