package seclang

import (
	"fmt"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

func init() {
	RegisterSecLangRule(new(RuleSecRule))
}

// RuleRequestBodyAccess
type RuleSecRule struct {
	rule *modsecurity.SecRule
}

func (*RuleSecRule) Token() int {
	return parser.TkDirRule
}

func (r *RuleSecRule) FromSecLang(d parser.Directive) (Rule, error) {
	if d.Token() != r.Token() {
		return nil, fmt.Errorf("RuleSecRule expect directive with token %d, but %d", r.Token(), d.Token())
	}
	dd, ok := d.(*parser.RuleDirective)
	if !ok {
		return nil, fmt.Errorf("RuleSecRule can't accpet directive %#v", d)
	}
	variables, err := MakeVariables(dd.Variable)
	if err != nil {
		return nil, err
	}
	trans, err := makeTrans(dd.Actions.Trans)
	if err != nil {
		return nil, err
	}
	operator, err := MakeOperator(dd.Operator)
	if err != nil {
		return nil, err
	}
	actions, err := makeActions(dd.Actions.Action)
	if err != nil {
		return nil, err
	}
	return &RuleSecRule{
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

func (r *RuleSecRule) Execute(e *modsecurity.Engine) error {
	e.AddSecRule(r.rule)
	return nil
}

func makeTrans([]*parser.Trans) ([]modsecurity.Trans, error) {
	return nil, nil
}

func makeActions([]*parser.Action) ([]modsecurity.Action, error) {
	return nil, nil
}
