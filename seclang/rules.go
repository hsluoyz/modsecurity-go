package seclang

import (
	"fmt"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

func init() {
	RegisterSecLangRule(new(RuleRequestBodyAccess))
	RegisterSecLangRule(new(RuleResponseBodyAccess))
	RegisterSecLangRule(new(RuleSecRuleEngine))
}

// RuleRequestBodyAccess
type RuleRequestBodyAccess struct {
	enable bool
}

func (*RuleRequestBodyAccess) Token() int {
	return parser.TkDirReqBody
}

func (r *RuleRequestBodyAccess) FromSecLang(d parser.Directive) (Rule, error) {
	if d.Token() != r.Token() {
		return nil, fmt.Errorf("RuleRequestBodyAccess expect directive with token %d, but %d", r.Token(), d.Token())
	}
	dd, ok := d.(*parser.BoolArgDirective)
	if !ok {
		return nil, fmt.Errorf("RuleRequestBodyAccess can't accpet directive %#v", d)
	}
	return &RuleRequestBodyAccess{dd.Value}, nil
}

func (r *RuleRequestBodyAccess) Execute(e *modsecurity.Engine) error {
	e.RequestBodyAccess = r.enable
	return nil
}

// RuleResponseBodyAccess
type RuleResponseBodyAccess struct {
	enable bool
}

func (*RuleResponseBodyAccess) Token() int {
	return parser.TkDirResBody
}

func (r *RuleResponseBodyAccess) FromSecLang(d parser.Directive) (Rule, error) {
	if d.Token() != r.Token() {
		return nil, fmt.Errorf("RuleResponseBodyAccess expect directive with token %d, but %d", r.Token(), d.Token())
	}
	dd, ok := d.(*parser.BoolArgDirective)
	if !ok {
		return nil, fmt.Errorf("RuleResponseBodyAccess can't accpet directive %#v", d)
	}
	return &RuleResponseBodyAccess{dd.Value}, nil
}

func (r *RuleResponseBodyAccess) Execute(e *modsecurity.Engine) error {
	e.ResponseBodyAccess = r.enable
	return nil
}

// RuleSecRuleEngine
type RuleSecRuleEngine struct {
	value int
}

func (*RuleSecRuleEngine) Token() int {
	return parser.TkDirRuleEng
}

func (r *RuleSecRuleEngine) FromSecLang(d parser.Directive) (Rule, error) {
	if d.Token() != r.Token() {
		return nil, fmt.Errorf("RuleResponseBodyAccess expect directive with token %d, but %d", r.Token(), d.Token())
	}
	dd, ok := d.(*parser.TriBoolArgDirective)
	if !ok {
		return nil, fmt.Errorf("RuleResponseBodyAccess can't accpet directive %#v", d)
	}
	return &RuleSecRuleEngine{dd.Value}, nil
}

func (r *RuleSecRuleEngine) Execute(e *modsecurity.Engine) error {
	switch r.value {
	case parser.TriBoolTrue:
		e.Enable(modsecurity.StatusOn)
	case parser.TriBoolFalse:
		e.Enable(modsecurity.StatusOff)
	case parser.TriBoolElse:
		e.Enable(modsecurity.StatusDect)
	}
	return nil
}
