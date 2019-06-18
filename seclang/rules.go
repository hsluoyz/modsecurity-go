package seclang

import (
	"fmt"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

func init() {
	RegisterSecLangRule(new(RuleRequestBodyAccess))
	RegisterSecLangRule(new(RuleResponseBodyAccess))
}

// RuleRequestBodyAccess
type RuleRequestBodyAccess struct {
	enable bool
}

func NewRequestBodyAccess(enable bool) Rule {
	return &RuleRequestBodyAccess{
		enable: enable,
	}
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
		fmt.Errorf("RuleRequestBodyAccess can't accpet directive %#v", d)
	}
	return NewRequestBodyAccess(dd.Value), nil
}

func (r *RuleRequestBodyAccess) Execute(e *modsecurity.Engine) error {
	e.RequestBodyAccess = r.enable
	return nil
}

// RuleResponseBodyAccess
type RuleResponseBodyAccess struct {
	enable bool
}

func NewResponseBodyAccess(enable bool) Rule {
	return &RuleResponseBodyAccess{
		enable: enable,
	}
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
		fmt.Errorf("RuleResponseBodyAccess can't accpet directive %#v", d)
	}
	return NewResponseBodyAccess(dd.Value), nil
}

func (r *RuleResponseBodyAccess) Execute(e *modsecurity.Engine) error {
	e.ResponseBodyAccess = r.enable
	return nil
}
