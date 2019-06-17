package libmodsecruity

import (
	"fmt"

	"github.com/senghoo/modsecurity-go/libmodsecurity/seclang"
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
	return seclang.TkDirReqBody
}

func (r *RuleRequestBodyAccess) FromSecLang(d seclang.Directive) (Rule, error) {
	if d.Token() != r.Token() {
		return nil, fmt.Errorf("RuleRequestBodyAccess expect directive with token %d, but %d", r.Token(), d.Token())
	}
	dd, ok := d.(*seclang.BoolArgDirective)
	if !ok {
		fmt.Errorf("RuleRequestBodyAccess can't accpet directive %#v", d)
	}
	return NewRequestBodyAccess(dd.Value), nil
}

func (r *RuleRequestBodyAccess) Execute(e *Engine) error {
	e.RequestBodyAccess(r.enable)
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
	return seclang.TkDirResBody
}

func (r *RuleResponseBodyAccess) FromSecLang(d seclang.Directive) (Rule, error) {
	if d.Token() != r.Token() {
		return nil, fmt.Errorf("RuleResponseBodyAccess expect directive with token %d, but %d", r.Token(), d.Token())
	}
	dd, ok := d.(*seclang.BoolArgDirective)
	if !ok {
		fmt.Errorf("RuleResponseBodyAccess can't accpet directive %#v", d)
	}
	return NewResponseBodyAccess(dd.Value), nil
}

func (r *RuleResponseBodyAccess) Execute(e *Engine) error {
	e.ResponseBodyAccess(r.enable)
	return nil
}
