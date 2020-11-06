package seclang

import (
	"fmt"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/seclang/parser"
)

func init() {
	RegisterDire(new(DireRequestBodyAccess))
	RegisterDire(new(DireResponseBodyAccess))
	RegisterDire(new(DireRuleEngine))
}

// DireRequestBodyAccess
type DireRequestBodyAccess struct {
	enable bool
}

func (*DireRequestBodyAccess) Token() int {
	return parser.TkDirReqBody
}

func (r *DireRequestBodyAccess) FromSecLang(d parser.Directive) (Dire, error) {
	if d.Token() != r.Token() {
		return nil, fmt.Errorf("DireRequestBodyAccess expect directive with token %d, but %d", r.Token(), d.Token())
	}
	dd, ok := d.(*parser.BoolArgDirective)
	if !ok {
		return nil, fmt.Errorf("DireRequestBodyAccess can't accpet directive %#v", d)
	}
	return &DireRequestBodyAccess{dd.Value}, nil
}

func (r *DireRequestBodyAccess) Execute(e *modsecurity.Engine) error {
	e.RequestBodyAccess = r.enable
	return nil
}

// DireResponseBodyAccess
type DireResponseBodyAccess struct {
	enable bool
}

func (*DireResponseBodyAccess) Token() int {
	return parser.TkDirResBody
}

func (r *DireResponseBodyAccess) FromSecLang(d parser.Directive) (Dire, error) {
	if d.Token() != r.Token() {
		return nil, fmt.Errorf("DireResponseBodyAccess expect directive with token %d, but %d", r.Token(), d.Token())
	}
	dd, ok := d.(*parser.BoolArgDirective)
	if !ok {
		return nil, fmt.Errorf("DireResponseBodyAccess can't accpet directive %#v", d)
	}
	return &DireResponseBodyAccess{dd.Value}, nil
}

func (r *DireResponseBodyAccess) Execute(e *modsecurity.Engine) error {
	e.ResponseBodyAccess = r.enable
	return nil
}

// DireRuleEngine
type DireRuleEngine struct {
	value int
}

func (*DireRuleEngine) Token() int {
	return parser.TkDirRuleEng
}

func (r *DireRuleEngine) FromSecLang(d parser.Directive) (Dire, error) {
	if d.Token() != r.Token() {
		return nil, fmt.Errorf("DireResponseBodyAccess expect directive with token %d, but %d", r.Token(), d.Token())
	}
	dd, ok := d.(*parser.TriBoolArgDirective)
	if !ok {
		return nil, fmt.Errorf("DireResponseBodyAccess can't accpet directive %#v", d)
	}
	return &DireRuleEngine{dd.Value}, nil
}

func (r *DireRuleEngine) Execute(e *modsecurity.Engine) error {
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
