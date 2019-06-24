package seclang

import (
	"fmt"

	"github.com/senghoo/modsecurity-go/modsecurity"
	"github.com/senghoo/modsecurity-go/seclang/parser"
)

var ruleTypes = make(map[int]RuleFromSecLang)

func RegisterSecLangDire(rule RuleFromSecLang) {
	tk := rule.Token()
	exist, has := ruleTypes[tk]
	if has {
		panic(fmt.Errorf("rule with token %d already registered with %#v, cannot register %#v", tk, exist, rule))
	}
	ruleTypes[tk] = rule
}

func direFactory(d parser.Directive) (Dire, error) {
	t, has := ruleTypes[d.Token()]
	if !has {
		return nil, fmt.Errorf("token %d not implemented", d.Token())
	}
	return t.FromSecLang(d)
}

func NewDireSet() *DireSet {
	return &DireSet{}
}
func NewDireSetFromSecLangString(rules string) (*DireSet, error) {
	rs := NewDireSet()
	err := rs.AddSecLangString(rules)
	if err != nil {
		return nil, err
	}
	return rs, nil
}

type DireSet struct {
	dires []Dire
}

func (rs *DireSet) AddSecLangString(str string) error {
	scanner := parser.NewSecLangScannerFromString(str)
	dirs, err := scanner.AllDirective()
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		dire, err := direFactory(dir)
		if err != nil {
			return err
		}
		rs.dires = append(rs.dires, dire)
	}
	return nil
}

func (rs *DireSet) Execute(e *modsecurity.Engine) error {
	for _, dire := range rs.dires {
		if err := dire.Execute(e); err != nil {
			return err
		}
	}
	return nil
}

type Dire interface {
	Execute(*modsecurity.Engine) error
}

type RuleFromSecLang interface {
	Token() int
	FromSecLang(parser.Directive) (Dire, error)
}
