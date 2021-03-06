package seclang

import (
	"fmt"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/seclang/parser"
)

var direTypes = make(map[int]DireFromSecLang)

func RegisterDire(dire DireFromSecLang) {
	tk := dire.Token()
	exist, has := direTypes[tk]
	if has {
		panic(fmt.Errorf("dire with token %d already registered with %#v, cannot register %#v", tk, exist, dire))
	}
	direTypes[tk] = dire
}

func direFactory(d parser.Directive) (Dire, error) {
	t, has := direTypes[d.Token()]
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
	var chainParent *DireRule
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
		if dr, ok := dire.(*DireRule); ok {
			parent := chainParent // keep old parent
			if !dr.chain {        // chain end or normal rule
				chainParent = nil
			} else if chainParent == nil { // new chain start
				chainParent = dr
			} // else keep old chain

			if parent != nil {
				parent.rule.AppendSubRules(dr.rule)
				continue // skip append dire
			}
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

type DireFromSecLang interface {
	Token() int
	FromSecLang(parser.Directive) (Dire, error)
}
