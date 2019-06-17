package libmodsecruity

import (
	"fmt"

	"github.com/senghoo/modsecurity-go/libmodsecurity/seclang"
)

var ruleTypes = make(map[int]RuleFromSecLang)

func RegisterSecLangRule(rule RuleFromSecLang) {
	tk := rule.Token()
	exist, has := ruleTypes[tk]
	if has {
		panic(fmt.Errorf("rule with token %d already registered with %#v, cannot register %#v", tk, exist, rule))
	}
	ruleTypes[tk] = rule
}

func ParseDirective(d seclang.Directive) (Rule, error) {
	t, has := ruleTypes[d.Token()]
	if !has {
		return nil, fmt.Errorf("token %d not implemented", d.Token())
	}
	return t.FromSecLang(d)
}

func NewRuleSet() *RuleSet {
	return &RuleSet{}
}
func NewRuleSetFromSecLangString(rules string) (*RuleSet, error) {
	rs := NewRuleSet()
	err := rs.AddSecLangString(rules)
	if err != nil {
		return nil, err
	}
	return rs, nil
}

type RuleSet struct {
	rules []Rule
}

func (rs *RuleSet) AddSecLangString(str string) error {
	scanner := seclang.NewSecLangScannerFromString(str)
	dirs, err := scanner.AllDirective()
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		rule, err := ParseDirective(dir)
		if err != nil {
			return err
		}
		rs.rules = append(rs.rules, rule)
	}
	return nil
}

func (rs *RuleSet) Execute(e *Engine) error {
	for _, rule := range rs.rules {
		if err := rule.Execute(e); err != nil {
			return err
		}
	}
	return nil
}

type Rule interface {
	Execute(*Engine) error
}

type RuleFromSecLang interface {
	Token() int
	FromSecLang(seclang.Directive) (Rule, error)
}
