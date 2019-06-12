package seclang

import (
	"strings"
	"testing"
)

type expect struct {
	tk  int
	str []string
}

func TestSecLangDirectives(t *testing.T) {
	one := func(rule string) Directive {
		scan := NewSecLangScanner(strings.NewReader(rule))
		dir, err := scan.ScanDirective()
		if err != nil {
			t.Error(err)
			return nil
		}
		return dir
	}
	t.Run("Directive SecRuleEngine", func(t *testing.T) {
		expectKind := TkDirRuleEng
		rules := map[string]int{
			`SecRuleEngine On`:            TriBoolTrue,
			`SecRuleEngine on`:            TriBoolTrue,
			`SecRuleEngine Off`:           TriBoolFalse,
			`secruleengine OFF`:           TriBoolFalse,
			`SecRuleEngine DetectionOnly`: TriBoolDetc,
			`SECRULEENGINE detectiononly`: TriBoolDetc,
		}
		for rule, expectValue := range rules {
			dir := one(rule)
			if d, ok := dir.(*TriBoolArgDirective); ok {
				if d.Type() != expectKind {
					t.Errorf("rule: %s expect kind %d, bug got %#v", rule, expectKind, dir)
				}
				if d.Value != expectValue {
					t.Errorf("rule: %s expect value %#v, bug got %#v", rule, expectValue, dir)
				}
			} else {
				t.Errorf("rule: %s expect BoolArgDirective, bug got %#v", rule, dir)
				return
			}
		}
	})
}
