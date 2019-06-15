package seclang

import (
	"reflect"
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
		dir, err := scan.ReadDirective()
		if err != nil {
			t.Error(err)
			return nil
		}
		return dir
	}
	t.Run("Directive SecRuleEngine", func(t *testing.T) {
		expectToken := TkDirRuleEng
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
				if d.Token() != expectToken {
					t.Errorf("rule: %s expect token %d, but got %#v", rule, expectToken, dir)
				}
				if d.Value != expectValue {
					t.Errorf("rule: %s expect value %#v, but got %#v", rule, expectValue, dir)
				}
			} else {
				t.Errorf("rule: %s expect BoolArgDirective, but got %#v", rule, dir)
				return
			}
		}
	})
}

func TestSecLangVariables(t *testing.T) {
	one := func(rule string) []*Variable {
		scan := NewSecLangScanner(strings.NewReader(rule))
		dir, err := scan.ReadVariables()
		if err != nil {
			t.Error(err)
			return nil
		}
		return dir
	}
	t.Run("Variables", func(t *testing.T) {
		rules := map[string][]*Variable{
			`ARGS`: []*Variable{
				&Variable{TkVarArgs, "", false, false},
			},
			`ARGS|ARGS_NAMES`: []*Variable{
				&Variable{TkVarArgs, "", false, false},
				&Variable{TkVarArgsNames, "", false, false},
			},
			`!ARGS|&ARGS_NAMES`: []*Variable{
				&Variable{TkVarArgs, "", false, true},
				&Variable{TkVarArgsNames, "", true, false},
			},
			`ARGS|ARGS_NAMES|REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_HEADERS`: []*Variable{
				&Variable{TkVarArgs, "", false, false},
				&Variable{TkVarArgsNames, "", false, false},
				&Variable{TkVarRequestCookies, "", false, false},
				&Variable{TkVarRequestCookies, "/__utm/", false, true},
				&Variable{TkVarRequestCookiesNames, "", false, false},
				&Variable{TkVarRequestBody, "", false, false},
				&Variable{TkVarRequestHeaders, "", false, false},
			},
		}
		for rule, expectValue := range rules {
			vars := one(rule)
			for idx, v := range vars {
				if !reflect.DeepEqual(vars, expectValue) {
					// fmt.Printf("variable: %s expect %#v,  got %#v", rule, expectValue[idx], v)
					t.Errorf("variable: %s expect %#v, but got %#v", rule, expectValue[idx], v)
				}

			}
		}
	})
}

func TestSecLangOperators(t *testing.T) {
	one := func(rule string) *Operator {
		scan := NewSecLangScanner(strings.NewReader(rule))
		op, err := scan.ReadOperator()
		if err != nil {
			t.Error(err)
			return nil
		}
		return op
	}
	t.Run("Operations", func(t *testing.T) {
		rules := map[string]*Operator{
			`"some regex"`:  &Operator{TkOpRx, false, "some regex"},
			`withoutQuote`:  &Operator{TkOpRx, false, "withoutQuote"},
			`"@rx nikto"`:   &Operator{TkOpRx, false, "nikto"},
			`"!some regex"`: &Operator{TkOpRx, true, "some regex"},
			`!withoutQuote`: &Operator{TkOpRx, true, "withoutQuote"},
			`"!@rx nikto"`:  &Operator{TkOpRx, true, "nikto"},
			`"@eq 15"`:      &Operator{TkOpEq, false, "15"},
			`"@ge 16"`:      &Operator{TkOpGe, false, "16"},
			`"@gt 17"`:      &Operator{TkOpGt, false, "17"},
			`"@le 18"`:      &Operator{TkOpLe, false, "18"},
			`"@lt 19"`:      &Operator{TkOpLt, false, "19"},
		}
		for rule, expectValue := range rules {
			op := one(rule)
			if op == nil {
				return
			}
			if !reflect.DeepEqual(op, expectValue) {
				t.Errorf("operator: %s expect %#v, but got %#v", rule, expectValue, op)
			}
		}
	})
}

func TestSecLangActions(t *testing.T) {
	one := func(rule string) *Actions {
		scan := NewSecLangScanner(strings.NewReader(rule))
		o, err := scan.ReadActions()
		if err != nil {
			t.Error(err)
			return nil
		}
		return o
	}
	t.Run("Actions", func(t *testing.T) {
		rules := map[string]*Actions{
			`"phase:1,id:5"`:     &Actions{Phase: 1, Id: 5},
			`"phase:1,\n\tid:5"`: &Actions{Phase: 1, Id: 5},
		}
		for rule, expect := range rules {
			res := one(rule)
			if res == nil {
				return
			}
			if !reflect.DeepEqual(res, expect) {
				t.Errorf("actions: %s expect %#v, but got %#v", rule, expect, res)
			}
		}
	})
}
