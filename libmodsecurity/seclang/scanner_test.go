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
					t.Errorf("rule: %s expect kind %d, but got %#v", rule, expectKind, dir)
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
		rules := map[string][]Variable{
			`ARGS`: []Variable{
				Variable{TkVarArgs, "", false, false},
			},
			`ARGS|ARGS_NAMES`: []Variable{
				Variable{TkVarArgs, "", false, false},
				Variable{TkVarArgsNames, "", false, false},
			},
			`!ARGS|&ARGS_NAMES`: []Variable{
				Variable{TkVarArgs, "", false, true},
				Variable{TkVarArgsNames, "", true, false},
			},
			`ARGS|ARGS_NAMES|REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_HEADERS`: []Variable{
				Variable{TkVarArgs, "", false, false},
				Variable{TkVarArgsNames, "", false, false},
				Variable{TkVarRequestCookies, "", false, false},
				Variable{TkVarRequestCookies, "/__utm/", false, true},
				Variable{TkVarRequestCookiesNames, "", false, false},
				Variable{TkVarRequestBody, "", false, false},
				Variable{TkVarRequestHeaders, "", false, false},
			},
		}
		for rule, expectValue := range rules {
			vars := one(rule)
			for idx, v := range vars {
				if expectValue[idx].Kind != v.Kind ||
					expectValue[idx].Index != v.Index ||
					expectValue[idx].Count != v.Count ||
					expectValue[idx].Exclusion != v.Exclusion {
					// fmt.Printf("variable: %s expect %#v,  got %#v", rule, expectValue[idx], v)
					t.Errorf("variable: %s expect %#v, but got %#v", rule, expectValue[idx], v)
				}

			}
		}
	})
}
