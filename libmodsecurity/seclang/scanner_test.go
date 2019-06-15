package seclang

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
)

type expect struct {
	tk  int
	str []string
}

func TestSecLangSimpleDirectives(t *testing.T) {
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

func TestSecLangSecRule(t *testing.T) {
	one := func(rule string) *RuleDirective {
		scan := NewSecLangScanner(strings.NewReader(rule))
		o, err := scan.ReadDirective()
		if err != nil {
			t.Error(err)
			return nil
		}
		r, ok := o.(*RuleDirective)
		if !ok {
			t.Error(fmt.Errorf("expect RuleDirective get %#v", o))
			return nil
		}
		return r
	}
	t.Run("Actions", func(t *testing.T) {
		rules := map[string]*RuleDirective{
			`SecRule ARGS "abc" "id:123,phase:1,deny"`: &RuleDirective{
				Variable: []*Variable{
					&Variable{
						Tk: TkVarArgs,
					},
				},
				Operator: &Operator{
					Tk:       TkOpRx,
					Argument: "abc",
				},
				Actions: &Actions{
					Id:    123,
					Phase: 1,
					Action: []*Action{
						&Action{
							Tk: TkActionDeny,
						},
					},
				},
			},
			` 
SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|REQUEST_BODY|REQUEST_HEADERS|XML:/*|XML://@* \
    "@rx java\.lang\.(?:runtime|processbuilder)" \
    "id:944100,\
    phase:2,\
    block,\
    log,\
    msg:'Remote Command Execution: Suspicious Java class detected',\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',\
    t:none,t:lowercase,\
    tag:'application-multi',\
    tag:'language-java',\
    tag:'platform-multi',\
    tag:'attack-rce',\
    tag:'OWASP_CRS/WEB_ATTACK/COMMAND_INJECTION',\
    tag:'WASCTC/WASC-31',\
    tag:'OWASP_TOP_10/A1',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/1',\
    ver:'OWASP_CRS/3.1.0',\
    severity:'CRITICAL',\
    setvar:'tx.rce_score=+%{tx.critical_anomaly_score}',\
    setvar:'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
`: &RuleDirective{
				Variable: []*Variable{
					&Variable{Tk: TkVarArgs},
					&Variable{Tk: TkVarArgsNames},
					&Variable{Tk: TkVarRequestCookies},
					&Variable{Tk: TkVarRequestCookies, Index: "/__utm/", Exclusion: true},
					&Variable{Tk: TkVarRequestCookiesNames},
					&Variable{Tk: TkVarRequestBody},
					&Variable{Tk: TkVarRequestHeaders},
					&Variable{Tk: TkVarXML, Index: "/*"},
					&Variable{Tk: TkVarXML, Index: "//@*"},
				},
				Operator: &Operator{
					Tk:       TkOpRx,
					Argument: "java.lang.(?:runtime|processbuilder)",
				},
				Actions: &Actions{
					Id:    944100,
					Phase: 2,
					Msg: []string{
						"Remote Command Execution: Suspicious Java class detected",
					},
					Tags: []string{
						"application-multi",
						"language-java",
						"platform-multi",
						"attack-rce",
						"OWASP_CRS/WEB_ATTACK/COMMAND_INJECTION",
						"WASCTC/WASC-31",
						"OWASP_TOP_10/A1",
						"PCI/6.5.2",
						"paranoia-level/1",
					},
					Severity: 2,
					Trans: []*Trans{
						&Trans{Tk: TkTransNone},
						&Trans{Tk: TkTransLowercase},
					},
					Action: []*Action{
						&Action{Tk: TkActionBlock, Argument: ""},
						&Action{Tk: TkActionLog, Argument: ""},
						&Action{Tk: TkActionLogData, Argument: "'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"},
						&Action{Tk: TkActionVer, Argument: "'OWASP_CRS/3.1.0'"},
						&Action{Tk: TkActionSetVar, Argument: "'tx.rce_score=+%{tx.critical_anomaly_score}'"},
						&Action{Tk: TkActionSetVar, Argument: "'tx.anomaly_score_pl1=+%{tx.critical_anomaly_score}'"},
					},
				},
			},
		}
		for rule, expect := range rules {
			res := one(rule)
			if res == nil {
				return
			}
			if !reflect.DeepEqual(res, expect) {
				t.Errorf("rule: %s expect %#+v, but got %#+v\n", rule, expect, res)
				spew.Dump(expect, res)
			}
		}
	})
}
