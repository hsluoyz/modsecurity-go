package seclang

import (
	"testing"

	"github.com/hsluoyz/modsecurity-go/modsecurity"
	"github.com/hsluoyz/modsecurity-go/modsecurity/actions"
	"github.com/hsluoyz/modsecurity-go/modsecurity/operators"
	"github.com/hsluoyz/modsecurity-go/modsecurity/transforms"
	"github.com/hsluoyz/modsecurity-go/modsecurity/variables"
)

func TestSecRule(t *testing.T) {
	t.Run("deny", func(t *testing.T) {
		eng := modsecurity.NewEngine()
		input := `SecRule REQUEST_URI '@rx abc' \
                            "id:123,\
                             phase:2,\
                             t:lowercase,\
                             deny" `
		rs, err := NewDireSetFromSecLangString(input)
		if err != nil {
			t.Error(err)
			return
		}
		err = rs.Execute(eng)
		if err != nil {
			t.Error(err)
			return
		}
		if len(eng.RuleSet.Phases[2]) != 1 {
			t.Error("expect 1 rule in phases 2")
			return
		}
		rule := eng.RuleSet.Phases[2][0]
		if rule.Id != 123 {
			t.Errorf("expect rule id 123, got %d", rule.Id)
			return
		}
		if rule.Phase != 2 {
			t.Errorf("expect rule phase 2, got %d", rule.Phase)
			return
		}
		if len(rule.Variables) != 1 {
			t.Error("expect one variables")
			return
		}
		if _, ok := rule.Variables[0].(*variables.VariableRequestURI); !ok {
			t.Errorf("expect VariableRequestURI, got %#v", rule.Variables[0])
			return
		}

		if len(rule.Trans) != 1 {
			t.Error("expect one trans")
			return
		}
		if _, ok := rule.Trans[0].(*transforms.TransLowerCase); !ok {
			t.Errorf("expect TranLowerCase, got %#v", rule.Trans[0])
			return
		}

		op, ok := rule.Operator.(*operators.OperatorRx)
		if !ok {
			t.Errorf("expect OperatorRx, got %#v", rule.Operator)
			return
		}
		if op.Args() != "abc" {
			t.Errorf("expect op variable abc, got %#v", op.Args())
			return
		}

		if len(rule.Actions) != 1 {
			t.Error("expect one actions")
			return
		}
		if _, ok := rule.Actions[0].(*actions.ActionDeny); !ok {
			t.Errorf("expect ActionDeny, got %#v", rule.Actions[0])
			return
		}
	})
}
